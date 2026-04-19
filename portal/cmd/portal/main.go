package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/babs/poc-proxies/internal/logging"
	"github.com/babs/poc-proxies/internal/obs"
	"github.com/babs/poc-proxies/portal/internal/api"
	"github.com/babs/poc-proxies/portal/internal/config"
	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/ephemeral"
	portaloidc "github.com/babs/poc-proxies/portal/internal/oidc"
	"github.com/babs/poc-proxies/portal/internal/policy"
	"github.com/babs/poc-proxies/portal/internal/store"

	// Register persistent store drivers so the -store flag can resolve
	// `sqlite:///path`, `sqlite::memory:`, and `postgres://…` URLs.
	_ "github.com/babs/poc-proxies/portal/internal/store/postgres"
	_ "github.com/babs/poc-proxies/portal/internal/store/sqlite"
)

var (
	Version        = "v0.0.0"
	Commit         = "0000000"
	BuildTimestamp = "unknown"
	Builder        = "unknown"
)

func main() {
	cfg := config.RegisterFlags(flag.CommandLine)
	flag.Parse()

	logger := logging.New()
	defer logging.Sync()

	if err := cfg.Validate(); err != nil {
		logger.Error("invalid portal config", "err", err)
		logging.Sync()
		os.Exit(2)
	}

	otelCtx, otelCancel := context.WithTimeout(context.Background(), 10*time.Second)
	tracerShutdown, err := obs.InitTracerWith(otelCtx, "portal", Version, os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	otelCancel()
	if err != nil {
		logger.Error("otel init failed", "err", err)
		os.Exit(1)
	}
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = tracerShutdown(shutCtx)
		cancel()
	}()

	s, err := store.NewFromURL(cfg.StoreURL)
	if err != nil {
		logger.Error("store init failed", "url", cfg.StoreURL, "err", err)
		logging.Sync()
		os.Exit(2)
	}
	defer func() { _ = s.Close() }()
	engine := policy.New(s)

	// Ephemeral provisioner — off by default. When enabled, every backend
	// must have a BackendAccount with role=dba; boot fails fast otherwise.
	var ephemeralMgr *ephemeral.Manager
	if cfg.EphemeralAccounts {
		bootCtx, bootCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := ensureDBACreds(bootCtx, s); err != nil {
			bootCancel()
			logger.Error("ephemeral accounts enabled but DBA creds missing", "err", err)
			logging.Sync()
			os.Exit(2)
		}
		bootCancel()
		lookup := ephemeral.NewStoreDBALookup(s)
		ephemeralMgr = ephemeral.NewManager(map[ephemeral.BackendType]ephemeral.Provisioner{
			ephemeral.BackendPostgres: ephemeral.NewPostgresProvisioner(lookup, nil),
			ephemeral.BackendMySQL:    ephemeral.NewMySQLProvisioner(lookup, nil),
			ephemeral.BackendMongo:    ephemeral.NewMongoProvisioner(lookup, nil),
		}, ephemeral.NewMetrics(), logger)
		logger.Info("ephemeral_accounts_enabled")
	}

	auditMetrics := store.NewAuditMetrics()
	sweeperCtx, stopSweeper := context.WithCancel(context.Background())
	defer stopSweeper()
	sweeperDone := make(chan struct{})
	var orphanHook func(context.Context, store.Store)
	if ephemeralMgr != nil {
		orphanHook = ephemeral.OrphanSweepHook(ephemeralMgr, logger)
	}
	go func() {
		store.RunAuditSweeper(sweeperCtx, s, store.AuditSweeperConfig{
			RetentionDays:        cfg.AuditRetentionDays,
			MaxEntries:           cfg.AuditMaxEntries,
			Interval:             cfg.AuditSweepInterval,
			OrphanEphemeralSweep: orphanHook,
		}, auditMetrics, logger)
		close(sweeperDone)
	}()

	// Build OIDC provider if the issuer is configured. Discovery hits the
	// network, so we give it a bounded deadline — an unreachable IdP at boot
	// should surface fast rather than hanging on flag.Parse().
	var oidcProvider *portaloidc.Provider
	oidcCfg := &portaloidc.Config{
		IssuerURL:    cfg.OIDCIssuerURL,
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		RedirectURL:  cfg.OIDCRedirectURL,
		AdminClaim:   cfg.OIDCAdminClaim,
		AdminValue:   cfg.OIDCAdminValue,
		CookieSecure: cfg.OIDCCookieSecure,
	}
	if oidcCfg.Enabled() {
		discCtx, discCancel := context.WithTimeout(context.Background(), 10*time.Second)
		p, err := portaloidc.New(discCtx, oidcCfg, portaloidc.NewMemoryStore(), logger)
		discCancel()
		if err != nil {
			logger.Error("oidc init failed", "err", err)
			logging.Sync()
			os.Exit(2)
		}
		oidcProvider = p
		logger.Info("oidc enabled", "issuer", cfg.OIDCIssuerURL)
	}

	handler := api.NewRouterWithEphemeral(cfg, s, engine, oidcProvider, ephemeralMgr, logger)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       60 * time.Second,
	}

	var sidecar *obs.Server
	if cfg.MetricsAddr != "" {
		sidecar = obs.NewServer(cfg.MetricsAddr, logger,
			obs.BuildInfo{Version: Version, Commit: Commit, BuildTimestamp: BuildTimestamp, Builder: Builder},
			func() (uint64, uint64, uint64) { return 0, 0, 0 }) // portal has no conn counters today
		sidecar.SetAuditStats(auditMetrics.Snapshot)
		sidecar.SetGrantStats(auditMetrics.GrantsExpired)
		if ephemeralMgr != nil {
			sidecar.SetEphemeralStats(ephemeralMgr.Metrics().Snapshot)
		}
		if err := sidecar.Start(); err != nil {
			logger.Error("failed to start obs sidecar", "err", err)
			os.Exit(1)
		}
		sidecar.MarkReady()
	}

	logger.Info("portal starting",
		"listen", cfg.ListenAddr,
		"version", Version,
		"proxy_token_enabled", cfg.ProxyToken != "",
		"user_token_enabled", cfg.UserToken != "",
		"auto_approve", cfg.AutoApprove,
		"approval_webhook_enabled", cfg.ApprovalWebhookURL != "",
	)

	apiDone := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			apiDone <- err
			return
		}
		apiDone <- nil
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-apiDone:
		if err != nil {
			logger.Error("api exited", "err", err)
			os.Exit(1)
		}
	}

	apiCtx, apiCancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer apiCancel()
	if err := srv.Shutdown(apiCtx); err != nil {
		logger.Error("api shutdown error", "err", err)
	}
	stopSweeper()
	<-sweeperDone
	if sidecar != nil {
		// Dedicated deadline so the sidecar still gets time even if the API
		// drain consumed the full ShutdownGrace window.
		sideCtx, sideCancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = sidecar.Shutdown(sideCtx)
		sideCancel()
	}
	logger.Info("portal stopped")
}

// ensureDBACreds verifies every registered backend carries a BackendAccount
// with role=dba. Fail-closed: missing DBA creds + ephemeral flag on is a
// fatal boot error — the operator asked for isolation they can't get.
//
// Empty backend list is tolerated (fresh deployment) — the admin will seed
// backends + DBA accounts before requesting any grants, and provisioning
// failures at /approve time will surface clearly if any backend is missing.
func ensureDBACreds(ctx context.Context, s store.Store) error {
	backends, err := s.ListBackends(ctx)
	if err != nil {
		return err
	}
	for _, b := range backends {
		if _, err := s.GetBackendAccount(ctx, b.ID, domain.RoleDBA); err != nil {
			return fmt.Errorf("backend %q (%s) has no DBA account: %w", b.Name, b.ID, err)
		}
	}
	return nil
}
