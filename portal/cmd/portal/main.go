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
	"github.com/babs/poc-proxies/internal/metrics"
	"github.com/babs/poc-proxies/internal/obs"
	"github.com/babs/poc-proxies/portal/internal/api"
	"github.com/babs/poc-proxies/portal/internal/config"
	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/entra"
	"github.com/babs/poc-proxies/portal/internal/ephemeral"
	portaloidc "github.com/babs/poc-proxies/portal/internal/oidc"
	"github.com/babs/poc-proxies/portal/internal/policy"
	"github.com/babs/poc-proxies/portal/internal/lifecycle"
	"github.com/babs/poc-proxies/portal/internal/notify"
	"github.com/babs/poc-proxies/portal/internal/secrets"
	"github.com/babs/poc-proxies/portal/internal/store"

	// Register persistent store drivers so the -store flag can resolve
	// `sqlite:///path`, `sqlite::memory:`, and `postgres://…` URLs.
	_ "github.com/babs/poc-proxies/portal/internal/store/postgres"
	_ "github.com/babs/poc-proxies/portal/internal/store/sqlite"
)

var (
	Version        = "v0.0.0"
	CommitHash     = "0000000"
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

	raw, err := store.NewFromURL(cfg.Store.URL)
	if err != nil {
		logger.Error("store init failed", "url", cfg.Store.URL, "err", err)
		logging.Sync()
		os.Exit(2)
	}
	defer func() { _ = raw.Close() }()

	// At-rest secret cipher: wrap the store so every backend-account password,
	// portal password, and ephemeral password is SecretBox-encrypted before
	// persistence. A key is required unless the operator explicitly opts out
	// via -secretbox-key-env="" (local-dev escape hatch).
	var cipher secrets.Cipher = secrets.Noop{}
	switch {
	case cfg.Store.SecretboxKeyEnv == "":
		logger.Warn("at_rest_encryption_disabled",
			"reason", "-secretbox-key-env empty",
			"impact", "backend-account passwords and grant portal/ephemeral passwords stored in plaintext")
	default:
		key, kerr := secrets.LoadKeyFromEnv(cfg.Store.SecretboxKeyEnv)
		if kerr != nil {
			logger.Error("secretbox key load failed", "env", cfg.Store.SecretboxKeyEnv, "err", kerr)
			logging.Sync()
			os.Exit(2)
		}
		c, cerr := secrets.NewSecretboxCipher(key)
		if cerr != nil {
			logger.Error("secretbox init failed", "err", cerr)
			logging.Sync()
			os.Exit(2)
		}
		cipher = c
		logger.Info("at_rest_encryption_enabled", "env", cfg.Store.SecretboxKeyEnv)
	}
	s := store.Store(store.NewEncrypting(raw, cipher, logger))
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

	auditMetrics := lifecycle.NewAuditMetrics()
	sweeperCtx, stopSweeper := context.WithCancel(context.Background())
	defer stopSweeper()
	sweeperDone := make(chan struct{})
	var orphanHook func(context.Context, store.Store)
	if ephemeralMgr != nil {
		orphanHook = ephemeral.OrphanSweepHook(ephemeralMgr, logger)
	}
	go func() {
		lifecycle.Run(sweeperCtx, s, lifecycle.SweeperConfig{
			RetentionDays:        cfg.Audit.RetentionDays,
			MaxEntries:           cfg.Audit.MaxEntries,
			Interval:             cfg.Audit.SweepInterval,
			OrphanEphemeralSweep: orphanHook,
		}, auditMetrics, logger)
		close(sweeperDone)
	}()

	// Build OIDC provider if the issuer is configured. Discovery hits the
	// network, so we give it a bounded deadline — an unreachable IdP at boot
	// should surface fast rather than hanging on flag.Parse().
	var oidcProvider *portaloidc.Provider
	oidcCfg := &portaloidc.Config{
		IssuerURL:    cfg.OIDC.IssuerURL,
		ClientID:     cfg.OIDC.ClientID,
		ClientSecret: cfg.OIDC.ClientSecret,
		RedirectURL:  cfg.OIDC.RedirectURL,
		AdminClaim:   cfg.OIDC.AdminClaim,
		AdminValue:   cfg.OIDC.AdminValue,
		CookieSecure: cfg.OIDC.CookieSecure,
	}
	if oidcCfg.Enabled() {
		// Cluster-safe sessions: when the portal runs against a persistent
		// store, sessions live there too so any replica can validate the
		// cookie set by another. The in-memory store keeps using the
		// in-memory SessionStore — there's no DB to share with anyway.
		var sessionStore portaloidc.SessionStore
		if _, isMemory := s.(*store.Memory); isMemory {
			sessionStore = portaloidc.NewMemoryStore()
		} else {
			sessionStore = portaloidc.NewSQLStore(s)
			logger.Info("oidc_sessions_persistent", "store", cfg.Store.URL)
		}
		discCtx, discCancel := context.WithTimeout(context.Background(), 10*time.Second)
		p, err := portaloidc.New(discCtx, oidcCfg, sessionStore, logger)
		discCancel()
		if err != nil {
			logger.Error("oidc init failed", "err", err)
			logging.Sync()
			os.Exit(2)
		}
		// Wire first-login provisioning: on callback the provider materialises
		// or resolves a portal user for the IdP subject so grants handlers can
		// scope non-admin requests to their own user_id.
		oidcProvider = p.WithProvisioner(api.StoreUserProvisioner{Store: s})
		logger.Info("oidc enabled", "issuer", cfg.OIDC.IssuerURL)
	}

	mreg := metrics.New(time.Now())
	rlMetrics := api.NewRateLimitMetrics()

	// Entra integration — wire only when credentials are set. Policy-file
	// load is fail-closed: a broken file aborts boot.
	var entraClient entra.Client
	var requestPol *policy.RequestPolicy
	entraMetrics := notify.NewEntraMetrics()
	if cfg.Entra.Enabled() {
		c, err := entra.NewFromConfig(context.Background(), entra.Config{
			TenantID:     cfg.Entra.TenantID,
			ClientID:     cfg.Entra.ClientID,
			ClientSecret: cfg.Entra.ClientSecret,
			Logger:       logger,
		})
		if err != nil {
			logger.Error("entra init failed", "err", err)
			logging.Sync()
			os.Exit(2)
		}
		entraClient = c
		logger.Info("entra enabled", "tenant", cfg.Entra.TenantID, "sender", cfg.Entra.SenderUPN)
	}
	if cfg.Entra.PolicyFile != "" {
		p, err := policy.LoadRequestPolicy(cfg.Entra.PolicyFile)
		if err != nil {
			logger.Error("entra policy load failed", "err", err, "path", cfg.Entra.PolicyFile)
			logging.Sync()
			os.Exit(2)
		}
		requestPol = p
		logger.Info("entra policy loaded", "path", cfg.Entra.PolicyFile, "groups", len(p.Groups()))
	}

	handler := api.NewRouter(cfg, s, engine, logger,
		api.WithOIDC(oidcProvider),
		api.WithPromRegistry(mreg),
		api.WithRateLimitMetrics(rlMetrics),
		api.WithEphemeralManager(ephemeralMgr),
		api.WithEntra(entraClient),
		api.WithRequestPolicy(requestPol),
		api.WithEntraMail(cfg.Entra.SenderUPN, entraMetrics),
		api.WithPublicURL(cfg.HTTP.PublicURL),
		api.WithT2Mailbox(cfg.Entra.T2Mailbox),
	)

	srv := &http.Server{
		Addr:              cfg.HTTP.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       60 * time.Second,
	}

	var sidecar *obs.Server
	if cfg.HTTP.MetricsAddr != "" {
		sidecar = obs.NewServer(cfg.HTTP.MetricsAddr, logger,
			obs.BuildInfo{Version: Version, CommitHash: CommitHash, BuildTimestamp: BuildTimestamp, Builder: Builder},
			func() (uint64, uint64, uint64) { return 0, 0, 0 }) // portal has no conn counters today
		sidecar.SetAuditStats(auditMetrics.Snapshot)
		sidecar.SetGrantStats(auditMetrics.GrantsExpired)
		sidecar.SetRegistry(mreg)
		sidecar.SetRateLimitStats(rlMetrics.Snapshot)
		if ephemeralMgr != nil {
			sidecar.SetEphemeralStats(ephemeralMgr.Metrics().Snapshot)
		}
		sidecar.SetEntraStats(entraMetrics.Snapshot)
		if err := sidecar.Start(); err != nil {
			logger.Error("failed to start obs sidecar", "err", err)
			os.Exit(1)
		}
		sidecar.MarkReady()
	}

	logger.Info("portal starting",
		"listen", cfg.HTTP.ListenAddr,
		"version", Version,
		"proxy_token_enabled", cfg.ProxyToken != "",
		"user_token_enabled", cfg.UserToken != "",
		"auto_approve", cfg.Approval.AutoApprove,
		"approval_webhook_enabled", cfg.Approval.WebhookURL != "",
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

	apiCtx, apiCancel := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownGrace)
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
