package main

import (
	"context"
	"errors"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/babs/poc-proxies/internal/logging"
	"github.com/babs/poc-proxies/internal/obs"
	"github.com/babs/poc-proxies/portal/internal/api"
	"github.com/babs/poc-proxies/portal/internal/config"
	"github.com/babs/poc-proxies/portal/internal/entra"
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

	auditMetrics := store.NewAuditMetrics()
	sweeperCtx, stopSweeper := context.WithCancel(context.Background())
	defer stopSweeper()
	sweeperDone := make(chan struct{})
	go func() {
		store.RunAuditSweeper(sweeperCtx, s, store.AuditSweeperConfig{
			RetentionDays: cfg.AuditRetentionDays,
			MaxEntries:    cfg.AuditMaxEntries,
			Interval:      cfg.AuditSweepInterval,
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

	// Entra integration — wire only when credentials are set. Policy-file
	// load is fail-closed: a broken file aborts boot so operators don't
	// silently lose RBAC scoping.
	var entraClient entra.Client
	var requestPol *policy.RequestPolicy
	entraMetrics := api.NewEntraMetrics()
	if cfg.EntraEnabled() {
		c, err := entra.NewFromConfig(context.Background(), entra.Config{
			TenantID:     cfg.EntraTenantID,
			ClientID:     cfg.EntraClientID,
			ClientSecret: cfg.EntraClientSecret,
			Logger:       logger,
		})
		if err != nil {
			logger.Error("entra init failed", "err", err)
			logging.Sync()
			os.Exit(2)
		}
		entraClient = c
		logger.Info("entra enabled", "tenant", cfg.EntraTenantID, "sender", cfg.EntraSenderUPN)
	}
	if cfg.EntraPolicyFile != "" {
		p, err := policy.LoadRequestPolicy(cfg.EntraPolicyFile)
		if err != nil {
			logger.Error("entra policy load failed", "err", err, "path", cfg.EntraPolicyFile)
			logging.Sync()
			os.Exit(2)
		}
		requestPol = p
		logger.Info("entra policy loaded", "path", cfg.EntraPolicyFile, "groups", len(p.Groups()))
	}

	handler := api.NewRouter(cfg, s, engine, oidcProvider, logger, api.RouterDeps{
		Entra:        entraClient,
		RequestPol:   requestPol,
		EntraSender:  cfg.EntraSenderUPN,
		PublicURL:    cfg.PublicURL,
		EntraMetrics: entraMetrics,
	})

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
		sidecar.SetEntraStats(entraMetrics.Snapshot)
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
