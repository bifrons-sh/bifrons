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
	portaloidc "github.com/babs/poc-proxies/portal/internal/oidc"
	"github.com/babs/poc-proxies/portal/internal/policy"
	"github.com/babs/poc-proxies/portal/internal/store"
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

	// OpenTelemetry init — honours OTEL_EXPORTER_OTLP_ENDPOINT; empty = noop
	// tracer (otelhttp wrapper stays a cheap no-op).
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

	s := store.NewMemory()
	engine := policy.New(s)

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

	handler := api.NewRouter(cfg, s, engine, oidcProvider, logger)

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
	if sidecar != nil {
		// Dedicated deadline so the sidecar still gets time even if the API
		// drain consumed the full ShutdownGrace window.
		sideCtx, sideCancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = sidecar.Shutdown(sideCtx)
		sideCancel()
	}
	logger.Info("portal stopped")
}
