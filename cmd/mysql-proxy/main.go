package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/babs/poc-proxies/internal/audit"
	"github.com/babs/poc-proxies/internal/auth"
	"github.com/babs/poc-proxies/internal/config"
	"github.com/babs/poc-proxies/internal/logging"
	"github.com/babs/poc-proxies/internal/obs"
	"github.com/babs/poc-proxies/internal/protocol/mysql"
	"github.com/babs/poc-proxies/internal/proxy"
)

var (
	Version        = "v0.0.0"
	Commit         = "0000000"
	BuildTimestamp = "unknown"
	Builder        = "unknown"
)

func main() {
	cfg := config.RegisterFlags(flag.CommandLine, "127.0.0.1:13306", "127.0.0.1:3306")
	authURL := flag.String("auth-url", config.GetEnv("PROXY_AUTH_URL", ""), "Portal auth URL (env: PROXY_AUTH_URL, enables auth re-mapping)")
	auditURL := flag.String("audit-url", config.GetEnv("PROXY_AUDIT_URL", ""), "Portal audit URL (env: PROXY_AUDIT_URL, enables audit shipping)")
	portalToken := flag.String("portal-token", config.GetEnv("PROXY_PORTAL_TOKEN", ""), "Shared secret sent as X-Portal-Token (env: PROXY_PORTAL_TOKEN)")
	flag.Parse()

	logger := logging.New()
	defer logging.Sync()

	if err := cfg.Validate(); err != nil {
		logger.Error("invalid config", "err", err)
		logging.Sync()
		os.Exit(2)
	}

	var authClient *auth.Client
	if *authURL != "" {
		authClient = auth.NewClient(*authURL)
		logger.Info("auth re-mapping enabled", "auth_url", *authURL)
	}

	auditClient := audit.New(audit.Config{
		URL:   *auditURL,
		Token: *portalToken,
	}, logger)
	if *auditURL != "" {
		logger.Info("audit shipping enabled", "audit_url", *auditURL)
	}

	handler := mysql.NewFromConfig(logger, authClient, auditClient, cfg)
	srv, err := proxy.New(cfg, handler, logger)
	if err != nil {
		logger.Error("failed to start", "err", err)
		os.Exit(1)
	}

	var sidecar *obs.Server
	if cfg.MetricsAddr != "" {
		sidecar = obs.NewServer(cfg.MetricsAddr, logger,
			obs.BuildInfo{Version: Version, Commit: Commit, BuildTimestamp: BuildTimestamp, Builder: Builder},
			srv.Stats)
		if err := sidecar.Start(); err != nil {
			logger.Error("failed to start obs sidecar", "err", err)
			os.Exit(1)
		}
		sidecar.MarkReady()
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Info("starting mysql proxy", "listen", cfg.ListenAddr, "backend", cfg.BackendAddr, "version", Version)
	serveErr := srv.Serve(ctx)

	// Flush in-flight audit batch on graceful shutdown.
	if auditClient != nil {
		auditCtx, auditCancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = auditClient.Shutdown(auditCtx)
		auditCancel()
	}
	if sidecar != nil {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = sidecar.Shutdown(shutCtx)
		cancel()
	}
	if serveErr != nil {
		logger.Error("server error", "err", serveErr)
		os.Exit(1)
	}
}
