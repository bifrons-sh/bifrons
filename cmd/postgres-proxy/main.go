package main

import (
	"context"
	"crypto/tls"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/babs/poc-proxies/internal/audit"
	"github.com/babs/poc-proxies/internal/auth"
	"github.com/babs/poc-proxies/internal/config"
	"github.com/babs/poc-proxies/internal/logging"
	"github.com/babs/poc-proxies/internal/metrics"
	"github.com/babs/poc-proxies/internal/obs"
	"github.com/babs/poc-proxies/internal/protocol/postgres"
	"github.com/babs/poc-proxies/internal/proxy"
	"github.com/babs/poc-proxies/internal/tlsutil"
)

var (
	Version        = "v0.0.0"
	Commit         = "0000000"
	BuildTimestamp = "unknown"
	Builder        = "unknown"
)

func main() {
	cfg := config.RegisterFlags(flag.CommandLine, "127.0.0.1:15432", "127.0.0.1:5432")
	authURL := flag.String("auth-url", config.GetEnv("PROXY_AUTH_URL", ""), "Portal auth URL (env: PROXY_AUTH_URL, enables auth re-mapping)")
	auditURL := flag.String("audit-url", config.GetEnv("PROXY_AUDIT_URL", ""), "Portal audit URL (env: PROXY_AUDIT_URL, enables audit shipping)")
	portalBase := flag.String("portal-url", config.GetEnv("PROXY_PORTAL_URL", ""), "Portal base URL for mid-session revoke polling (env: PROXY_PORTAL_URL, enables revoke watcher)")
	portalToken := flag.String("portal-token", config.GetEnv("PROXY_PORTAL_TOKEN", ""), "Shared secret sent as X-Portal-Token (env: PROXY_PORTAL_TOKEN)")
	clientAuthMethod := flag.String("client-auth-method", "scram", "client-facing auth method when re-mapping: scram | cleartext")
	flag.Parse()

	logger := logging.New()
	defer logging.Sync()

	if err := cfg.Validate(); err != nil {
		logger.Error("invalid config", "err", err)
		logging.Sync()
		os.Exit(2)
	}

	// OpenTelemetry init — honours OTEL_EXPORTER_OTLP_ENDPOINT; empty = noop
	// tracer (hot path stays allocation-free).
	otelCtx, otelCancel := context.WithTimeout(context.Background(), 10*time.Second)
	tracerShutdown, err := obs.InitTracerWith(otelCtx, "postgres-proxy", Version, os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
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

	var authClient *auth.Client
	if *authURL != "" {
		switch postgres.ClientAuthMethod(*clientAuthMethod) {
		case postgres.ClientAuthSCRAM, postgres.ClientAuthCleartext:
			// ok
		default:
			logger.Error("invalid -client-auth-method", "value", *clientAuthMethod, "allowed", "scram|cleartext")
			logging.Sync()
			os.Exit(2)
		}
		authClient = auth.NewClient(*authURL)
		logger.Info("auth re-mapping enabled", "auth_url", *authURL, "client_auth_method", *clientAuthMethod)
	}

	// PostgreSQL must always listen plaintext: the wire protocol negotiates TLS
	// via SSLRequest on an already-open TCP connection. ForcePlainListener suppresses
	// the shared listener-level TLS wrap; if client-tls-cert is supplied the handler
	// upgrades inside handleStartup.
	var sslRequestTLS *tls.Config
	if cfg.ClientCertFile != "" && cfg.ClientKeyFile != "" {
		var err error
		sslRequestTLS, err = tlsutil.ListenerTLSConfig(cfg.ClientCertFile, cfg.ClientKeyFile, cfg.ClientCACertFile, cfg.ClientTLSRequired)
		if err != nil {
			logger.Error("failed to load SSL request TLS config", "err", err)
			os.Exit(1)
		}
	}

	auditClient := audit.New(audit.Config{URL: *auditURL, Token: *portalToken}, logger)
	if *auditURL != "" {
		logger.Info("audit shipping enabled", "audit_url", *auditURL)
	}

	mreg := metrics.New(time.Now())
	handler := postgres.NewFromConfig(logger, sslRequestTLS, authClient, auditClient, postgres.ClientAuthMethod(*clientAuthMethod), cfg).WithMetrics(mreg)
	if *portalBase != "" {
		handler.WithRevokeClient(proxy.NewHTTPGrantStatusClient(*portalBase, *portalToken, 3*time.Second))
		logger.Info("mid-session revoke watcher enabled", "portal_url", *portalBase)
	}
	srv, err := proxy.NewWithOptions(cfg, handler, logger, proxy.Options{ForcePlainListener: true, DBSystem: "postgresql"})
	if err != nil {
		logger.Error("failed to start", "err", err)
		os.Exit(1)
	}

	var sidecar *obs.Server
	if cfg.MetricsAddr != "" {
		sidecar = obs.NewServer(cfg.MetricsAddr, logger,
			obs.BuildInfo{Version: Version, Commit: Commit, BuildTimestamp: BuildTimestamp, Builder: Builder},
			srv.Stats)
		sidecar.SetRegistry(mreg)
		if err := sidecar.Start(); err != nil {
			logger.Error("failed to start obs sidecar", "err", err)
			os.Exit(1)
		}
		sidecar.MarkReady()
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Info("starting postgres proxy", "listen", cfg.ListenAddr, "backend", cfg.BackendAddr, "version", Version)
	serveErr := srv.Serve(ctx)

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
