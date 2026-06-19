package proxy

import (
	"context"
	"fmt"
	"log/slog"
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
)

// HandlerDeps carries the shared building blocks a protocol handler needs.
// RunService constructs these once and hands them to ServiceSpec.BuildHandler
// so each protocol only owns its wire-specific wiring (handler constructor,
// revoke client, optional SCRAM cache) and not the boilerplate around it.
type HandlerDeps struct {
	Logger      *slog.Logger
	Cfg         *config.Config
	AuthClient  *auth.Client // nil when auth re-mapping is disabled
	AuditClient *audit.Client
	Metrics     *metrics.Registry
	// PortalBase/PortalToken let the factory wire the mid-session revoke
	// watcher when PortalBase is non-empty; kept here so every protocol gets
	// identical revoke semantics.
	PortalBase  string
	PortalToken string
}

// BuiltHandler is the result of ServiceSpec.BuildHandler: the protocol handler
// plus an optional SCRAM-cache stats callback (nil when the protocol has no
// PBKDF2 cache or caching is disabled) so RunService can wire the sidecar
// generically without knowing protocol internals.
type BuiltHandler struct {
	Handler         Handler
	ScramCacheStats obs.ScramCacheStatsFn
}

// ServiceSpec describes a protocol proxy. The three cmd/*-proxy binaries differ
// only in these fields; everything else (logger, OTEL, auth/audit clients,
// metrics, obs sidecar, signal handling, graceful shutdown) is shared by
// RunService.
//
// The caller is responsible for flag parsing (each protocol has its own flag
// surface) and for populating Cfg + the auth/audit/portal endpoints before
// calling RunService.
type ServiceSpec struct {
	// Name is the OTEL service name and the log/startup label (e.g. "mysql-proxy").
	Name string
	// DBSystem is the OpenTelemetry db.system attribute (mysql|postgresql|mongodb).
	DBSystem string
	// ForcePlain suppresses listener-level TLS wrapping (PostgreSQL upgrades
	// inside its own startup handshake).
	ForcePlain bool
	// Build is the -ldflags-injected build metadata, surfaced on /metrics.
	Build obs.BuildInfo
	// Cfg is the parsed proxy config (post flag.Parse).
	Cfg *config.Config

	// Portal endpoints, parsed from the shared flag surface by the caller.
	AuthURL     string // empty disables auth re-mapping
	AuditURL    string // empty disables audit shipping
	PortalBase  string // empty disables the mid-session revoke watcher
	PortalToken string // shared secret sent as X-Portal-Token

	// BuildHandler constructs the protocol handler from the shared deps.
	BuildHandler func(deps HandlerDeps) (BuiltHandler, error)
}

// RunService runs a protocol proxy end-to-end: it owns the bootstrap that was
// previously duplicated across the cmd/*-proxy main() bodies — logger lifecycle,
// OTEL init/shutdown, auth/audit clients, metrics registry, obs sidecar, signal
// context, and graceful drain. Each cmd/*-proxy main() is now a thin call into
// this with a protocol-specific ServiceSpec.
//
// Returns nil on clean shutdown; a non-nil error means the caller should exit
// non-zero. Fatal startup problems are logged here and surfaced as an error.
func RunService(spec ServiceSpec) error {
	logger := logging.New()
	defer logging.Sync()

	cfg := spec.Cfg

	if err := cfg.Validate(); err != nil {
		logger.Error("invalid config", "err", err)
		return err
	}

	// OpenTelemetry init — honours OTEL_EXPORTER_OTLP_ENDPOINT; empty = noop
	// tracer (hot path stays allocation-free). Done early so even pre-serve
	// errors get captured in a parent span if one propagates in.
	otelCtx, otelCancel := context.WithTimeout(context.Background(), 10*time.Second)
	tracerShutdown, err := obs.InitTracerWith(otelCtx, spec.Name, spec.Build.Version, os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	otelCancel()
	if err != nil {
		logger.Error("otel init failed", "err", err)
		return err
	}
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = tracerShutdown(shutCtx)
		cancel()
	}()

	var authClient *auth.Client
	if spec.AuthURL != "" {
		authClient = auth.NewClient(spec.AuthURL)
		logger.Info("auth re-mapping enabled", "auth_url", spec.AuthURL)
	}

	auditClient := audit.New(audit.Config{URL: spec.AuditURL, Token: spec.PortalToken}, logger)
	if spec.AuditURL != "" {
		logger.Info("audit shipping enabled", "audit_url", spec.AuditURL)
	}

	mreg := metrics.New(time.Now())

	built, err := spec.BuildHandler(HandlerDeps{
		Logger:      logger,
		Cfg:         cfg,
		AuthClient:  authClient,
		AuditClient: auditClient,
		Metrics:     mreg,
		PortalBase:  spec.PortalBase,
		PortalToken: spec.PortalToken,
	})
	if err != nil {
		logger.Error("failed to build handler", "err", err)
		return err
	}

	srv, err := NewWithOptions(cfg, built.Handler, logger, Options{
		ForcePlainListener: spec.ForcePlain,
		DBSystem:           spec.DBSystem,
	})
	if err != nil {
		logger.Error("failed to start", "err", err)
		return err
	}

	var sidecar *obs.Server
	if cfg.MetricsAddr != "" {
		sidecar = obs.NewServer(cfg.MetricsAddr, logger, spec.Build, srv.Stats)
		sidecar.SetRegistry(mreg)
		if built.ScramCacheStats != nil {
			sidecar.SetScramCacheStats(built.ScramCacheStats)
		}
		sidecar.SetRateLimitStats(srv.RateLimitStats)
		if err := sidecar.Start(); err != nil {
			logger.Error("failed to start obs sidecar", "err", err)
			return err
		}
		sidecar.MarkReady()
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Info(fmt.Sprintf("starting %s", spec.Name), "listen", cfg.ListenAddr, "backend", cfg.BackendAddr, "version", spec.Build.Version)
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
		return serveErr
	}
	return nil
}
