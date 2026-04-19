package api

import (
	"log/slog"
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/babs/poc-proxies/portal/internal/config"
	"github.com/babs/poc-proxies/portal/internal/ephemeral"
	"github.com/babs/poc-proxies/portal/internal/oidc"
	"github.com/babs/poc-proxies/portal/internal/policy"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// NewRouter wires all handlers behind the shared middleware stack.
//   - Proxy-facing endpoints are guarded by X-Portal-Token.
//   - Operator (admin) endpoints — /api/v1/users, /api/v1/backends*,
//     /api/v1/grants* — accept an OIDC session cookie (when `provider` is
//     supplied AND the session carries IsAdmin=true) OR a static bearer token
//     (when `cfg.UserToken` is set; bearer is already a privileged operator
//     credential). Both guards empty = open (local-dev convenience).
//   - /oidc/login, /oidc/callback, /oidc/logout are mounted when provider!=nil.
func NewRouter(cfg *config.Config, s store.Store, eng *policy.Engine, provider *oidc.Provider, logger *slog.Logger) http.Handler {
	return NewRouterWithEphemeral(cfg, s, eng, provider, nil, logger)
}

// NewRouterWithEphemeral is the full-fat constructor that additionally wires
// the ephemeral backend-user provisioner. Passing a nil manager is equivalent
// to NewRouter — the handler falls back to the shared BackendAccount path.
func NewRouterWithEphemeral(cfg *config.Config, s store.Store, eng *policy.Engine, provider *oidc.Provider, mgr *ephemeral.Manager, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	// Proxy-facing endpoints
	proxyMux := http.NewServeMux()
	proxyMux.Handle("/api/v1/auth", &authHandler{engine: eng, logger: logger})
	proxyMux.Handle("/api/v1/audit/query", &auditHandler{store: s, logger: logger})
	// Mid-session revoke polling — proxies hit this every few seconds per active conn.
	proxyMux.Handle("/api/v1/grants/status/", &grantStatusHandler{store: s, logger: logger})
	proxyGuarded := requireProxyToken(cfg.ProxyToken, proxyMux)

	// User-facing endpoints
	userMux := http.NewServeMux()
	grants := &grantsHandler{
		store:         s,
		logger:        logger,
		autoApprove:   cfg.AutoApprove,
		webhookURL:    cfg.ApprovalWebhookURL,
		webhookSecret: cfg.ApprovalWebhookSecret,
		ephemeral:     mgr,
	}
	userMux.Handle("/api/v1/grants", grants)
	userMux.Handle("/api/v1/grants/", grants)
	admin := &adminHandler{store: s, logger: logger}
	userMux.Handle("/api/v1/users", admin)
	userMux.Handle("/api/v1/backends", admin)
	userMux.Handle("/api/v1/backends/", admin)
	userGuarded := requireUserAuth(provider, cfg.UserToken, userMux)

	// Route by prefix — ServeMux uses longest-match, so /grants/status/ wins
	// over /grants/ regardless of registration order. Declarations are just
	// grouped by audience here.
	mux.Handle("/api/v1/auth", proxyGuarded)
	mux.Handle("/api/v1/audit/query", proxyGuarded)
	mux.Handle("/api/v1/grants/status/", proxyGuarded)
	mux.Handle("/api/v1/grants", userGuarded)
	mux.Handle("/api/v1/grants/", userGuarded)
	mux.Handle("/api/v1/users", userGuarded)
	mux.Handle("/api/v1/backends", userGuarded)
	mux.Handle("/api/v1/backends/", userGuarded)

	// OIDC auth flow (no-op if provider is nil).
	provider.RegisterRoutes(mux)

	// otelhttp wraps the whole mux so every request becomes a server span.
	// When no tracer endpoint is configured, the global tracer is no-op and
	// the wrapper adds a single conditional on the hot path — negligible cost.
	return otelhttp.NewHandler(accessLog(logger, mux), "portal.http")
}
