package api

import (
	"log/slog"
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/babs/poc-proxies/portal/internal/config"
	"github.com/babs/poc-proxies/portal/internal/oidc"
	"github.com/babs/poc-proxies/portal/internal/policy"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// NewRouter wires all handlers behind the shared middleware stack.
//   - Proxy-facing endpoints are guarded by X-Portal-Token.
//   - User-facing endpoints accept an OIDC session cookie (when `provider` is
//     supplied) OR a static bearer token (when `cfg.UserToken` is set). Both
//     guards empty = open (local-dev convenience).
//   - /oidc/login, /oidc/callback, /oidc/logout are mounted when provider!=nil.
func NewRouter(cfg *config.Config, s store.Store, eng *policy.Engine, provider *oidc.Provider, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	// Proxy-facing endpoints
	proxyMux := http.NewServeMux()
	proxyMux.Handle("/api/v1/auth", &authHandler{engine: eng, logger: logger})
	proxyMux.Handle("/api/v1/audit/query", &auditHandler{store: s, logger: logger})
	proxyGuarded := requireProxyToken(cfg.ProxyToken, proxyMux)

	// User-facing endpoints
	userMux := http.NewServeMux()
	grants := &grantsHandler{store: s, logger: logger}
	userMux.Handle("/api/v1/grants", grants)
	userMux.Handle("/api/v1/grants/", grants)
	admin := &adminHandler{store: s, logger: logger}
	userMux.Handle("/api/v1/users", admin)
	userMux.Handle("/api/v1/backends", admin)
	userMux.Handle("/api/v1/backends/", admin)
	userGuarded := requireUserAuth(provider, cfg.UserToken, userMux)

	// Route by prefix — proxy endpoints are specific paths; everything else goes to the user mux.
	mux.Handle("/api/v1/auth", proxyGuarded)
	mux.Handle("/api/v1/audit/query", proxyGuarded)
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
