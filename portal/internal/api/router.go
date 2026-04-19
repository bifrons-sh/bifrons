package api

import (
	"log/slog"
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/babs/poc-proxies/internal/metrics"
	"github.com/babs/poc-proxies/portal/internal/api/ui"
	"github.com/babs/poc-proxies/portal/internal/config"
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
	return NewRouterWithMetrics(cfg, s, eng, provider, logger, nil)
}

// NewRouterWithMetrics is NewRouter plus a shared metrics.Registry. When reg
// is non-nil, a histogram-recording middleware wraps every handler and the
// auth endpoint's internal lookup timing can be fed into the registry by
// callers holding the engine. Pass nil to opt out (same behaviour as NewRouter).
func NewRouterWithMetrics(cfg *config.Config, s store.Store, eng *policy.Engine, provider *oidc.Provider, logger *slog.Logger, reg *metrics.Registry) http.Handler {
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

	// Operator SPA. Served behind the same OIDC/bearer guard as the REST
	// API, but unauthenticated requests get a 302 to /oidc/login rather
	// than a JSON 401 — the browser is the audience here, not a script.
	// A session endpoint lets the loaded SPA render its landing state.
	uiHandler := requireUserAuthHTML(provider, cfg.UserToken, ui.Handler())
	mux.Handle("/ui/", uiHandler)
	sessionGuarded := requireUserAuth(provider, cfg.UserToken, http.HandlerFunc(sessionHandler))
	mux.Handle("/api/v1/session", sessionGuarded)
	// Root redirects to the SPA for convenience.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/ui/", http.StatusFound)
	})

	// OIDC auth flow (no-op if provider is nil).
	provider.RegisterRoutes(mux)

	// Middleware stack, innermost → outermost:
	//   mux → promMetrics → accessLog → otelhttp
	// promMetrics sits inside accessLog so the status code it records is the
	// status the handler emitted, not a wrapper-forced override.
	return otelhttp.NewHandler(accessLog(logger, promMetrics(reg, mux)), "portal.http")
}
