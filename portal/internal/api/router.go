package api

import (
	"log/slog"
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/babs/poc-proxies/internal/ratelimit"
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
//
// When cfg.AuthRatePerIP or cfg.AuthRatePerUser are >0, POST /api/v1/auth and
// POST /api/v1/grants get wrapped in a token-bucket rate limiter; rejections
// surface on /metrics as rate_limited_total. Pass rlMetrics=nil to build an
// internal counter set (unreachable by /metrics) — typically only tests do that.
func NewRouter(cfg *config.Config, s store.Store, eng *policy.Engine, provider *oidc.Provider, logger *slog.Logger, rlMetrics *RateLimitMetrics) http.Handler {
	if rlMetrics == nil {
		rlMetrics = NewRateLimitMetrics()
	}
	// Separate bucket sets per endpoint so /grants floods don't drain the
	// /auth budget and vice-versa. TTL matches package default (10m) so the
	// eviction window is long enough to catch repeat offenders but short
	// enough to bound memory against an IP-scanning attacker.
	var (
		authIP, authUser     *ratelimit.Buckets
		grantsIP, grantsUser *ratelimit.Buckets
	)
	if cfg.AuthRatePerIP > 0 {
		authIP = ratelimit.New(ratelimit.PerMinute(cfg.AuthRatePerIP))
		grantsIP = ratelimit.New(ratelimit.PerMinute(cfg.AuthRatePerIP))
	}
	if cfg.AuthRatePerUser > 0 {
		authUser = ratelimit.New(ratelimit.PerMinute(cfg.AuthRatePerUser))
		grantsUser = ratelimit.New(ratelimit.PerMinute(cfg.AuthRatePerUser))
	}

	mux := http.NewServeMux()

	// Proxy-facing endpoints
	proxyMux := http.NewServeMux()
	authRL := requireAuthRateLimit(authIP, authUser, AuthUsernameKey, rlMetrics,
		&authHandler{engine: eng, logger: logger})
	proxyMux.Handle("/api/v1/auth", authRL)
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
	// Only the /api/v1/grants collection POST is rate-limited — GET/PATCH on
	// :id are operator housekeeping and expected to be infrequent. Mounting
	// the limiter at the collection path keeps GETs unthrottled (they route
	// through the same handler but reading a list doesn't cost PBKDF2).
	grantsCollection := withPOSTOnly(requireAuthRateLimit(grantsIP, grantsUser, GrantUserIDKey, rlMetrics, grants), grants)
	userMux.Handle("/api/v1/grants", grantsCollection)
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
