package api

import (
	"log/slog"
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/babs/poc-proxies/internal/metrics"
	"github.com/babs/poc-proxies/internal/ratelimit"
	"github.com/babs/poc-proxies/portal/internal/api/ui"
	"github.com/babs/poc-proxies/portal/internal/config"
	"github.com/babs/poc-proxies/portal/internal/entra"
	"github.com/babs/poc-proxies/portal/internal/ephemeral"
	"github.com/babs/poc-proxies/portal/internal/notify"
	"github.com/babs/poc-proxies/portal/internal/oidc"
	"github.com/babs/poc-proxies/portal/internal/policy"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// routerOpts gathers the optional wiring the router needs.
// Populated via functional Option helpers.
type routerOpts struct {
	provider          *oidc.Provider
	promRegistry      *metrics.Registry
	rlMetrics         *RateLimitMetrics
	ephemeralMgr      *ephemeral.Manager
	entra             entra.Client
	requestPol        *policy.RequestPolicy
	entraSender       string
	publicURL         string
	entraMetrics      *EntraMetrics
	entraAdminMailbox string
	entraAdminGroupID string
}

// Option configures NewRouter. Keeps the constructor signature stable as new
// integrations land.
type Option func(*routerOpts)

// WithOIDC wires the OIDC provider and mounts /oidc/{login,callback,logout}.
func WithOIDC(p *oidc.Provider) Option { return func(o *routerOpts) { o.provider = p } }

// WithPromRegistry attaches a Prometheus registry so the metrics middleware
// records latency / status histograms on the shared registry.
func WithPromRegistry(r *metrics.Registry) Option { return func(o *routerOpts) { o.promRegistry = r } }

// WithRateLimitMetrics pins a shared RateLimitMetrics so main() can scrape
// per-dimension rejection counters from the obs sidecar.
func WithRateLimitMetrics(m *RateLimitMetrics) Option { return func(o *routerOpts) { o.rlMetrics = m } }

// WithEphemeralManager enables per-grant DB-user provisioning at /claim.
func WithEphemeralManager(m *ephemeral.Manager) Option {
	return func(o *routerOpts) { o.ephemeralMgr = m }
}

// WithEntra wires the Entra/Graph client used for manager resolution and mail.
func WithEntra(c entra.Client) Option { return func(o *routerOpts) { o.entra = c } }

// WithRequestPolicy wires the trio policy that gates non-admin grant creates.
func WithRequestPolicy(p *policy.RequestPolicy) Option {
	return func(o *routerOpts) { o.requestPol = p }
}

// WithEntraMail configures the mail sender address + metrics sink.
func WithEntraMail(sender string, m *EntraMetrics) Option {
	return func(o *routerOpts) { o.entraSender = sender; o.entraMetrics = m }
}

// WithPublicURL is the externally reachable base URL embedded in outbound mail.
func WithPublicURL(u string) Option { return func(o *routerOpts) { o.publicURL = u } }

// WithAdminReachability configures the admin mailbox / group-id used once the
// manager half of the dual gate fires.
func WithAdminReachability(mailbox, groupID string) Option {
	return func(o *routerOpts) { o.entraAdminMailbox = mailbox; o.entraAdminGroupID = groupID }
}

// RouterDeps is a convenience bag for callers (typically tests) that set many
// Entra-flavoured fields at once. Prefer the individual WithXxx helpers in
// production; this keeps the test wiring terse.
type RouterDeps struct {
	Entra             entra.Client
	RequestPol        *policy.RequestPolicy
	EntraSender       string
	PublicURL         string
	EntraMetrics      *EntraMetrics
	EntraAdminMailbox string
	EntraAdminGroupID string
}

// Options translates the deps bag into the canonical []Option list.
func (d RouterDeps) Options() []Option {
	return []Option{
		WithEntra(d.Entra),
		WithRequestPolicy(d.RequestPol),
		WithEntraMail(d.EntraSender, d.EntraMetrics),
		WithPublicURL(d.PublicURL),
		WithAdminReachability(d.EntraAdminMailbox, d.EntraAdminGroupID),
	}
}

// NewRouter wires all handlers behind the shared middleware stack.
//   - Proxy-facing endpoints are guarded by X-Portal-Token.
//   - Operator endpoints accept an OIDC session cookie OR a static bearer token
//     (both empty = open, local-dev convenience).
//   - /oidc/login, /oidc/callback, /oidc/logout are mounted via WithOIDC.
//
// Optional wiring (entra, ephemeral, rate-limit metrics, prom registry, etc.)
// is supplied via Option functions so the constructor signature stays stable.
func NewRouter(cfg *config.Config, s store.Store, eng *policy.Engine, logger *slog.Logger, opts ...Option) http.Handler {
	o := &routerOpts{}
	for _, apply := range opts {
		apply(o)
	}
	if o.rlMetrics == nil {
		o.rlMetrics = NewRateLimitMetrics()
	}
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
	authRL := requireAuthRateLimit(authIP, authUser, AuthUsernameKey, o.rlMetrics,
		&authHandler{engine: eng, logger: logger})
	proxyMux.Handle("/api/v1/auth", authRL)
	proxyMux.Handle("/api/v1/audit/query", &auditHandler{store: s, logger: logger})
	proxyMux.Handle("/api/v1/grants/status/", &grantStatusHandler{store: s, logger: logger})
	proxyGuarded := requireProxyToken(cfg.ProxyToken, proxyMux)

	// Build the notifier fan-out. Nil builders drop out via notify.NewMulti.
	var mail notify.Notifier
	if m := notify.NewEntraMailNotifier(notify.EntraConfig{
		Client: o.entra, Sender: o.entraSender, PublicURL: o.publicURL,
		AdminMailbox: o.entraAdminMailbox, AdminGroupID: o.entraAdminGroupID,
		Metrics: o.entraMetrics, Logger: logger,
	}); m != nil {
		mail = m
	}
	var webhook notify.Notifier
	if cfg.ApprovalWebhookURL != "" {
		webhook = notify.NewWebhookNotifier(cfg.ApprovalWebhookURL, cfg.ApprovalWebhookSecret, nil, logger)
	}
	notifier := notify.Notifier(notify.Noop{})
	if mail != nil || webhook != nil {
		notifier = notify.NewMulti(mail, webhook)
	}

	// User-facing endpoints
	userMux := http.NewServeMux()
	grants := &grantsHandler{
		store:            s,
		logger:           logger,
		autoApprove:      cfg.AutoApprove,
		ephemeral:        o.ephemeralMgr,
		entra:            o.entra,
		requestPol:       o.requestPol,
		entraMetrics:     o.entraMetrics,
		notifier:         notifier,
		validationWindow: cfg.ValidationWindow,
		claimWindow:      cfg.ClaimWindow,
		credentialTTL:    cfg.CredentialTTL,
	}
	grantsCollection := withPOSTOnly(requireAuthRateLimit(grantsIP, grantsUser, GrantUserIDKey, o.rlMetrics, grants), grants)
	userMux.Handle("/api/v1/grants", grantsCollection)
	userMux.Handle("/api/v1/grants/", requireIPRateLimit(grantsIP, o.rlMetrics, grants))
	admin := &adminHandler{store: s, logger: logger}
	userMux.Handle("/api/v1/users", admin)
	userMux.Handle("/api/v1/backends", admin)
	userMux.Handle("/api/v1/backends/", admin)
	userGuarded := requireUserAuth(o.provider, cfg.UserToken, userMux)

	mux.Handle("/api/v1/auth", proxyGuarded)
	mux.Handle("/api/v1/audit/query", proxyGuarded)
	mux.Handle("/api/v1/grants/status/", proxyGuarded)
	mux.Handle("/api/v1/grants", userGuarded)
	mux.Handle("/api/v1/grants/", userGuarded)
	mux.Handle("/api/v1/users", userGuarded)
	mux.Handle("/api/v1/backends", userGuarded)
	mux.Handle("/api/v1/backends/", userGuarded)

	uiHandler := requireUserAuthHTML(o.provider, cfg.UserToken, ui.Handler())
	mux.Handle("/ui/", uiHandler)
	sessionGuarded := requireUserAuth(o.provider, cfg.UserToken, http.HandlerFunc(sessionHandler))
	mux.Handle("/api/v1/session", sessionGuarded)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/ui/", http.StatusFound)
	})

	o.provider.RegisterRoutes(mux)

	// Middleware stack, innermost → outermost: mux → promMetrics → accessLog → otelhttp
	return otelhttp.NewHandler(accessLog(logger, promMetrics(o.promRegistry, mux)), "portal.http")
}
