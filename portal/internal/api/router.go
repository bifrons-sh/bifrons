package api

import (
	"context"
	"log/slog"
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/babs/poc-proxies/internal/metrics"
	"github.com/babs/poc-proxies/internal/ratelimit"
	"github.com/babs/poc-proxies/portal/internal/api/ui"
	"github.com/babs/poc-proxies/portal/internal/config"
	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/entra"
	"github.com/babs/poc-proxies/portal/internal/notify"
	"github.com/babs/poc-proxies/portal/internal/oidc"
	"github.com/babs/poc-proxies/portal/internal/policy"
	"github.com/babs/poc-proxies/portal/internal/provisioning"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// routerOpts gathers the optional wiring the router needs.
// Populated via functional Option helpers.
type routerOpts struct {
	provider     *oidc.Provider
	promRegistry *metrics.Registry
	rlMetrics    *RateLimitMetrics
	provisioner  *provisioning.Client
	entra        entra.Client
	requestPol   *policy.RequestPolicy
	entraSender  string
	publicURL    string
	entraMetrics *notify.EntraMetrics
	// t2Mailbox is the reachability fallback mailbox for gate2
	// notifications (applied regardless of backend). Per-backend T2
	// recipients are resolved from backends.t2_group_slug at notify-time.
	t2Mailbox string
	// lifecycleCtx ties background goroutines started by NewRouter (currently
	// the rate-limit bucket sweeper) to the server lifetime. nil ⇒ no sweeper
	// is started (tests / callers that don't manage a lifecycle).
	lifecycleCtx context.Context
	// notifierSink, when non-nil, receives the constructed notifier so main()
	// can call Wait() during graceful shutdown and drain in-flight deliveries.
	notifierSink *notify.Notifier
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

// WithProvisioningClient enables per-grant DB-user provisioning at /claim by
// emitting intents to the outbox. The portal holds no master/DBA credentials
// and never runs DDL itself (spec §8.2) — a dedicated worker consumes the
// intents. nil leaves ephemeral provisioning disabled (shared-account path).
func WithProvisioningClient(c *provisioning.Client) Option {
	return func(o *routerOpts) { o.provisioner = c }
}

// WithEntra wires the Entra/Graph client used for validator resolution and mail.
func WithEntra(c entra.Client) Option { return func(o *routerOpts) { o.entra = c } }

// WithRequestPolicy wires the trio policy that gates non-admin grant creates.
func WithRequestPolicy(p *policy.RequestPolicy) Option {
	return func(o *routerOpts) { o.requestPol = p }
}

// WithEntraMail configures the mail sender address + metrics sink.
func WithEntraMail(sender string, m *notify.EntraMetrics) Option {
	return func(o *routerOpts) { o.entraSender = sender; o.entraMetrics = m }
}

// WithPublicURL is the externally reachable base URL embedded in outbound mail.
func WithPublicURL(u string) Option { return func(o *routerOpts) { o.publicURL = u } }

// WithT2Mailbox configures a single-mailbox reachability fallback for
// gate2 notifications. Primary recipient resolution is per-backend via
// backends.t2_group_slug; this mailbox is appended regardless so the
// notification always reaches somebody even on misconfigured backends.
func WithT2Mailbox(mailbox string) Option {
	return func(o *routerOpts) { o.t2Mailbox = mailbox }
}

// WithLifecycleContext ties NewRouter's background goroutines (the rate-limit
// bucket sweeper) to a server-scoped context. Passing main()'s root context
// makes them stop on shutdown; omitting it leaves no sweeper running.
func WithLifecycleContext(ctx context.Context) Option {
	return func(o *routerOpts) { o.lifecycleCtx = ctx }
}

// WithNotifierSink hands the constructed notifier back to the caller through
// the supplied pointer. main() needs the reference so it can call Wait() after
// srv.Shutdown to drain in-flight webhook/email deliveries instead of dropping
// them on SIGTERM. Keeps NewRouter's return signature stable for the many
// callers (portal.go, tests) that don't need the handle.
func WithNotifierSink(sink *notify.Notifier) Option {
	return func(o *routerOpts) { o.notifierSink = sink }
}

// RouterDeps is a convenience bag for callers (typically tests) that set many
// Entra-flavoured fields at once. Prefer the individual WithXxx helpers in
// production; this keeps the test wiring terse.
type RouterDeps struct {
	Entra        entra.Client
	RequestPol   *policy.RequestPolicy
	EntraSender  string
	PublicURL    string
	EntraMetrics *notify.EntraMetrics
	T2Mailbox    string
}

// Options translates the deps bag into the canonical []Option list.
func (d RouterDeps) Options() []Option {
	return []Option{
		WithEntra(d.Entra),
		WithRequestPolicy(d.RequestPol),
		WithEntraMail(d.EntraSender, d.EntraMetrics),
		WithPublicURL(d.PublicURL),
		WithT2Mailbox(d.T2Mailbox),
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
	if cfg.RateLimit.PerIP > 0 {
		authIP = ratelimit.New(ratelimit.PerMinute(cfg.RateLimit.PerIP))
		grantsIP = ratelimit.New(ratelimit.PerMinute(cfg.RateLimit.PerIP))
	}
	if cfg.RateLimit.PerUser > 0 {
		authUser = ratelimit.New(ratelimit.PerMinute(cfg.RateLimit.PerUser))
		grantsUser = ratelimit.New(ratelimit.PerMinute(cfg.RateLimit.PerUser))
	}
	// Security: per-IP/per-user buckets are keyed by an attacker-controllable
	// dimension (source IP). Without periodic eviction the bucket map grows
	// unbounded under a spoofed-IP flood and eventually OOMs the portal. Sweep
	// idle buckets on a timer tied to the server lifecycle so the map stays
	// bounded by the unique-key rate across the bucket TTL.
	if o.lifecycleCtx != nil {
		startBucketSweeper(o.lifecycleCtx, logger, authIP, authUser, grantsIP, grantsUser)
	}

	mux := http.NewServeMux()

	// Proxy-facing endpoints
	proxyMux := http.NewServeMux()
	authRL := requireAuthRateLimit(authIP, authUser, AuthUsernameKey, o.rlMetrics,
		&authHandler{engine: eng, logger: logger})
	proxyMux.Handle("/api/v1/auth", authRL)
	proxyMux.Handle("/api/v1/audit/query", &auditHandler{store: s, logger: logger})
	proxyMux.Handle("GET /api/v1/grants/status/{id}", &grantStatusHandler{store: s, logger: logger})
	proxyGuarded := requireProxyToken(cfg.ProxyToken, proxyMux)

	// Build the notifier fan-out. Nil builders drop out via notify.NewMulti.
	// T2 lookup is per-backend: each Event carries its backend, and the
	// closure resolves the backend's T2 group membership via the store. No
	// live IdP call at send time.
	t2Lookup := func(ctx context.Context, backend domain.Backend) ([]string, error) {
		if backend.T2GroupSlug == "" {
			return nil, nil
		}
		g, err := s.GetGroupBySlug(ctx, backend.T2GroupSlug)
		if err != nil {
			return nil, err
		}
		members, err := s.ListGroupMembers(ctx, g.ID)
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(members))
		for _, u := range members {
			if u.Email != "" {
				out = append(out, u.Email)
			}
		}
		return out, nil
	}
	var mail notify.Notifier
	if m := notify.NewEntraMailNotifier(notify.EntraConfig{
		Client: o.entra, Sender: o.entraSender, PublicURL: o.publicURL,
		T2Mailbox: o.t2Mailbox, T2Lookup: t2Lookup,
		Metrics: o.entraMetrics, Logger: logger,
	}); m != nil {
		mail = m
	}
	var webhook notify.Notifier
	if cfg.Approval.WebhookURL != "" {
		webhook = notify.NewWebhookNotifier(cfg.Approval.WebhookURL, cfg.Approval.WebhookSecret, nil, logger)
	}
	notifier := notify.Notifier(notify.Noop{})
	if mail != nil || webhook != nil {
		notifier = notify.NewMulti(mail, webhook)
	}
	// Hand the notifier back so main() can drain in-flight deliveries on
	// shutdown (see WithNotifierSink). Deliveries are detached goroutines; a
	// SIGTERM mid-POST drops them unless Wait() runs after srv.Shutdown.
	if o.notifierSink != nil {
		*o.notifierSink = notifier
	}

	// Grants + admin endpoints register onto a shared user-mux using Go 1.22
	// method + pattern matching (handlers pull path params via r.PathValue).
	// Rate-limit wrappers sit in front: the collection POST is body-aware so
	// it can key the user bucket; the sub-resource paths only bucket per-IP
	// (no body to inspect + keeps hot-path cheap).
	userMux := http.NewServeMux()
	grants := &grantsHandler{
		store:            s,
		logger:           logger,
		autoApprove:      cfg.Approval.AutoApprove,
		provisioner:      o.provisioner,
		entra:            o.entra,
		requestPol:       o.requestPol,
		entraMetrics:     o.entraMetrics,
		notifier:         notifier,
		validationWindow: cfg.Windows.Validation,
		claimWindow:      cfg.Windows.Claim,
		credentialTTL:    cfg.Windows.CredentialTTL,
	}
	// Build an unwrapped grants mux so we can layer rate-limit middleware per
	// route pattern without the flat sub-resource catch-all we used before.
	grantsMux := http.NewServeMux()
	registerGrantRoutes(grantsMux, grants)
	// Wrap collection POST (/api/v1/grants) with the body-keyed limiter; every
	// other grants path goes through the cheap per-IP limiter.
	userMux.Handle("POST /api/v1/grants",
		requireAuthRateLimit(grantsIP, grantsUser, GrantUserIDKey, o.rlMetrics, grantsMux))
	userMux.Handle("/api/v1/grants/",
		requireIPRateLimit(grantsIP, o.rlMetrics, grantsMux))
	userMux.Handle("GET /api/v1/grants", grantsMux)

	adminH := &adminHandler{store: s, logger: logger}
	registerAdminRoutes(userMux, adminH)
	provH := &provisioningHandler{store: s, logger: logger}
	registerProvisioningRoutes(userMux, provH)
	orgH := &orgHandler{store: s, logger: logger}
	registerOrgRoutes(userMux, orgH)

	userGuarded := requireUserAuth(o.provider, cfg.UserToken, userMux)

	mux.Handle("/api/v1/auth", proxyGuarded)
	mux.Handle("/api/v1/audit/query", proxyGuarded)
	mux.Handle("/api/v1/grants/status/", proxyGuarded)
	mux.Handle("/api/v1/grants", userGuarded)
	mux.Handle("/api/v1/grants/", userGuarded)
	mux.Handle("/api/v1/users", userGuarded)
	mux.Handle("/api/v1/users/", userGuarded) // /users/{id}/validator, /users/{id}/groups
	mux.Handle("/api/v1/backends", userGuarded)
	mux.Handle("/api/v1/backends/", userGuarded)
	mux.Handle("/api/v1/groups", userGuarded)
	mux.Handle("/api/v1/groups/", userGuarded)
	mux.Handle("/api/v1/provisioning/", userGuarded) // worker-liveness (operator-gated)

	uiHandler := requireUserAuthHTML(o.provider, cfg.UserToken, ui.Handler(logger))
	mux.Handle("/ui/", uiHandler)
	sessionGuarded := requireUserAuth(o.provider, cfg.UserToken, sessionHandler(cfg.OIDC.AccountURL))
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
