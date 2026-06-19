package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/babs/poc-proxies/internal/auth"
	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/secrets"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// ErrNoActiveGrant is returned when the user has no applicable grant for the lookup.
var ErrNoActiveGrant = errors.New("no active grant")

// ErrGrantExpired is returned when the matching grant is past its expiry or revoked.
var ErrGrantExpired = errors.New("grant expired or revoked")

// ErrAmbiguousGrant is returned when a user holds more than one active grant on
// the same backend and the request cannot single one out (no requested database,
// or the database matches none/several). Failing closed here prevents the proxy
// from silently serving whichever grant happens to sort first — which could hand
// back a higher-privileged role or a different database scope than intended.
var ErrAmbiguousGrant = errors.New("ambiguous grant: multiple active grants match")

// resolveSecret is the hook the policy engine uses to dereference
// BackendAccount.PasswordRef. Swappable in tests to avoid touching the env /
// filesystem; defaults to the package-level secrets registry.
type resolveSecret func(ref string) (string, error)

// Engine resolves a proxy LookupRequest into an AuthResponse by combining user,
// backend, grant, and backend-account records.
type Engine struct {
	s       store.Store
	now     func() time.Time
	resolve resolveSecret
	logger  *slog.Logger
}

// New builds an Engine backed by s. The clock is pluggable for tests.
func New(s store.Store) *Engine {
	return &Engine{
		s:       s,
		now:     time.Now,
		resolve: secrets.Resolve,
		logger:  slog.Default(),
	}
}

// WithClock overrides the engine's clock — intended for tests.
func (e *Engine) WithClock(now func() time.Time) *Engine {
	e.now = now
	return e
}

// WithSecretsResolver overrides the secret resolver — intended for tests that
// don't want to plant values in the process environment.
func (e *Engine) WithSecretsResolver(r resolveSecret) *Engine {
	e.resolve = r
	return e
}

// WithLogger attaches a logger used for fail-closed resolution diagnostics.
func (e *Engine) WithLogger(l *slog.Logger) *Engine {
	if l != nil {
		e.logger = l
	}
	return e
}

// Resolve returns the auth response for a proxy lookup, or an error describing
// why the request is denied (not authorized, expired, or not configured).
func (e *Engine) Resolve(ctx context.Context, req auth.LookupRequest) (auth.AuthResponse, error) {
	if req.Username == "" || req.BackendServer == "" || req.ProxyType == "" {
		return auth.AuthResponse{}, fmt.Errorf("lookup request missing required fields")
	}

	user, err := e.s.GetUserByUsername(ctx, req.Username)
	if err != nil {
		return auth.AuthResponse{}, ErrNoActiveGrant
	}
	if user.Status != "active" {
		return auth.AuthResponse{}, ErrNoActiveGrant
	}

	backend, err := e.s.GetBackendByAddress(ctx, req.BackendServer)
	if err != nil {
		return auth.AuthResponse{}, ErrNoActiveGrant
	}
	if string(backend.Type) != req.ProxyType {
		return auth.AuthResponse{}, fmt.Errorf("proxy type %q does not match backend type %q", req.ProxyType, backend.Type)
	}

	grants, err := e.s.ListGrants(ctx, store.GrantFilter{
		UserID:    user.ID,
		BackendID: backend.ID,
		// Only ACTIVE grants serve creds — APPROVED means "claim window
		// open, no creds yet". Tri-phase lifecycle, see HLD §6.
		Statuses: []domain.GrantStatus{domain.GrantActive},
	})
	if err != nil {
		return auth.AuthResponse{}, err
	}

	now := e.now()
	// Collect every grant that is genuinely active right now (the store filters
	// by status; IsActive additionally enforces the expiry instant). Selection
	// among multiple candidates is deferred to selectGrant so the lookup can
	// never silently serve whichever grant the store returned first.
	var active []domain.Grant
	for _, g := range grants {
		if g.IsActive(now) {
			active = append(active, g)
		}
	}
	g, err := selectGrant(active, req.Database)
	if err != nil {
		switch {
		case errors.Is(err, ErrAmbiguousGrant):
			e.logger.Error("ambiguous_grant_lookup",
				"backend_id", backend.ID,
				"user_id", user.ID,
				"requested_database", req.Database,
				"active_grants", len(active),
			)
		case errors.Is(err, ErrNoActiveGrant):
			// The user and backend resolved, so reaching here means no grant is
			// currently servable (expired, revoked, or none) — report it as
			// expired, matching the long-standing contract for this path.
			err = ErrGrantExpired
		}
		return auth.AuthResponse{}, err
	}
	{
		// Ephemeral per-grant backend user takes precedence over the shared
		// BackendAccount when populated. Skips the account lookup entirely —
		// the ephemeral user was created with the grant's Role, so the
		// privilege model is preserved.
		if g.EphemeralUsername != "" {
			resp := auth.AuthResponse{
				Password:    g.PortalPassword,
				BackendUser: g.EphemeralUsername,
				BackendPass: g.EphemeralPassword,
				GrantID:     g.ID,
				Role:        string(g.Role),
			}
			if g.ExpiresAt != nil {
				resp.ExpiresAt = *g.ExpiresAt
			}
			if g.ConnectionTTLSec > 0 {
				resp.ConnectionTTLSeconds = g.ConnectionTTLSec
			}
			if g.Database != "" {
				resp.AllowedDBs = []string{g.Database}
			}
			return resp, nil
		}
		acct, err := e.s.GetBackendAccount(ctx, backend.ID, g.Role)
		if err != nil {
			// Fail-closed: this grant matched (active, right user/backend) but
			// its backing account is unresolvable. `continue`ing would fall
			// through to a DIFFERENT grant's credentials — never substitute
			// another grant's creds for the one that actually matched. Deny.
			e.logger.Error("backend_account_lookup_failed",
				"backend_id", backend.ID,
				"role", string(g.Role),
				"grant_id", g.ID,
				"err", err.Error(),
			)
			return auth.AuthResponse{}, ErrGrantExpired
		}
		// PasswordRef (external secret) takes precedence; fall back to
		// the row-stored Password (decrypted by the Encrypting store) when no
		// ref is configured.
		backendPass := acct.Password
		if acct.PasswordRef != "" {
			// Fail-closed: a broken secret reference must not fall back to the
			// row-stored Password or leak the ref in the user-facing error.
			// Log the scheme only (the full ref can carry env-var names or
			// file paths operators might class as sensitive).
			resolved, rerr := e.resolve(acct.PasswordRef)
			if rerr != nil {
				scheme := acct.PasswordRef
				if i := strings.Index(scheme, "://"); i > 0 {
					scheme = scheme[:i]
				}
				e.logger.Error("backend_password_resolve_failed",
					"backend_id", backend.ID,
					"role", string(g.Role),
					"grant_id", g.ID,
					"ref_scheme", scheme,
					"err", rerr.Error(),
				)
				return auth.AuthResponse{}, ErrGrantExpired
			}
			backendPass = resolved
		}
		resp := auth.AuthResponse{
			Password:    g.PortalPassword,
			BackendUser: acct.Username,
			BackendPass: backendPass,
			GrantID:     g.ID,
			Role:        string(g.Role),
		}
		if g.ExpiresAt != nil {
			resp.ExpiresAt = *g.ExpiresAt
		}
		if g.ConnectionTTLSec > 0 {
			resp.ConnectionTTLSeconds = g.ConnectionTTLSec
		}
		if g.Database != "" {
			resp.AllowedDBs = []string{g.Database}
		}
		return resp, nil
	}
}

// selectGrant picks the single grant a lookup resolves to among the active
// candidates for one (user, backend) pair.
//
//   - 0 candidates  -> ErrNoActiveGrant.
//   - 1 candidate   -> that grant (the overwhelmingly common case, unchanged).
//   - >1 candidates -> disambiguate by the requested database. We never fall
//     back to "first/newest wins": with the lookup keyed only on (user,
//     backend), serving an arbitrary grant could silently hand back a
//     higher-privileged role or a different database than the client asked
//     for. So we require the requested database to single one out, and fail
//     closed (ErrAmbiguousGrant) if it is empty, matches none, or matches more
//     than one. The fix for the underlying overlap is operator-side: don't keep
//     two active grants that collide on the same database.
//
// A grant matches a requested database when its scoped Database equals it, or
// when it is unscoped (empty Database = "any database on this backend").
func selectGrant(active []domain.Grant, database string) (domain.Grant, error) {
	switch len(active) {
	case 0:
		return domain.Grant{}, ErrNoActiveGrant
	case 1:
		return active[0], nil
	}
	if database == "" {
		return domain.Grant{}, ErrAmbiguousGrant
	}
	var match domain.Grant
	found := 0
	for _, g := range active {
		if g.Database == "" || g.Database == database {
			match = g
			found++
		}
	}
	if found != 1 {
		return domain.Grant{}, ErrAmbiguousGrant
	}
	return match, nil
}
