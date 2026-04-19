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
	for _, g := range grants {
		if !g.IsActive(now) {
			continue
		}
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
			continue
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
	return auth.AuthResponse{}, ErrGrantExpired
}
