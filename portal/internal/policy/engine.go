package policy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/babs/poc-proxies/internal/auth"
	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// ErrNoActiveGrant is returned when the user has no applicable grant for the lookup.
var ErrNoActiveGrant = errors.New("no active grant")

// ErrGrantExpired is returned when the matching grant is past its expiry or revoked.
var ErrGrantExpired = errors.New("grant expired or revoked")

// Engine resolves a proxy LookupRequest into an AuthResponse by combining user,
// backend, grant, and backend-account records.
type Engine struct {
	s   store.Store
	now func() time.Time
}

// New builds an Engine backed by s. The clock is pluggable for tests.
func New(s store.Store) *Engine {
	return &Engine{s: s, now: time.Now}
}

// WithClock overrides the engine's clock — intended for tests.
func (e *Engine) WithClock(now func() time.Time) *Engine {
	e.now = now
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
		Statuses:  []domain.GrantStatus{domain.GrantApproved},
	})
	if err != nil {
		return auth.AuthResponse{}, err
	}

	now := e.now()
	for _, g := range grants {
		if !g.IsActive(now) {
			continue
		}
		acct, err := e.s.GetBackendAccount(ctx, backend.ID, g.Role)
		if err != nil {
			continue
		}
		resp := auth.AuthResponse{
			Password:    g.PortalPassword,
			BackendUser: acct.Username,
			BackendPass: acct.Password,
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
