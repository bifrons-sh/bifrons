package store

import (
	"context"
	"errors"

	"github.com/babs/poc-proxies/portal/internal/domain"
)

// ErrNotFound is returned when a lookup has no match.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned when a write violates uniqueness (e.g. duplicate username).
var ErrConflict = errors.New("conflict")

// Store is the portal's persistence abstraction. In-memory + SQL impls satisfy it.
type Store interface {
	// Users
	CreateUser(ctx context.Context, u domain.User) error
	GetUserByUsername(ctx context.Context, username string) (domain.User, error)
	GetUser(ctx context.Context, id string) (domain.User, error)

	// Backends
	CreateBackend(ctx context.Context, b domain.Backend) error
	GetBackendByAddress(ctx context.Context, addr string) (domain.Backend, error)
	ListBackends(ctx context.Context) ([]domain.Backend, error)

	// Backend accounts
	UpsertBackendAccount(ctx context.Context, a domain.BackendAccount) error
	GetBackendAccount(ctx context.Context, backendID string, role domain.Role) (domain.BackendAccount, error)

	// Grants
	CreateGrant(ctx context.Context, g domain.Grant) error
	GetGrant(ctx context.Context, id string) (domain.Grant, error)
	UpdateGrant(ctx context.Context, g domain.Grant) error
	ListGrants(ctx context.Context, filter GrantFilter) ([]domain.Grant, error)

	// Audit
	AppendAudit(ctx context.Context, entries []domain.AuditEntry) error
	ListAudit(ctx context.Context, filter AuditFilter) ([]domain.AuditEntry, error)
}

// GrantFilter narrows ListGrants results.
type GrantFilter struct {
	UserID    string
	BackendID string
	Statuses  []domain.GrantStatus
	Limit     int
}

// AuditFilter narrows ListAudit results.
type AuditFilter struct {
	GrantID  string
	Username string
	Limit    int
}
