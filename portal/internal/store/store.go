package store

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
)

// ErrNotFound is returned when a lookup has no match.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned when a write violates uniqueness (e.g. duplicate username).
var ErrConflict = errors.New("conflict")

// Store is the portal's persistence abstraction. In-memory + SQL impls satisfy it.
// Close is mandatory: memory returns nil; SQL impls release pooled connections.
// Embedding io.Closer ensures any decorator/wrapper keeps the handle visible —
// a type-assertion pattern would silently skip wrappers and leak pools.
type Store interface {
	io.Closer

	// Users
	CreateUser(ctx context.Context, u domain.User) error
	GetUserByUsername(ctx context.Context, username string) (domain.User, error)
	GetUser(ctx context.Context, id string) (domain.User, error)
	// GetUserByExternalID resolves a portal user by its IdP subject claim
	// (OIDC `sub`). Returns ErrNotFound when no user has been provisioned
	// for the given subject yet — callers (e.g. the OIDC callback) use the
	// error to trigger first-login provisioning.
	GetUserByExternalID(ctx context.Context, externalID string) (domain.User, error)

	// Backends
	CreateBackend(ctx context.Context, b domain.Backend) error
	GetBackendByAddress(ctx context.Context, addr string) (domain.Backend, error)
	// GetBackend resolves a backend by its internal id. Used by grant-bound
	// lookups (approve / claim / revoke) where the grant already carries the
	// BackendID — avoids a ListBackends + linear scan.
	GetBackend(ctx context.Context, id string) (domain.Backend, error)
	// GetBackendByName resolves a backend by its alias / display name. Used by
	// the trio policy where operators reference instances by friendly name
	// rather than internal id.
	GetBackendByName(ctx context.Context, name string) (domain.Backend, error)
	ListBackends(ctx context.Context) ([]domain.Backend, error)

	// Backend accounts
	UpsertBackendAccount(ctx context.Context, a domain.BackendAccount) error
	GetBackendAccount(ctx context.Context, backendID string, role domain.Role) (domain.BackendAccount, error)

	// Grants
	CreateGrant(ctx context.Context, g domain.Grant) error
	GetGrant(ctx context.Context, id string) (domain.Grant, error)
	UpdateGrant(ctx context.Context, g domain.Grant) error
	// UpdateGrantIfStatus is a compare-and-swap: persists g only if the row's
	// current status still matches expect. Returns ErrConflict if some other
	// actor beat us to the transition (two admins double-click "approve",
	// approve vs. deny race, etc.). Callers must set g.Status to the new
	// value before calling.
	UpdateGrantIfStatus(ctx context.Context, g domain.Grant, expect domain.GrantStatus) error
	// SetGrantEphemeral persists the provisioned ephemeral backend credential
	// alongside the grant row. Called after a successful
	// ephemeral.Provisioner.Provision so the policy engine can return these
	// instead of the shared BackendAccount credentials. Passing empty strings
	// clears the fields (used by the orphan-sweep after a successful drop).
	SetGrantEphemeral(ctx context.Context, id, username, password string) error
	ListGrants(ctx context.Context, filter GrantFilter) ([]domain.Grant, error)

	// Audit
	AppendAudit(ctx context.Context, entries []domain.AuditEntry) error
	ListAudit(ctx context.Context, filter AuditFilter) ([]domain.AuditEntry, error)

	// PruneAudit enforces the retention window and hard cap for audit
	// entries. Entries strictly older than cutoff are deleted; after that,
	// if the remaining row count still exceeds maxEntries (>0), the oldest
	// rows beyond the cap are deleted too. Returns the number of rows
	// actually pruned and the row count remaining after the sweep.
	PruneAudit(ctx context.Context, cutoff time.Time, maxEntries int) (pruned, total int, err error)

	// ExpireStaleGrants transitions ACTIVE grants whose ExpiresAt is
	// before `now` to EXPIRED. Returns the count of grants flipped. This
	// reconciles stored status with time-based liveness so admin queries
	// don't see "ACTIVE" rows that are actually dead at auth time.
	ExpireStaleGrants(ctx context.Context, now time.Time) (int, error)

	// ExpireUnclaimedGrants handles the two pre-credential expiry passes:
	//   * PENDING | MANAGER_APPROVED past RequestExpiresAt → EXPIRED
	//     (validation window lapsed; no creds were ever issued)
	//   * APPROVED past ClaimExpiresAt → EXPIRED
	//     (claim window lapsed; the requester never picked up the grant)
	// Returns the total count of rows transitioned across both passes.
	ExpireUnclaimedGrants(ctx context.Context, now time.Time) (int, error)

	// --- OIDC sessions ---
	CreateSession(ctx context.Context, s SessionRecord) error
	GetSession(ctx context.Context, id string) (SessionRecord, error)
	DeleteSession(ctx context.Context, id string) error
	PruneExpiredSessions(ctx context.Context, now time.Time) (int, error)

	// ListEphemeralOrphans returns grants in a terminal state
	// (DENIED|REVOKED|EXPIRED) that still carry a non-empty
	// EphemeralUsername — typically because the portal crashed between
	// status flip and provisioner.Revoke(). Used by the sweeper for
	// defence-in-depth cleanup.
	ListEphemeralOrphans(ctx context.Context) ([]domain.Grant, error)
}

// SessionRecord is the persisted shape of an OIDC session.
type SessionRecord struct {
	ID        string
	Subject   string
	Email     string
	Name      string
	IsAdmin   bool
	ExpiresAt time.Time
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
