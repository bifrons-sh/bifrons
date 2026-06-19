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

// ErrLastAdmin is returned when an UpdateUserDemote would leave the system
// with zero active admins. The handler maps this to 409.
var ErrLastAdmin = errors.New("last admin")

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
	// SetUserValidator writes validatorUserID onto the user row; pass "" to clear.
	// Returns ErrNotFound if the user doesn't exist. The sync script calls
	// this after resolving the org hierarchy.
	SetUserValidator(ctx context.Context, userID, validatorUserID string) error
	// ListUsers returns every user, ordered by username. Used by the sync
	// script (to skip already-created users) and the operator SPA.
	ListUsers(ctx context.Context) ([]domain.User, error)
	// UpdateUser reconciles the mutable scalar attributes of an existing user
	// (display_name, email, external_id, is_operator, status). Does NOT change
	// username, password_hash, validator_user_id, created_at, or id — username
	// is the stable identity and validator mutations go through SetUserValidator.
	//
	// Compare-and-swap on u.UpdatedAt: the row is only written if the current
	// updated_at in the store still equals the value on u. Callers are expected
	// to build u via GetUser → mutate → UpdateUser, never to synthesise it with
	// a zero time. Concurrent patches race cleanly: first wins, the second
	// returns ErrConflict so the handler can respond 409 instead of silently
	// clobbering the losing writer's fields.
	//
	// Returns ErrNotFound when the row doesn't exist OR the CAS failed because
	// the row's updated_at drifted; ErrConflict when external_id collides with
	// another row.
	//
	// Status is written unconditionally — callers MUST set u.Status to a valid
	// schema value ('active' or 'disabled'); passing the zero string overwrites
	// the row to '' and breaks every code path that filters on status.
	UpdateUser(ctx context.Context, u domain.User) error
	// CountAdmins returns the number of active users with is_operator = true.
	// Used by the admin API to block the "demote the last admin" foot-gun on
	// PATCH /users/{id}.
	CountAdmins(ctx context.Context) (int, error)
	// UpdateUserDemote applies the same CAS update as UpdateUser but atomically
	// enforces that the operation does not strand the system without an admin:
	// when u.IsOperator is false and the row's current is_operator is true, the
	// active-admin count must be > 1 or the call returns ErrLastAdmin. The
	// count check and the update happen under a single transaction (or, for
	// the memory store, under the same exclusive lock) so two concurrent
	// demotes of different admins cannot both pass a non-transactional guard.
	UpdateUserDemote(ctx context.Context, u domain.User) error

	// Groups + membership. Populated by the sync script; read by the policy
	// engine and the notifier's admin-recipient lookup.
	UpsertGroup(ctx context.Context, g domain.Group) error
	GetGroup(ctx context.Context, id string) (domain.Group, error)
	GetGroupBySlug(ctx context.Context, slug string) (domain.Group, error)
	ListGroups(ctx context.Context) ([]domain.Group, error)
	DeleteGroup(ctx context.Context, id string) error
	// AddGroupMember is idempotent — calling twice for the same (group, user)
	// is a no-op, not an error, so the syncer doesn't have to diff membership.
	AddGroupMember(ctx context.Context, groupID, userID string) error
	RemoveGroupMember(ctx context.Context, groupID, userID string) error
	ListGroupMembers(ctx context.Context, groupID string) ([]domain.User, error)
	ListUserGroups(ctx context.Context, userID string) ([]domain.Group, error)

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
	//   * PENDING | VALIDATOR_APPROVED past RequestExpiresAt → EXPIRED
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

	// --- Provisioning outbox (provision_intents) ---
	//
	// The portal (producer) writes intents; a separate worker (consumer)
	// claims, executes, and reports back. This Store layer is persistence
	// only — it stores exactly what it's given and never computes
	// credentials. See specs/phase-8-provisioning-worker.md §8.4.

	// InsertIntent durably emits an outbox row. Idempotent: the intent id is
	// deterministic from (grant_id, kind) (domain.IntentID), so a producer
	// retry re-inserting the same row is a no-op SUCCESS — NOT ErrConflict.
	// Backed by INSERT ... ON CONFLICT(id) DO NOTHING.
	InsertIntent(ctx context.Context, in domain.Intent) error

	// ClaimPendingIntents atomically leases up to limit eligible rows to
	// workerID. Eligible = status='pending' OR (status='in_flight' AND
	// lease_expires_at < now) [stale-lease reclaim]. When instanceWhitelist is
	// non-empty, only rows whose backend_id is in the set are claimed (empty ⇒
	// all backends). Claimed rows are ordered revoke-before-provision then by
	// created_at ASC so teardown drains ahead of new provisioning. On claim the
	// row flips to in_flight with worker_id, lease_expires_at=now+lease, and a
	// fresh updated_at. Returns the rows as they now are (decrypted results).
	ClaimPendingIntents(ctx context.Context, workerID string, instanceWhitelist []string, lease time.Duration, limit int) ([]domain.Intent, error)

	// HeartbeatIntentLease extends the lease on an owned, in-flight intent by
	// lease (from now). Returns ErrNotFound when the row is gone, not in_flight,
	// or owned by a different worker — the caller must stop working it.
	HeartbeatIntentLease(ctx context.Context, id, workerID string, lease time.Duration) error

	// CompleteIntent marks an owned, in-flight intent done and stores the
	// provisioned credential plus completed_at. Returns ErrNotFound when the
	// row is gone, not in_flight, or owned by a different worker.
	CompleteIntent(ctx context.Context, id, workerID, resultUsername, resultPassword string) error

	// FailIntent marks an owned, in-flight intent failed with the closed-enum
	// error_class, sanitised error_detail, and retry_count. Returns ErrNotFound
	// when the row is gone, not in_flight, or owned by a different worker.
	FailIntent(ctx context.Context, id, workerID, errorClass, errorDetail string, retryCount int) error

	// ResetIntentForRetry flips a 'failed' intent back to 'pending' so a worker
	// can re-claim it (spec §8.6 retry). Clears worker_id, lease_expires_at,
	// error_class, error_detail and zeroes retry_count. Because the deterministic
	// intent id makes InsertIntent ON CONFLICT DO NOTHING, this is the ONLY way a
	// failed row re-enters the claim queue — re-POSTing /claim can't re-insert it.
	// Only acts on a 'failed' row: a row in any other state (or absent) returns
	// ErrNotFound so a caller racing the worker doesn't yank an in-flight retry.
	ResetIntentForRetry(ctx context.Context, id string) error

	// GetIntent returns one intent by id, or ErrNotFound.
	GetIntent(ctx context.Context, id string) (domain.Intent, error)

	// GetLatestIntentForGrant returns the newest intent (by created_at) for a
	// (grant, kind) pair, or ErrNotFound when none exists.
	GetLatestIntentForGrant(ctx context.Context, grantID string, kind domain.IntentKind) (domain.Intent, error)

	// --- Worker liveness (provisioning_workers) ---
	//
	// One row per worker PROCESS, keyed by WorkerID. The worker beats here on a
	// timer so operators see it's alive even when idle, plus a per-instance
	// health map. Rows carry no secrets, so the Encrypting decorator passes
	// these through untouched. See specs/phase-8-provisioning-worker.md.

	// UpsertWorkerHeartbeat registers or refreshes a worker's liveness row.
	// First call inserts; subsequent calls update health/instances/version and
	// advance LastSeenAt. StartedAt is preserved from the original insert — a
	// later beat never overwrites it, so process uptime stays readable.
	UpsertWorkerHeartbeat(ctx context.Context, hb domain.WorkerHeartbeat) error

	// ListWorkerHeartbeats returns every worker row, ordered by worker_id.
	ListWorkerHeartbeats(ctx context.Context) ([]domain.WorkerHeartbeat, error)

	// PruneStaleWorkers deletes rows whose last_seen_at predates cutoff and
	// returns the number removed. Callers derive cutoff from the staleness
	// window (now - within), matching domain.WorkerHeartbeat.IsStale.
	PruneStaleWorkers(ctx context.Context, cutoff time.Time) (int, error)
}

// SessionRecord is the persisted shape of an OIDC session.
type SessionRecord struct {
	ID           string
	Subject      string
	Email        string
	Name         string
	IsOperator   bool
	PortalUserID string // domain.User.ID bound at first OIDC login; empty if no binding
	ExpiresAt    time.Time
}

// GrantFilter narrows ListGrants results.
//
// ValidatorUserID is a bridge field for the phase-7 §7.4 "scope=validator"
// query: when set, the store returns grants whose owner's validator chain
// (today's single users.validator_user_id column) points at this user.
// Mutually exclusive with UserID — when both are set, ValidatorUserID wins,
// because operator-style "show me everything I should approve" is a strictly
// narrower view than "show me everything for user X".
//
// TODO(phase-7-final): replace single-column lookup with the JOIN against the
// future grant_validators snapshot table per specs/phase-7-validation-ui.md
// §7.3. The bridge query path stays correct in the meantime because each
// user has at most one validator under today's schema.
type GrantFilter struct {
	UserID          string
	ValidatorUserID string
	BackendID       string
	Statuses        []domain.GrantStatus
	Limit           int
}

// AuditFilter narrows ListAudit results.
type AuditFilter struct {
	GrantID  string
	Username string
	Limit    int
}
