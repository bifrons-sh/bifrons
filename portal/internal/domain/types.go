package domain

import (
	"crypto/rand"
	"database/sql/driver"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"
)

// GrantStatus tracks the lifecycle of a grant.
type GrantStatus string

const (
	GrantPending          GrantStatus = "PENDING"
	GrantValidatorApproved  GrantStatus = "VALIDATOR_APPROVED"
	GrantApproved         GrantStatus = "APPROVED"
	GrantActive           GrantStatus = "ACTIVE"
	GrantDenied           GrantStatus = "DENIED"
	GrantExpired          GrantStatus = "EXPIRED"
	GrantRevoked          GrantStatus = "REVOKED"
)

// Role identifies the backend account profile a grant binds to.
type Role string

const (
	RoleRO  Role = "ro"
	RoleApp Role = "app"
	RoleDBA Role = "dba"
)

// AccessMode controls credential lifecycle for a granted trio. Resolved by
// the request policy at create time and persisted on the Grant so /claim
// doesn't need to re-consult the policy.
type AccessMode string

const (
	ModePermanent AccessMode = "permanent"
	ModeEphemeral AccessMode = "ephemeral"
)

// Value implements driver.Valuer so every SQL driver (including ones stricter
// than pgx/modernc-sqlite about named string types) gets an explicit string.
// Empty AccessMode is stored as "" to match the schema's NOT NULL DEFAULT ''
// (policy_mode column) — returning nil would violate the constraint.
func (m AccessMode) Value() (driver.Value, error) {
	return string(m), nil
}

// Scan implements sql.Scanner for symmetry with Value — accepts string, []byte,
// or NULL. Any other kind is a driver bug and surfaces a typed error.
func (m *AccessMode) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		*m = ""
	case string:
		*m = AccessMode(v)
	case []byte:
		*m = AccessMode(string(v))
	default:
		return fmt.Errorf("domain.AccessMode: unsupported scan type %T", src)
	}
	return nil
}

// ProxyType names the protocol proxy making the lookup.
type ProxyType string

const (
	ProxyMySQL    ProxyType = "mysql"
	ProxyPostgres ProxyType = "postgres"
	ProxyMongo    ProxyType = "mongo"
)

// User is a human or automation identity.
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"` // bcrypt/argon2id — never serialized
	DisplayName  string    `json:"display_name,omitempty"`
	Email        string    `json:"email,omitempty"`
	// ExternalID binds this portal user to an IdP subject (OIDC `sub` claim).
	// Populated on first OIDC login and used thereafter to skip a lookup by
	// username — the sub is the only stable identifier across IdP rename/email
	// changes. Empty for users created out-of-band via the admin API.
	ExternalID string `json:"external_id,omitempty"`
	// ValidatorUserID is the portal id of this user's validator, populated by the
	// org-hierarchy sync script (see cmd/entra-sync). Empty for top-of-hier
	// users and out-of-band admins. The grant-creation path reads this to
	// stamp Grant.ValidatorSubject for the dual-gate approval; no live call to
	// any IdP happens on the hot path.
	ValidatorUserID string    `json:"validator_user_id,omitempty"`
	IsAdmin       bool      `json:"is_admin"`
	Status        string    `json:"status"` // active|disabled
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Group is an org-hierarchy grouping (DBA team, dev squad, on-call rotation, …)
// populated by the sync script. The slug is the stable identifier the trio
// policy YAML references; external_id carries the upstream IdP id so the
// syncer can reconcile without dropping the local row on every run.
type Group struct {
	ID          string    `json:"id"`
	Slug        string    `json:"slug"` // stable human-readable id
	DisplayName string    `json:"display_name,omitempty"`
	ExternalID  string    `json:"external_id,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// GroupMember joins a user to a group. Empty struct-level fields are fine —
// the primary key is (GroupID, UserID), JoinedAt is advisory history.
type GroupMember struct {
	GroupID  string    `json:"group_id"`
	UserID   string    `json:"user_id"`
	JoinedAt time.Time `json:"joined_at"`
}

// Backend is a target database server.
type Backend struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      ProxyType `json:"type"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	Databases []string  `json:"databases,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Address returns host:port suitable for matching against proxy LookupRequest.BackendServer.
func (b Backend) Address() string { return fmt.Sprintf("%s:%d", b.Host, b.Port) }

// BackendAccount is a shared backend credential (per role) the proxy re-authenticates with.
//
// Two credential storage modes, mutually exclusive per row:
//   - PasswordRef (e.g. "env://DB_APP_RW_PW", "file:///etc/portal/app.pw")
//     resolves the secret on demand at /auth time; the portal never stores
//     the plaintext. Preferred when secrets are managed externally (Vault,
//     env-injected from a secret store, etc.).
//   - Password is the secret stored on the row itself, encrypted at rest via
//     the store.Encrypting decorator (SecretBox, see portal/internal/secrets).
//     Used when the portal is the source of truth for the credential.
//
// The policy engine prefers PasswordRef when both are set.
type BackendAccount struct {
	ID          string    `json:"id"`
	BackendID   string    `json:"backend_id"`
	Role        Role      `json:"role"`
	Username    string    `json:"username"`
	PasswordRef string    `json:"password_ref,omitempty"` // scheme://key ref resolved by portal/internal/secrets
	// Password holds a secret stored directly on the row. Encrypted at rest
	// by the Encrypting store decorator; never serialised over the wire.
	Password  string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// LogValue implements slog.LogValuer so accidental structured-logging of a
// BackendAccount can never leak Password or PasswordRef — both fields are
// redacted regardless of log format.
func (a BackendAccount) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", a.ID),
		slog.String("backend_id", a.BackendID),
		slog.String("role", string(a.Role)),
		slog.String("username", a.Username),
		slog.String("password_ref", redactIfSet(a.PasswordRef)),
		slog.String("password", redactIfSet(a.Password)),
	)
}

// redactIfSet returns "<redacted>" when s is non-empty, "" otherwise — so
// operators can still distinguish "field unset" from "field present but
// hidden" in logs without ever seeing the value.
func redactIfSet(s string) string {
	if s == "" {
		return ""
	}
	return "<redacted>"
}

// Grant is a time-bound authorization for a user to access a specific backend via a role.
type Grant struct {
	ID               string      `json:"id"`
	UserID           string      `json:"user_id"`
	BackendID        string      `json:"backend_id"`
	Database         string      `json:"database"`
	Role             Role        `json:"role"`
	Status           GrantStatus `json:"status"`
	Reason           string      `json:"reason,omitempty"`
	PortalPassword   string      `json:"-"` // what the user presents to the proxy; rotated per grant
	RequestedBy      string      `json:"requested_by,omitempty"`
	ApprovedBy       string      `json:"approved_by,omitempty"`
	DeniedBy         string      `json:"denied_by,omitempty"`
	// ApproverHint records the email/UPN of the approver the portal notified
	// (typically the requester's validator). Advisory only — the actual
	// approve call is still gated on admin privileges.
	ApproverHint     string      `json:"approver_hint,omitempty"`
	// ValidatorSubject is the Entra `id` (object id / sub) of the requester's
	// validator, captured at create time. The dual-gate approval flow matches
	// session.Subject against this to decide whether the caller is acting as
	// the validator half of the four-eyes sign-off.
	ValidatorSubject     string     `json:"validator_subject,omitempty"`
	ValidatorApprovedBy  string     `json:"validator_approved_by,omitempty"`
	ValidatorApprovedAt  *time.Time `json:"validator_approved_at,omitempty"`
	RequestedAt      time.Time   `json:"requested_at"`
	ApprovedAt       *time.Time  `json:"approved_at,omitempty"`
	DeniedAt         *time.Time  `json:"denied_at,omitempty"`
	// RequestExpiresAt is the phase-1 (validation) deadline: when the
	// PENDING / VALIDATOR_APPROVED request lapses if not fully approved.
	RequestExpiresAt *time.Time `json:"request_expires_at,omitempty"`
	// ClaimExpiresAt is the phase-2 (claim) deadline: when an APPROVED grant
	// stops being claimable via /claim.
	ClaimExpiresAt   *time.Time `json:"claim_expires_at,omitempty"`
	// ExpiresAt is the phase-3 (credential TTL) deadline: set at /claim time;
	// the ACTIVE grant lapses once this passes.
	ExpiresAt        *time.Time  `json:"expires_at,omitempty"`
	RevokedAt        *time.Time  `json:"revoked_at,omitempty"`
	ConnectionTTLSec int         `json:"connection_ttl_seconds,omitempty"`
	// PolicyMode records the access mode resolved by the trio policy at
	// create time: "permanent" (shared BackendAccount) or "ephemeral"
	// (per-grant DB user provisioned at /claim). Empty when the request
	// came from an admin / static-bearer path that bypassed the policy —
	// callers default to permanent in that case.
	PolicyMode        AccessMode `json:"policy_mode,omitempty"`
	// EphemeralUsername is the per-grant backend account provisioned by the
	// ephemeral provisioner when enabled. Empty string means "not provisioned"
	// — the engine falls back to the shared BackendAccount for the role.
	EphemeralUsername string `json:"ephemeral_username,omitempty"`
	// EphemeralPassword is the ephemeral account's secret. Never serialized
	// and redacted via LogValue — defence in depth against accidental log /
	// response leaks.
	EphemeralPassword string    `json:"-"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// LogValue implements slog.LogValuer so the ephemeral and portal passwords
// never land in structured log output, regardless of format. Mirrors the
// redaction contract already applied to BackendAccount.
func (g Grant) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", g.ID),
		slog.String("user_id", g.UserID),
		slog.String("backend_id", g.BackendID),
		slog.String("database", g.Database),
		slog.String("role", string(g.Role)),
		slog.String("status", string(g.Status)),
		slog.String("reason", g.Reason),
		slog.String("portal_password", redactIfSet(g.PortalPassword)),
		slog.String("requested_by", g.RequestedBy),
		slog.String("approved_by", g.ApprovedBy),
		slog.String("denied_by", g.DeniedBy),
		slog.String("ephemeral_username", g.EphemeralUsername),
		slog.String("ephemeral_password", redactIfSet(g.EphemeralPassword)),
	)
}

// IsActive reports whether the grant is usable right now. With the tri-phase
// lifecycle, only ACTIVE grants (claimed + within credential TTL) hand out
// auth — APPROVED grants are claimable but not yet usable.
func (g Grant) IsActive(at time.Time) bool {
	if g.Status != GrantActive {
		return false
	}
	if g.ExpiresAt != nil && at.After(*g.ExpiresAt) {
		return false
	}
	return g.RevokedAt == nil
}

// IsEphemeral reports whether the grant carries the ephemeral access mode —
// i.e. /claim must provision a per-grant DB user through the ephemeral.Manager
// instead of returning the shared BackendAccount creds.
func (g Grant) IsEphemeral() bool {
	return g.PolicyMode == ModeEphemeral
}

// IsPastValidationWindow reports whether the phase-1 deadline has lapsed. A
// PENDING or VALIDATOR_APPROVED grant past this point must be EXPIRED by the
// sweeper. Zero RequestExpiresAt means "feature disabled" — never expired.
func (g Grant) IsPastValidationWindow(at time.Time) bool {
	return g.RequestExpiresAt != nil && at.After(*g.RequestExpiresAt)
}

// IsPastClaimWindow reports whether the phase-2 deadline has lapsed. An
// APPROVED grant past this point can no longer be claimed — /claim returns
// 410 Gone and the sweeper transitions the row to EXPIRED.
func (g Grant) IsPastClaimWindow(at time.Time) bool {
	return g.ClaimExpiresAt != nil && at.After(*g.ClaimExpiresAt)
}

// IsPastCredentialTTL reports whether the phase-3 deadline has lapsed — ACTIVE
// grants past this point are functionally expired even before the sweeper sees
// them. Matches IsActive's expiry branch so the two agree.
func (g Grant) IsPastCredentialTTL(at time.Time) bool {
	return g.ExpiresAt != nil && at.After(*g.ExpiresAt)
}

// AuditEntry mirrors the proxy's audit payload per HLD §5.1.
type AuditEntry struct {
	Timestamp     time.Time `json:"timestamp"`
	GrantID       string    `json:"grant_id"`
	Username      string    `json:"username"`
	ProxyType     ProxyType `json:"proxy_type"`
	BackendServer string    `json:"backend_server"`
	Database      string    `json:"database,omitempty"`
	Query         string    `json:"query"`
	Truncated     bool      `json:"truncated"`
	SourceIP      string    `json:"source_ip,omitempty"`
	DurationMs    int64     `json:"duration_ms,omitempty"`
	TraceID       string    `json:"trace_id,omitempty"`
}

// NewID returns a prefixed hex identifier (e.g. "g-<16hex>"). Panics if the
// system entropy source fails — silently returning a zero-suffix ID would
// collapse every subsequent call to the same value and hot-collide uniqueness
// constraints in the store. An entropy failure is the kind of boot-time
// environment bug that should abort fast, not fail quietly.
//
// Not a ULID — kept simple for the scaffold; replace with ULID/UUIDv7 for prod.
func NewID(prefix string) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("crypto/rand failed generating ID: %v", err))
	}
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b[:]))
}

// NewSecret returns a cryptographically random hex string suitable as a
// user-facing password or token. 32 bytes → 64 hex chars → 256 bits of
// entropy, matching the session-id bar elsewhere in the portal. Panics on
// entropy failure for the same reason NewID does.
func NewSecret() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("crypto/rand failed generating secret: %v", err))
	}
	return hex.EncodeToString(b[:])
}
