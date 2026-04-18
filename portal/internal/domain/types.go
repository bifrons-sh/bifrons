package domain

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"
)

// GrantStatus tracks the lifecycle of a grant.
type GrantStatus string

const (
	GrantPending  GrantStatus = "PENDING"
	GrantApproved GrantStatus = "APPROVED"
	GrantDenied   GrantStatus = "DENIED"
	GrantExpired  GrantStatus = "EXPIRED"
	GrantRevoked  GrantStatus = "REVOKED"
)

// Role identifies the backend account profile a grant binds to.
type Role string

const (
	RoleApp Role = "app"
	RoleDBA Role = "dba"
)

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
	IsAdmin      bool      `json:"is_admin"`
	Status       string    `json:"status"` // active|disabled
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
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
// Prefer PasswordRef (e.g. "env://DB_APP_RW_PW", "file:///etc/portal/app.pw") so
// the secret is resolved on demand at /auth time instead of living in the
// portal store row. The legacy Password field stays for backwards-compat only.
type BackendAccount struct {
	ID          string    `json:"id"`
	BackendID   string    `json:"backend_id"`
	Role        Role      `json:"role"`
	Username    string    `json:"username"`
	PasswordRef string    `json:"password_ref,omitempty"` // scheme://key ref resolved by portal/internal/secrets
	// Deprecated: use PasswordRef instead. Kept for backwards-compat with stores
	// populated before the secrets package existed; never echoed back on GET.
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
	RequestedAt      time.Time   `json:"requested_at"`
	ApprovedAt       *time.Time  `json:"approved_at,omitempty"`
	DeniedAt         *time.Time  `json:"denied_at,omitempty"`
	ExpiresAt        *time.Time  `json:"expires_at,omitempty"`
	RevokedAt        *time.Time  `json:"revoked_at,omitempty"`
	ConnectionTTLSec int         `json:"connection_ttl_seconds,omitempty"`
	CreatedAt        time.Time   `json:"created_at"`
	UpdatedAt        time.Time   `json:"updated_at"`
}

// IsActive reports whether the grant is usable right now.
func (g Grant) IsActive(at time.Time) bool {
	if g.Status != GrantApproved {
		return false
	}
	if g.ExpiresAt != nil && at.After(*g.ExpiresAt) {
		return false
	}
	return g.RevokedAt == nil
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
