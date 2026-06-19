// Package ephemeral provisions (and revokes) per-grant backend database users
// so an approved grant binds to a dedicated credential at the DB level rather
// than sharing a pooled BackendAccount. Defence in depth: when a grant goes
// terminal (DENIED|REVOKED|EXPIRED) the portal drops the account so any
// connection string that leaked out of the proxy stops working at the backend
// too.
//
// The interface is protocol-agnostic — per-backend implementations live in
// postgres.go / mysql.go / mongo.go. All of them are fail-closed on boot when
// the flag is enabled but DBA credentials are missing, and idempotent on
// revoke so a double-fire doesn't surface as an error.
package ephemeral

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
)

// BackendType mirrors domain.ProxyType but is kept as a separate enum so
// provisioners can evolve their own naming without dragging the proxy type
// taxonomy along. Values intentionally match the proxy names today.
type BackendType string

const (
	BackendPostgres BackendType = "postgres"
	BackendMySQL    BackendType = "mysql"
	BackendMongo    BackendType = "mongo"
)

// ProvisionRequest captures what the provisioner needs to create a per-grant
// backend account. Host/Port point to the real backend (not the proxy). The
// Role maps to a pre-existing backend role that the new user inherits
// privileges from — the portal never defines ACLs itself.
//
// BackendID is the portal's internal backend identifier; the provisioner
// passes it back on ProvisionedAccount so Revoke can re-resolve the DBA
// credential via the same DBALookup without needing a separate map.
type ProvisionRequest struct {
	BackendType BackendType
	BackendID   string
	Host        string
	Port        int
	Database    string
	Role        domain.Role
	GrantID     string
	// TTL is the requested lifetime of the backend user. The provisioner is
	// free to translate it into whatever the backend understands (Postgres
	// VALID UNTIL, MySQL PASSWORD EXPIRE INTERVAL, etc.). A zero TTL means
	// "use the backend's default expiry policy" / no hard cap.
	TTL time.Duration

	// Username / Password are OPTIONAL explicit credentials. When BOTH are set
	// the provisioner uses them verbatim (instead of newUsername/newPassword)
	// AND runs idempotent DDL so a re-execution converges to the same state.
	// This is how the provisioner-worker passes its deterministic, HMAC-derived
	// credentials (spec §8.4): a lease-takeover re-runs the same intent, and the
	// idempotent "create-if-absent + always-set-password" shape repairs whatever
	// a crashed worker left behind rather than diverging (DB has password₁, the
	// outbox records password₂, every auth fails). When either field is empty the
	// provisioner keeps the legacy random-generation behaviour unchanged.
	Username string
	Password string
}

// explicitCreds reports whether the caller supplied both a username and a
// password — the signal to switch from random generation to the deterministic,
// idempotent provisioning path (spec §8.4).
func (r ProvisionRequest) explicitCreds() bool {
	return r.Username != "" && r.Password != ""
}

// resolveCreds returns the credentials to provision with: the caller's explicit
// pair when both are set, otherwise a freshly generated random pair (legacy
// behaviour). The second return value reports whether the explicit (idempotent)
// path is in effect so the provisioner can pick its DDL shape.
func (r ProvisionRequest) resolveCreds() (user, pass string, idempotent bool, err error) {
	if r.explicitCreds() {
		return r.Username, r.Password, true, nil
	}
	user, err = newUsername()
	if err != nil {
		return "", "", false, err
	}
	pass, err = newPassword()
	if err != nil {
		return "", "", false, err
	}
	return user, pass, false, nil
}

// ProvisionedAccount is what the provisioner hands back. The Username +
// Password must be persisted by the caller (via store.SetGrantEphemeral) so
// the policy engine can serve them instead of the shared BackendAccount.
//
// Host / Port / Database / BackendID are echoed back so Revoke can re-open an
// admin connection without consulting the store again (useful under the
// orphan-sweep path where the grant row is the only input).
type ProvisionedAccount struct {
	Username    string
	Password    string
	BackendID   string
	BackendType BackendType
	Host        string
	Port        int
	Database    string
	GrantID     string
	CreatedAt   time.Time
}

// Provisioner is the contract every backend-specific driver implements.
// Implementations MUST be idempotent on Revoke — a double-fire (handler +
// orphan sweep) must not return an error when the user is already gone.
type Provisioner interface {
	Provision(ctx context.Context, req ProvisionRequest) (ProvisionedAccount, error)
	Revoke(ctx context.Context, acct ProvisionedAccount) error
}

// DBACredential is the DBA connection the provisioner logs in with. Resolved
// from the BackendAccount with Role == RoleDBA at call time, so operators can
// rotate the credential without restarting the portal.
type DBACredential struct {
	Username string
	Password string
}

// ErrNoDBACredential is returned by the driver-agnostic resolver when a
// backend has no RoleDBA account configured. Callers fall back to the shared
// BackendAccount path and log a warning on /approve.
var ErrNoDBACredential = errors.New("ephemeral: no DBA credential configured for backend")

// usernameRNG is the entropy source for username / password generation.
// Swappable via SetUsernameRNG so deterministic tests can assert exact SQL
// shape without racing crypto/rand. nil means "use crypto/rand".
var usernameRNG io.Reader

// SetUsernameRNG overrides the entropy source used for generating ephemeral
// usernames and passwords. Intended for tests only — production always uses
// crypto/rand via the nil fallback.
//
// Not concurrency-safe by design: tests set it once, the rest of the process
// reads it through randRead under the same goroutine.
func SetUsernameRNG(r io.Reader) { usernameRNG = r }

func randRead(p []byte) error {
	r := usernameRNG
	if r == nil {
		r = rand.Reader
	}
	_, err := io.ReadFull(r, p)
	return err
}

// newUsername returns a portal-scoped identifier like "portal_grant_<16hex>".
// The `portal_grant_` prefix makes it trivially greppable in backend audit
// logs and lets DBA cleanup scripts bulk-sweep stragglers if the portal is
// wiped mid-grant.
//
// 64 bits of entropy is well over the collision horizon for the grant table
// (even at 1M grants we're at ~2^-32 collision probability — fine for a
// transient row keyed by the portal's own GrantID).
func newUsername() (string, error) {
	var b [8]byte
	if err := randRead(b[:]); err != nil {
		return "", fmt.Errorf("ephemeral: generate username: %w", err)
	}
	return "portal_grant_" + hex.EncodeToString(b[:]), nil
}

// newPassword returns 32 bytes of random data hex-encoded (64 chars). Length
// chosen so no backend rejects it for being "too short" under any reasonable
// policy; hex encoding avoids escaping issues inside SQL string literals for
// the Postgres / MySQL paths.
func newPassword() (string, error) {
	var b [32]byte
	if err := randRead(b[:]); err != nil {
		return "", fmt.Errorf("ephemeral: generate password: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
