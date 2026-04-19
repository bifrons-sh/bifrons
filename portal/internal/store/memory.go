package store

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
)

// Memory is a goroutine-safe in-memory Store. Data is lost on restart.
// Intended for POC / tests; swap for a persistent Store in real deployments.
type Memory struct {
	mu              sync.RWMutex
	users           map[string]domain.User
	usernameIndex   map[string]string // username -> user id
	externalIDIndex map[string]string // oidc sub -> user id
	backends        map[string]domain.Backend
	backendByAddr   map[string]string // host:port -> backend id
	backendAccounts map[string]domain.BackendAccount
	accountKey      map[string]string // backendID|role -> account id
	grants          map[string]domain.Grant
	audit           []domain.AuditEntry
	sessions        map[string]SessionRecord
}

// Close is a no-op for the in-memory store; satisfies the Store interface's
// io.Closer embed so callers can always `defer store.Close()`.
func (m *Memory) Close() error { return nil }

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		users:           make(map[string]domain.User),
		usernameIndex:   make(map[string]string),
		externalIDIndex: make(map[string]string),
		backends:        make(map[string]domain.Backend),
		backendByAddr:   make(map[string]string),
		backendAccounts: make(map[string]domain.BackendAccount),
		accountKey:      make(map[string]string),
		grants:          make(map[string]domain.Grant),
		sessions:        make(map[string]SessionRecord),
	}
}

// --- users ---

func (m *Memory) CreateUser(_ context.Context, u domain.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.usernameIndex[u.Username]; exists {
		return ErrConflict
	}
	if u.ExternalID != "" {
		if _, exists := m.externalIDIndex[u.ExternalID]; exists {
			return ErrConflict
		}
	}
	m.users[u.ID] = u
	m.usernameIndex[u.Username] = u.ID
	if u.ExternalID != "" {
		m.externalIDIndex[u.ExternalID] = u.ID
	}
	return nil
}

// GetUserByExternalID resolves a user by IdP subject. Returns ErrNotFound if
// no portal user has been provisioned for that subject yet.
func (m *Memory) GetUserByExternalID(_ context.Context, externalID string) (domain.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.externalIDIndex[externalID]
	if !ok {
		return domain.User{}, ErrNotFound
	}
	return m.users[id], nil
}

func (m *Memory) GetUser(_ context.Context, id string) (domain.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[id]
	if !ok {
		return domain.User{}, ErrNotFound
	}
	return u, nil
}

func (m *Memory) GetUserByUsername(_ context.Context, username string) (domain.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.usernameIndex[username]
	if !ok {
		return domain.User{}, ErrNotFound
	}
	return m.users[id], nil
}

// --- backends ---

func (m *Memory) CreateBackend(_ context.Context, b domain.Backend) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.backendByAddr[b.Address()]; exists {
		return ErrConflict
	}
	m.backends[b.ID] = b
	m.backendByAddr[b.Address()] = b.ID
	return nil
}

func (m *Memory) GetBackendByAddress(_ context.Context, addr string) (domain.Backend, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.backendByAddr[addr]
	if !ok {
		return domain.Backend{}, ErrNotFound
	}
	return m.backends[id], nil
}

// GetBackendByName scans for a backend whose Name matches. O(n) — backend
// counts in the POC are small and creation is rare; if this ever shows on
// a profile, add a name index alongside backendByAddr.
func (m *Memory) GetBackendByName(_ context.Context, name string) (domain.Backend, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, b := range m.backends {
		if b.Name == name {
			return b, nil
		}
	}
	return domain.Backend{}, ErrNotFound
}

func (m *Memory) ListBackends(_ context.Context) ([]domain.Backend, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.Backend, 0, len(m.backends))
	for _, b := range m.backends {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// --- backend accounts ---

func (m *Memory) UpsertBackendAccount(_ context.Context, a domain.BackendAccount) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := accountKey(a.BackendID, a.Role)
	if existingID, ok := m.accountKey[k]; ok {
		a.ID = existingID
	}
	m.backendAccounts[a.ID] = a
	m.accountKey[k] = a.ID
	return nil
}

func (m *Memory) GetBackendAccount(_ context.Context, backendID string, role domain.Role) (domain.BackendAccount, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.accountKey[accountKey(backendID, role)]
	if !ok {
		return domain.BackendAccount{}, ErrNotFound
	}
	return m.backendAccounts[id], nil
}

func accountKey(backendID string, role domain.Role) string {
	return backendID + "|" + string(role)
}

// --- grants ---

func (m *Memory) CreateGrant(_ context.Context, g domain.Grant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.grants[g.ID]; exists {
		return ErrConflict
	}
	m.grants[g.ID] = g
	return nil
}

func (m *Memory) GetGrant(_ context.Context, id string) (domain.Grant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	g, ok := m.grants[id]
	if !ok {
		return domain.Grant{}, ErrNotFound
	}
	return g, nil
}

func (m *Memory) UpdateGrant(_ context.Context, g domain.Grant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.grants[g.ID]; !ok {
		return ErrNotFound
	}
	m.grants[g.ID] = g
	return nil
}

// ListEphemeralOrphans returns terminal-state grants still carrying an
// ephemeral username — the sweeper drops these defensively in case a crash
// between status flip and provisioner.Revoke left a user behind.
func (m *Memory) ListEphemeralOrphans(_ context.Context) ([]domain.Grant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.Grant, 0)
	for _, g := range m.grants {
		if g.EphemeralUsername == "" {
			continue
		}
		switch g.Status {
		case domain.GrantDenied, domain.GrantRevoked, domain.GrantExpired:
			out = append(out, g)
		}
	}
	return out, nil
}

// ExpireStaleGrants flips ACTIVE grants past their ExpiresAt to EXPIRED.
// Skips rows with a revoked_at already set so a corner-case state can't
// clobber the revoke signal. Safe for concurrent use; single writer under
// the store mutex.
func (m *Memory) ExpireStaleGrants(_ context.Context, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, g := range m.grants {
		if g.Status != domain.GrantActive {
			continue
		}
		if g.ExpiresAt == nil || !g.ExpiresAt.Before(now) {
			continue
		}
		if g.RevokedAt != nil {
			continue
		}
		g.Status = domain.GrantExpired
		g.UpdatedAt = now
		m.grants[id] = g
		n++
	}
	return n, nil
}

// ExpireUnclaimedGrants implements the two pre-credential sweeper passes:
// PENDING|MANAGER_APPROVED past RequestExpiresAt and APPROVED past
// ClaimExpiresAt both transition to EXPIRED. Done in one mutex lock so
// the two passes share the writer barrier — neither modifies rows the other
// could pick up.
func (m *Memory) ExpireUnclaimedGrants(_ context.Context, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, g := range m.grants {
		if g.RevokedAt != nil {
			continue
		}
		switch g.Status {
		case domain.GrantPending, domain.GrantManagerApproved:
			if g.RequestExpiresAt != nil && g.RequestExpiresAt.Before(now) {
				g.Status = domain.GrantExpired
				g.UpdatedAt = now
				m.grants[id] = g
				n++
			}
		case domain.GrantApproved:
			if g.ClaimExpiresAt != nil && g.ClaimExpiresAt.Before(now) {
				g.Status = domain.GrantExpired
				g.UpdatedAt = now
				m.grants[id] = g
				n++
			}
		}
	}
	return n, nil
}

// SetGrantEphemeral stamps the ephemeral backend credential onto an existing
// grant row. Used after a successful provisioner call so the policy engine
// can serve the per-grant creds instead of the shared BackendAccount. Passing
// empty strings clears the fields — the orphan-sweep path does this after
// dropping an ephemeral account post-terminal-state.
func (m *Memory) SetGrantEphemeral(_ context.Context, id, username, password string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[id]
	if !ok {
		return ErrNotFound
	}
	g.EphemeralUsername = username
	g.EphemeralPassword = password
	g.UpdatedAt = time.Now().UTC()
	m.grants[id] = g
	return nil
}

// UpdateGrantIfStatus writes g only if the existing row still has expect.
// Returns ErrNotFound if no row, ErrConflict if status has drifted.
func (m *Memory) UpdateGrantIfStatus(_ context.Context, g domain.Grant, expect domain.GrantStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.grants[g.ID]
	if !ok {
		return ErrNotFound
	}
	if cur.Status != expect {
		return ErrConflict
	}
	m.grants[g.ID] = g
	return nil
}

func (m *Memory) ListGrants(_ context.Context, f GrantFilter) ([]domain.Grant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	statusSet := map[domain.GrantStatus]struct{}{}
	for _, s := range f.Statuses {
		statusSet[s] = struct{}{}
	}

	out := make([]domain.Grant, 0)
	for _, g := range m.grants {
		if f.UserID != "" && g.UserID != f.UserID {
			continue
		}
		if f.BackendID != "" && g.BackendID != f.BackendID {
			continue
		}
		if len(statusSet) > 0 {
			if _, ok := statusSet[g.Status]; !ok {
				continue
			}
		}
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

// --- audit ---

func (m *Memory) AppendAudit(_ context.Context, entries []domain.AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.audit = append(m.audit, entries...)
	return nil
}

func (m *Memory) ListAudit(_ context.Context, f AuditFilter) ([]domain.AuditEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.AuditEntry, 0)
	for _, e := range m.audit {
		if f.GrantID != "" && e.GrantID != f.GrantID {
			continue
		}
		if f.Username != "" && e.Username != f.Username {
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp.After(out[j].Timestamp) })
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

// PruneAudit trims entries older than cutoff and enforces the hard cap.
// Ordering is preserved (insertion order === timestamp order per caller contract).
func (m *Memory) PruneAudit(_ context.Context, cutoff time.Time, maxEntries int) (int, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	before := len(m.audit)
	// Drop entries strictly older than cutoff. Audit append order tracks
	// wall-clock timestamps very closely, but we scan rather than assume
	// sorted — a misbehaving shipper could submit out-of-order entries.
	kept := m.audit[:0]
	for _, e := range m.audit {
		if e.Timestamp.Before(cutoff) {
			continue
		}
		kept = append(kept, e)
	}
	// Release references held in the tail so GC can collect older entries.
	for i := len(kept); i < len(m.audit); i++ {
		m.audit[i] = domain.AuditEntry{}
	}
	m.audit = kept

	if maxEntries > 0 && len(m.audit) > maxEntries {
		drop := len(m.audit) - maxEntries
		// Slice-from-front: oldest entries live at the start.
		m.audit = append(m.audit[:0:0], m.audit[drop:]...)
	}
	pruned := before - len(m.audit)
	return pruned, len(m.audit), nil
}

// --- sessions ---

// CreateSession inserts s; returns ErrConflict if the ID already exists.
func (m *Memory) CreateSession(_ context.Context, s SessionRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[s.ID]; ok {
		return ErrConflict
	}
	m.sessions[s.ID] = s
	return nil
}

// GetSession returns the record or ErrNotFound. Does NOT check expiry —
// expiry policing is the caller's responsibility (matches the SQL impls).
func (m *Memory) GetSession(_ context.Context, id string) (SessionRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	if !ok {
		return SessionRecord{}, ErrNotFound
	}
	return s, nil
}

// DeleteSession drops id; no-op when absent.
func (m *Memory) DeleteSession(_ context.Context, id string) error {
	m.mu.Lock()
	delete(m.sessions, id)
	m.mu.Unlock()
	return nil
}

// PruneExpiredSessions removes every session whose ExpiresAt is before now.
func (m *Memory) PruneExpiredSessions(_ context.Context, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, s := range m.sessions {
		if s.ExpiresAt.Before(now) {
			delete(m.sessions, id)
			n++
		}
	}
	return n, nil
}
