package store

import (
	"context"
	"sort"
	"sync"

	"github.com/babs/poc-proxies/portal/internal/domain"
)

// Memory is a goroutine-safe in-memory Store. Data is lost on restart.
// Intended for POC / tests; swap for a persistent Store in real deployments.
type Memory struct {
	mu              sync.RWMutex
	users           map[string]domain.User
	usernameIndex   map[string]string // username -> user id
	backends        map[string]domain.Backend
	backendByAddr   map[string]string // host:port -> backend id
	backendAccounts map[string]domain.BackendAccount
	accountKey      map[string]string // backendID|role -> account id
	grants          map[string]domain.Grant
	audit           []domain.AuditEntry
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		users:           make(map[string]domain.User),
		usernameIndex:   make(map[string]string),
		backends:        make(map[string]domain.Backend),
		backendByAddr:   make(map[string]string),
		backendAccounts: make(map[string]domain.BackendAccount),
		accountKey:      make(map[string]string),
		grants:          make(map[string]domain.Grant),
	}
}

// --- users ---

func (m *Memory) CreateUser(_ context.Context, u domain.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.usernameIndex[u.Username]; exists {
		return ErrConflict
	}
	m.users[u.ID] = u
	m.usernameIndex[u.Username] = u.ID
	return nil
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
