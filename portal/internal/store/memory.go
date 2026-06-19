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
	groups          map[string]domain.Group
	groupSlugIndex  map[string]string               // slug -> group id
	groupMembers    map[string]map[string]time.Time // groupID -> userID -> joinedAt
	backends        map[string]domain.Backend
	backendByAddr   map[string]string // host:port -> backend id
	backendAccounts map[string]domain.BackendAccount
	accountKey      map[string]string // backendID|role -> account id
	grants          map[string]domain.Grant
	intents         map[string]domain.Intent
	workers         map[string]domain.WorkerHeartbeat
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
		groups:          make(map[string]domain.Group),
		groupSlugIndex:  make(map[string]string),
		groupMembers:    make(map[string]map[string]time.Time),
		backends:        make(map[string]domain.Backend),
		backendByAddr:   make(map[string]string),
		backendAccounts: make(map[string]domain.BackendAccount),
		accountKey:      make(map[string]string),
		grants:          make(map[string]domain.Grant),
		intents:         make(map[string]domain.Intent),
		workers:         make(map[string]domain.WorkerHeartbeat),
		sessions:        make(map[string]SessionRecord),
	}
}

// UpdateUser reconciles mutable scalar attributes on an existing user row.
// See store.Store.UpdateUser for the field boundary. ExternalID is kept
// unique across users — a collision returns ErrConflict.
//
// Compare-and-swap on u.UpdatedAt: the row is only written if the stored
// UpdatedAt matches what the caller read. A mismatch returns ErrNotFound
// (same shape as "row gone") so the handler doesn't need a third branch.
func (m *Memory) UpdateUser(_ context.Context, u domain.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.users[u.ID]
	if !ok {
		return ErrNotFound
	}
	// CAS: concurrent patches race cleanly, first writer wins. The caller's
	// u came from a prior GetUser, so u.UpdatedAt is what was on disk at
	// read time; a drift means somebody else patched between our read and
	// this write.
	if !cur.UpdatedAt.Equal(u.UpdatedAt) {
		return ErrNotFound
	}
	if u.ExternalID != "" && u.ExternalID != cur.ExternalID {
		if existing, taken := m.externalIDIndex[u.ExternalID]; taken && existing != u.ID {
			return ErrConflict
		}
	}
	cur.DisplayName = u.DisplayName
	cur.Email = u.Email
	cur.IsOperator = u.IsOperator
	cur.Status = u.Status
	if cur.ExternalID != u.ExternalID {
		if cur.ExternalID != "" {
			delete(m.externalIDIndex, cur.ExternalID)
		}
		cur.ExternalID = u.ExternalID
		if cur.ExternalID != "" {
			m.externalIDIndex[cur.ExternalID] = cur.ID
		}
	}
	cur.UpdatedAt = time.Now().UTC()
	m.users[u.ID] = cur
	return nil
}

// UpdateUserDemote applies UpdateUser's CAS write and the last-admin guard
// under the same exclusive lock so two concurrent demotes of different admins
// cannot both pass a stale count check.
func (m *Memory) UpdateUserDemote(_ context.Context, u domain.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.users[u.ID]
	if !ok {
		return ErrNotFound
	}
	if !cur.UpdatedAt.Equal(u.UpdatedAt) {
		return ErrNotFound
	}
	// Only enforce the guard when the row currently *counts* as an active
	// admin. Demoting a disabled admin doesn't reduce the active-admin tally
	// (it's already excluded), so blocking that case would be a false positive.
	if cur.IsOperator && !u.IsOperator && (cur.Status == "" || cur.Status == "active") {
		n := 0
		for _, x := range m.users {
			if x.IsOperator && (x.Status == "" || x.Status == "active") {
				n++
			}
		}
		if n <= 1 {
			return ErrLastAdmin
		}
	}
	if u.ExternalID != "" && u.ExternalID != cur.ExternalID {
		if existing, taken := m.externalIDIndex[u.ExternalID]; taken && existing != u.ID {
			return ErrConflict
		}
	}
	cur.DisplayName = u.DisplayName
	cur.Email = u.Email
	cur.IsOperator = u.IsOperator
	cur.Status = u.Status
	if cur.ExternalID != u.ExternalID {
		if cur.ExternalID != "" {
			delete(m.externalIDIndex, cur.ExternalID)
		}
		cur.ExternalID = u.ExternalID
		if cur.ExternalID != "" {
			m.externalIDIndex[cur.ExternalID] = cur.ID
		}
	}
	cur.UpdatedAt = time.Now().UTC()
	m.users[u.ID] = cur
	return nil
}

// CountAdmins returns the number of active users with IsOperator=true.
func (m *Memory) CountAdmins(_ context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, u := range m.users {
		if u.IsOperator && (u.Status == "" || u.Status == "active") {
			n++
		}
	}
	return n, nil
}

// ListUsers returns all users, ordered by username.
func (m *Memory) ListUsers(_ context.Context) ([]domain.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.User, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}

// --- validator + groups ---

func (m *Memory) SetUserValidator(_ context.Context, userID, validatorUserID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return ErrNotFound
	}
	if validatorUserID != "" {
		if _, ok := m.users[validatorUserID]; !ok {
			return ErrNotFound
		}
	}
	u.ValidatorUserID = validatorUserID
	u.UpdatedAt = time.Now().UTC()
	m.users[userID] = u
	return nil
}

func (m *Memory) UpsertGroup(_ context.Context, g domain.Group) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Slug uniqueness enforced at this layer — two groups can't claim the
	// same slug, else the policy YAML would ambiguously resolve.
	if existingID, ok := m.groupSlugIndex[g.Slug]; ok && existingID != g.ID {
		return ErrConflict
	}
	// If an existing row is being renamed, drop its old slug entry so the
	// index doesn't resolve both old and new slugs to the same group.
	if prev, ok := m.groups[g.ID]; ok && prev.Slug != "" && prev.Slug != g.Slug {
		delete(m.groupSlugIndex, prev.Slug)
	}
	m.groups[g.ID] = g
	m.groupSlugIndex[g.Slug] = g.ID
	return nil
}

func (m *Memory) GetGroup(_ context.Context, id string) (domain.Group, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	g, ok := m.groups[id]
	if !ok {
		return domain.Group{}, ErrNotFound
	}
	return g, nil
}

func (m *Memory) GetGroupBySlug(_ context.Context, slug string) (domain.Group, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.groupSlugIndex[slug]
	if !ok {
		return domain.Group{}, ErrNotFound
	}
	return m.groups[id], nil
}

func (m *Memory) ListGroups(_ context.Context) ([]domain.Group, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.Group, 0, len(m.groups))
	for _, g := range m.groups {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out, nil
}

func (m *Memory) DeleteGroup(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.groups[id]
	if !ok {
		return ErrNotFound
	}
	delete(m.groups, id)
	delete(m.groupSlugIndex, g.Slug)
	delete(m.groupMembers, id)
	return nil
}

func (m *Memory) AddGroupMember(_ context.Context, groupID, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.groups[groupID]; !ok {
		return ErrNotFound
	}
	if _, ok := m.users[userID]; !ok {
		return ErrNotFound
	}
	members, ok := m.groupMembers[groupID]
	if !ok {
		members = map[string]time.Time{}
		m.groupMembers[groupID] = members
	}
	// Idempotent: don't overwrite the original JoinedAt if already present.
	if _, exists := members[userID]; !exists {
		members[userID] = time.Now().UTC()
	}
	return nil
}

func (m *Memory) RemoveGroupMember(_ context.Context, groupID, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	members, ok := m.groupMembers[groupID]
	if !ok {
		return nil // idempotent: absent group → nothing to do
	}
	delete(members, userID)
	return nil
}

func (m *Memory) ListGroupMembers(_ context.Context, groupID string) ([]domain.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.groups[groupID]; !ok {
		return nil, ErrNotFound
	}
	members := m.groupMembers[groupID]
	out := make([]domain.User, 0, len(members))
	for uid := range members {
		if u, ok := m.users[uid]; ok {
			out = append(out, u)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}

func (m *Memory) ListUserGroups(_ context.Context, userID string) ([]domain.Group, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.users[userID]; !ok {
		return nil, ErrNotFound
	}
	out := make([]domain.Group, 0)
	for gid, members := range m.groupMembers {
		if _, ok := members[userID]; ok {
			if g, gok := m.groups[gid]; gok {
				out = append(out, g)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out, nil
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
	if b.ApprovalMode == "" {
		b.ApprovalMode = domain.ApprovalDualStrict
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

func (m *Memory) GetBackend(_ context.Context, id string) (domain.Backend, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.backends[id]
	if !ok {
		return domain.Backend{}, ErrNotFound
	}
	return b, nil
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
// PENDING|VALIDATOR_APPROVED past RequestExpiresAt and APPROVED past
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
		case domain.GrantPending, domain.GrantValidatorApproved:
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

	// Bridge for scope=validator (phase-7 §7.4): pre-resolve the set of
	// users whose validator chain points at f.ValidatorUserID. Today's
	// schema has at most one validator per user, so this is a single-pass
	// scan. Will be replaced by a JOIN against grant_validators when the
	// snapshot table lands.
	var validatorScope map[string]struct{}
	if f.ValidatorUserID != "" {
		validatorScope = map[string]struct{}{}
		for _, u := range m.users {
			if u.ValidatorUserID == f.ValidatorUserID {
				validatorScope[u.ID] = struct{}{}
			}
		}
	}

	out := make([]domain.Grant, 0)
	for _, g := range m.grants {
		if validatorScope != nil {
			if _, ok := validatorScope[g.UserID]; !ok {
				continue
			}
		} else if f.UserID != "" && g.UserID != f.UserID {
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

// --- provisioning outbox ---

// InsertIntent is idempotent: a row with the same id already present is left
// untouched and the call succeeds (mirrors INSERT ... ON CONFLICT DO NOTHING).
// The deterministic intent id means producer retries converge on one row.
func (m *Memory) InsertIntent(_ context.Context, in domain.Intent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.intents[in.ID]; exists {
		return nil
	}
	m.intents[in.ID] = in
	return nil
}

// ClaimPendingIntents leases eligible rows to workerID. Single writer under the
// store mutex makes the read-eligible-then-flip sequence atomic — no SELECT FOR
// UPDATE needed at this layer. Ordering: revoke before provision, then oldest
// first, so teardown drains ahead of new work.
func (m *Memory) ClaimPendingIntents(_ context.Context, workerID string, instanceWhitelist []string, lease time.Duration, limit int) ([]domain.Intent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()

	var allow map[string]struct{}
	if len(instanceWhitelist) > 0 {
		allow = make(map[string]struct{}, len(instanceWhitelist))
		for _, b := range instanceWhitelist {
			allow[b] = struct{}{}
		}
	}

	eligible := make([]domain.Intent, 0)
	for _, in := range m.intents {
		if allow != nil {
			if _, ok := allow[in.BackendID]; !ok {
				continue
			}
		}
		switch in.Status {
		case domain.IntentPending:
			eligible = append(eligible, in)
		case domain.IntentInFlight:
			// Stale-lease reclaim: a worker that died mid-flight leaves the
			// lease to lapse; another worker may take over once it's past.
			if in.LeaseExpiresAt != nil && in.LeaseExpiresAt.Before(now) {
				eligible = append(eligible, in)
			}
		}
	}

	sortIntentsForClaim(eligible)
	if limit > 0 && len(eligible) > limit {
		eligible = eligible[:limit]
	}

	leaseUntil := now.Add(lease)
	out := make([]domain.Intent, 0, len(eligible))
	for _, in := range eligible {
		in.Status = domain.IntentInFlight
		in.WorkerID = workerID
		in.LeaseExpiresAt = &leaseUntil
		in.UpdatedAt = now
		m.intents[in.ID] = in
		out = append(out, in)
	}
	return out, nil
}

// sortIntentsForClaim orders revoke ahead of provision, then by created_at
// ascending. Tie-break on id keeps the order deterministic across runs (map
// iteration is randomised), which matters for the contract test's expectations.
func sortIntentsForClaim(in []domain.Intent) {
	rank := func(k domain.IntentKind) int {
		if k == domain.IntentRevoke {
			return 0
		}
		return 1
	}
	sort.Slice(in, func(i, j int) bool {
		if ri, rj := rank(in[i].Kind), rank(in[j].Kind); ri != rj {
			return ri < rj
		}
		if !in[i].CreatedAt.Equal(in[j].CreatedAt) {
			return in[i].CreatedAt.Before(in[j].CreatedAt)
		}
		return in[i].ID < in[j].ID
	})
}

// HeartbeatIntentLease extends the lease only while the row is still owned by
// workerID and in_flight. Any other state means ownership lapsed — ErrNotFound
// tells the worker to stop.
func (m *Memory) HeartbeatIntentLease(_ context.Context, id, workerID string, lease time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	in, ok := m.intents[id]
	if !ok || in.Status != domain.IntentInFlight || in.WorkerID != workerID {
		return ErrNotFound
	}
	now := time.Now().UTC()
	leaseUntil := now.Add(lease)
	in.LeaseExpiresAt = &leaseUntil
	in.UpdatedAt = now
	m.intents[id] = in
	return nil
}

// CompleteIntent marks the row done with its result. Only the owning worker of
// an in_flight row may complete it.
func (m *Memory) CompleteIntent(_ context.Context, id, workerID, resultUsername, resultPassword string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	in, ok := m.intents[id]
	if !ok || in.Status != domain.IntentInFlight || in.WorkerID != workerID {
		return ErrNotFound
	}
	now := time.Now().UTC()
	in.Status = domain.IntentDone
	in.ResultUsername = resultUsername
	in.ResultPassword = resultPassword
	in.CompletedAt = &now
	in.UpdatedAt = now
	m.intents[id] = in
	return nil
}

// FailIntent marks the row failed. Only the owning worker of an in_flight row
// may fail it.
func (m *Memory) FailIntent(_ context.Context, id, workerID, errorClass, errorDetail string, retryCount int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	in, ok := m.intents[id]
	if !ok || in.Status != domain.IntentInFlight || in.WorkerID != workerID {
		return ErrNotFound
	}
	now := time.Now().UTC()
	in.Status = domain.IntentFailed
	in.ErrorClass = errorClass
	in.ErrorDetail = errorDetail
	in.RetryCount = retryCount
	in.UpdatedAt = now
	m.intents[id] = in
	return nil
}

// ResetIntentForRetry flips a failed row back to pending and clears the
// worker/lease/error bookkeeping. No-op-guarded: only a failed row is reset, so
// a concurrent worker that has already re-claimed it (in_flight) is untouched.
func (m *Memory) ResetIntentForRetry(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	in, ok := m.intents[id]
	if !ok || in.Status != domain.IntentFailed {
		return ErrNotFound
	}
	in.Status = domain.IntentPending
	in.WorkerID = ""
	in.LeaseExpiresAt = nil
	in.ErrorClass = ""
	in.ErrorDetail = ""
	in.RetryCount = 0
	in.UpdatedAt = time.Now().UTC()
	m.intents[id] = in
	return nil
}

func (m *Memory) GetIntent(_ context.Context, id string) (domain.Intent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	in, ok := m.intents[id]
	if !ok {
		return domain.Intent{}, ErrNotFound
	}
	return in, nil
}

// GetLatestIntentForGrant returns the newest matching intent. With today's
// deterministic id there's at most one row per (grant, kind), but the
// created_at scan keeps the contract honest if that ever changes.
func (m *Memory) GetLatestIntentForGrant(_ context.Context, grantID string, kind domain.IntentKind) (domain.Intent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var (
		best  domain.Intent
		found bool
	)
	for _, in := range m.intents {
		if in.GrantID != grantID || in.Kind != kind {
			continue
		}
		if !found || in.CreatedAt.After(best.CreatedAt) {
			best = in
			found = true
		}
	}
	if !found {
		return domain.Intent{}, ErrNotFound
	}
	return best, nil
}

// --- worker liveness ---

// UpsertWorkerHeartbeat registers or refreshes a worker row. On update the
// original StartedAt is preserved (a later beat must not reset uptime), and
// the Instances / Health slices are cloned so a caller mutating its own copy
// after the call can't reach into the stored map.
func (m *Memory) UpsertWorkerHeartbeat(_ context.Context, hb domain.WorkerHeartbeat) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.workers[hb.WorkerID]; ok {
		hb.StartedAt = existing.StartedAt
	}
	m.workers[hb.WorkerID] = cloneHeartbeat(hb)
	return nil
}

// ListWorkerHeartbeats returns every worker row ordered by worker_id, each a
// defensive clone so list consumers can't mutate stored state.
func (m *Memory) ListWorkerHeartbeats(_ context.Context) ([]domain.WorkerHeartbeat, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.WorkerHeartbeat, 0, len(m.workers))
	for _, hb := range m.workers {
		out = append(out, cloneHeartbeat(hb))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].WorkerID < out[j].WorkerID })
	return out, nil
}

// PruneStaleWorkers deletes rows last seen strictly before cutoff. The strict
// comparison matches domain.WorkerHeartbeat.IsStale (a row exactly at the
// cutoff is not yet stale) and the SQL impls' `last_seen_at < cutoff`.
func (m *Memory) PruneStaleWorkers(_ context.Context, cutoff time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, hb := range m.workers {
		if hb.LastSeenAt.Before(cutoff) {
			delete(m.workers, id)
			n++
		}
	}
	return n, nil
}

// cloneHeartbeat deep-copies the slice fields so the in-memory store never
// shares backing arrays with callers — matches the value-copy isolation the
// SQL backends get for free via JSON (de)serialisation.
func cloneHeartbeat(hb domain.WorkerHeartbeat) domain.WorkerHeartbeat {
	if hb.Instances != nil {
		hb.Instances = append([]string(nil), hb.Instances...)
	}
	if hb.Health != nil {
		hb.Health = append([]domain.InstanceHealth(nil), hb.Health...)
	}
	return hb
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
