package entra

import (
	"context"
	"sync"
)

// FakeClient is an in-memory Client used in unit/handler tests. Fields are
// goroutine-safe via the embedded mutex so tests can inspect sent mail and
// lookups from assertions without racing against background goroutines that
// the handler layer kicks off for non-blocking email delivery.
type FakeClient struct {
	mu       sync.Mutex
	Managers map[string]User
	// ManagerMissing, when set true for an id, causes Manager() to return
	// ErrNotFound regardless of the Managers map — useful for "user has no
	// manager" fallback-path tests.
	ManagerMissing map[string]bool
	GroupsByUser   map[string][]Group
	UsersByID      map[string]User
	MembersByGroup map[string][]User
	Sent           []SentMail
	// SendErr, when non-nil, is returned verbatim from SendMail — simulates a
	// Graph outage so tests can exercise the fail-open email path.
	SendErr error
}

// SentMail records a captured SendMail invocation.
type SentMail struct {
	From    string
	Message MailMessage
}

// NewFakeClient returns an empty FakeClient.
func NewFakeClient() *FakeClient {
	return &FakeClient{
		Managers:       make(map[string]User),
		ManagerMissing: make(map[string]bool),
		GroupsByUser:   make(map[string][]Group),
		UsersByID:      make(map[string]User),
		MembersByGroup: make(map[string][]User),
	}
}

// Manager looks up the configured manager, or returns ErrNotFound when unset.
func (f *FakeClient) Manager(_ context.Context, userObjectID string) (User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ManagerMissing[userObjectID] {
		return User{}, ErrNotFound
	}
	m, ok := f.Managers[userObjectID]
	if !ok {
		return User{}, ErrNotFound
	}
	return m, nil
}

// Groups returns the pre-seeded group list (nil when unset).
func (f *FakeClient) Groups(_ context.Context, userObjectID string) ([]Group, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Group(nil), f.GroupsByUser[userObjectID]...), nil
}

// GetUser returns the pre-seeded user, or ErrNotFound.
func (f *FakeClient) GetUser(_ context.Context, userObjectID string) (User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.UsersByID[userObjectID]
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}

// GroupMembers returns the pre-seeded member list (nil when unset).
func (f *FakeClient) GroupMembers(_ context.Context, groupID string) ([]User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]User(nil), f.MembersByGroup[groupID]...), nil
}

// SendMail records the request; honours SendErr to simulate failures.
func (f *FakeClient) SendMail(_ context.Context, from string, req MailMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.SendErr != nil {
		return f.SendErr
	}
	f.Sent = append(f.Sent, SentMail{From: from, Message: req})
	return nil
}

// SentSnapshot returns a copy of the captured messages, safe for concurrent reads.
func (f *FakeClient) SentSnapshot() []SentMail {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]SentMail(nil), f.Sent...)
}
