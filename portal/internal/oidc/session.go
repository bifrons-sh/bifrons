package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// Session represents an authenticated portal operator session backed by an
// OIDC ID token. The token-body itself is NOT stored; callers interact with
// the opaque session ID returned by the store.
type Session struct {
	ID      string
	Subject string // sub claim — stable user identifier
	Email   string
	Name    string
	IsAdmin bool // resolved from AdminClaim/AdminValue in Config
	// PortalUserID is the domain.User.ID bound to this session's Subject.
	// Populated on first-login provisioning so downstream handlers can scope
	// non-admin requests to their own records without re-running a store
	// lookup on every hit.
	PortalUserID string
	ExpiresAt    time.Time
}

// Expired reports whether now is past the session's expiry. Treated as
// "unauthenticated" by the middleware.
func (s *Session) Expired(now time.Time) bool { return now.After(s.ExpiresAt) }

// SessionStore persists session records. In-memory for the POC; swap for a
// persistent implementation (Redis, SQL) once the portal gains a real store.
type SessionStore interface {
	Create(s Session) error
	Get(id string) (Session, bool)
	Delete(id string)
	SweepExpired(now time.Time) int // prune; returns count removed
}

// MemoryStore is a goroutine-safe in-memory SessionStore.
type MemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]Session
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{sessions: make(map[string]Session)}
}

// Create records the session, returning ErrDuplicateSession if the ID exists.
func (m *MemoryStore) Create(s Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.sessions[s.ID]; exists {
		return errDuplicateSession
	}
	m.sessions[s.ID] = s
	return nil
}

// Get returns the session and true when present, zero + false otherwise.
// Callers must check Expired(now) themselves.
func (m *MemoryStore) Get(id string) (Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	return s, ok
}

// Delete drops the session; safe to call on unknown IDs.
func (m *MemoryStore) Delete(id string) {
	m.mu.Lock()
	delete(m.sessions, id)
	m.mu.Unlock()
}

// SweepExpired removes every session with ExpiresAt < now.
func (m *MemoryStore) SweepExpired(now time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	removed := 0
	for id, s := range m.sessions {
		if s.Expired(now) {
			delete(m.sessions, id)
			removed++
		}
	}
	return removed
}

// newSessionID returns a 32-byte URL-safe opaque token. Using crypto/rand
// directly: 256 bits of entropy is well beyond brute-force reach.
func newSessionID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

type errConst string

func (e errConst) Error() string { return string(e) }

const errDuplicateSession errConst = "session id already exists"
