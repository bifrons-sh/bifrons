package oidc

import (
	"container/list"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/babs/poc-proxies/portal/internal/store"
)

// persistentBackend is the subset of store.Store the SQL session store needs.
// Defined here so the oidc package doesn't pull the entire Store interface
// into its public API — callers wire whatever concrete store they already
// have (memory / sqlite / postgres) via store.Store, which satisfies this.
type persistentBackend interface {
	CreateSession(ctx context.Context, r store.SessionRecord) error
	GetSession(ctx context.Context, id string) (store.SessionRecord, error)
	DeleteSession(ctx context.Context, id string) error
}

// SQLStore is a cluster-safe SessionStore backed by the portal's persistence
// layer (store.Store). A small LRU cache with a short TTL keeps the happy
// path free of per-request DB queries; the cache is an optimization, never
// authoritative — writes always hit the backend first.
//
// The cache TTL is capped at 30s by convention so a session revoked on one
// replica becomes invisible to another within that window at the latest —
// a strict upper bound independent of the backend's own consistency model.
type SQLStore struct {
	backend  persistentBackend
	cache    *lruCache
	cacheTTL time.Duration
}

// SQLStoreOption tweaks SQLStore construction. Zero/negative values fall back
// to documented defaults (size=256, ttl=30s).
type SQLStoreOption func(*sqlStoreOpts)

type sqlStoreOpts struct {
	cacheSize int
	cacheTTL  time.Duration
}

// WithCacheSize sets the LRU capacity. Default 256 — enough for hundreds of
// concurrent operators without rebuilding the hash map on every eviction.
func WithCacheSize(n int) SQLStoreOption {
	return func(o *sqlStoreOpts) {
		if n > 0 {
			o.cacheSize = n
		}
	}
}

// WithCacheTTL caps per-entry staleness. Default 30s, ceiling 30s — longer
// TTLs would let a revoked session linger across replicas.
func WithCacheTTL(d time.Duration) SQLStoreOption {
	return func(o *sqlStoreOpts) {
		if d > 0 {
			o.cacheTTL = d
		}
	}
}

// NewSQLStore wraps a store.Store (via the narrow persistentBackend view) in
// a cache-fronted SessionStore. Panics if backend is nil — a nil backend is
// a programming error, not a runtime condition.
func NewSQLStore(backend persistentBackend, opts ...SQLStoreOption) *SQLStore {
	if backend == nil {
		panic("oidc: NewSQLStore called with nil backend")
	}
	o := sqlStoreOpts{cacheSize: 256, cacheTTL: 30 * time.Second}
	for _, opt := range opts {
		opt(&o)
	}
	// Hard ceiling: 30s. Any longer and cluster-wide invalidation after a
	// logout becomes user-visible.
	if o.cacheTTL > 30*time.Second {
		o.cacheTTL = 30 * time.Second
	}
	return &SQLStore{
		backend:  backend,
		cache:    newLRUCache(o.cacheSize),
		cacheTTL: o.cacheTTL,
	}
}

// Create writes the session through the backend, then seeds the cache so
// the very next Get skips the DB round-trip.
func (s *SQLStore) Create(sess Session) error {
	rec := store.SessionRecord{
		ID:           sess.ID,
		Subject:      sess.Subject,
		Email:        sess.Email,
		Name:         sess.Name,
		IsOperator:   sess.IsOperator,
		PortalUserID: sess.PortalUserID,
		ExpiresAt:    sess.ExpiresAt,
	}
	if err := s.backend.CreateSession(context.Background(), rec); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return errDuplicateSession
		}
		return err
	}
	s.cache.put(sess.ID, sess, time.Now().Add(s.cacheTTL))
	return nil
}

// Get returns the session. Cache hits avoid the DB entirely; misses fall
// through and populate the cache on success so the next lookup is cheap.
func (s *SQLStore) Get(id string) (Session, bool) {
	now := time.Now()
	if sess, ok := s.cache.get(id, now); ok {
		return sess, true
	}
	rec, err := s.backend.GetSession(context.Background(), id)
	if err != nil {
		// Negative results aren't cached: a just-created session elsewhere
		// must be visible immediately on this node. The TTL cap already
		// bounds positive staleness; negative caching would re-introduce
		// the problem on the other axis.
		return Session{}, false
	}
	sess := Session{
		ID:           rec.ID,
		Subject:      rec.Subject,
		Email:        rec.Email,
		Name:         rec.Name,
		IsOperator:   rec.IsOperator,
		PortalUserID: rec.PortalUserID,
		ExpiresAt:    rec.ExpiresAt,
	}
	s.cache.put(id, sess, now.Add(s.cacheTTL))
	return sess, true
}

// Delete drops the cache entry then the backend row. Order matters: if the
// cache evict lost a race with a concurrent Get and re-populated the cache
// from the DB before we delete the row, Get would serve a stale hit for up
// to cacheTTL. Deleting DB first + cache second closes that window.
func (s *SQLStore) Delete(id string) {
	_ = s.backend.DeleteSession(context.Background(), id)
	s.cache.del(id)
}

// SweepExpired satisfies SessionStore — here it only prunes the local cache,
// not the DB. The cluster sweeper calls store.Store.PruneExpiredSessions
// directly against the persistent backend.
func (s *SQLStore) SweepExpired(now time.Time) int {
	return s.cache.sweepExpired(now)
}

// --- LRU with TTL ---

// lruEntry is the value half of an LRU node. The list entry stores a pointer
// to this so eviction ordering and map lookup share the same record.
type lruEntry struct {
	key     string
	sess    Session
	expires time.Time // cache-entry expiry (NOT the session's ExpiresAt)
}

// lruCache is a small hand-rolled LRU+TTL. Using container/list keeps the
// implementation ~40 lines with zero external deps — the project's
// preference. Operations are O(1) but guarded by a single mutex; that's
// adequate at <10k req/s per replica.
type lruCache struct {
	mu    sync.Mutex
	cap   int
	ll    *list.List
	items map[string]*list.Element
}

func newLRUCache(cap int) *lruCache {
	if cap < 1 {
		cap = 1
	}
	return &lruCache{
		cap:   cap,
		ll:    list.New(),
		items: make(map[string]*list.Element, cap),
	}
}

func (c *lruCache) get(key string, now time.Time) (Session, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return Session{}, false
	}
	ent := el.Value.(*lruEntry)
	if now.After(ent.expires) {
		c.ll.Remove(el)
		delete(c.items, key)
		return Session{}, false
	}
	c.ll.MoveToFront(el)
	return ent.sess, true
}

func (c *lruCache) put(key string, sess Session, expires time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		ent := el.Value.(*lruEntry)
		ent.sess = sess
		ent.expires = expires
		c.ll.MoveToFront(el)
		return
	}
	ent := &lruEntry{key: key, sess: sess, expires: expires}
	el := c.ll.PushFront(ent)
	c.items[key] = el
	if c.ll.Len() > c.cap {
		oldest := c.ll.Back()
		if oldest != nil {
			c.ll.Remove(oldest)
			delete(c.items, oldest.Value.(*lruEntry).key)
		}
	}
}

func (c *lruCache) del(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.ll.Remove(el)
		delete(c.items, key)
	}
}

// sweepExpired prunes entries whose cache-expiry predates now. O(n) but only
// called from the session sweeper, not on the hot path.
func (c *lruCache) sweepExpired(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for el := c.ll.Back(); el != nil; {
		prev := el.Prev()
		ent := el.Value.(*lruEntry)
		if now.After(ent.expires) {
			c.ll.Remove(el)
			delete(c.items, ent.key)
			n++
		}
		el = prev
	}
	return n
}
