package oidc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/babs/poc-proxies/portal/internal/store"
	_ "github.com/babs/poc-proxies/portal/internal/store/sqlite"
)

func newBackendT(t *testing.T) store.Store {
	t.Helper()
	s, err := store.NewFromURL("sqlite::memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSQLStore_CRUD(t *testing.T) {
	backend := newBackendT(t)
	ss := NewSQLStore(backend)
	sess := Session{
		ID:        "sid-1",
		Subject:   "sub-1",
		Email:     "a@b",
		Name:      "Alice",
		IsAdmin:   true,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := ss.Create(sess); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Duplicate IDs surface as errDuplicateSession (matches MemoryStore).
	if err := ss.Create(sess); !errors.Is(err, errDuplicateSession) {
		t.Fatalf("dup create err=%v want errDuplicateSession", err)
	}
	// Drop the cache to force a DB round-trip for the next Get.
	ss.cache.del("sid-1")
	got, ok := ss.Get("sid-1")
	if !ok || got.Subject != "sub-1" || !got.IsAdmin {
		t.Fatalf("get miss or wrong value: ok=%v got=%+v", ok, got)
	}
	// Second Get should be served from the cache — verify by evicting the
	// row at the backend and confirming the cache still returns it.
	if err := backend.DeleteSession(context.Background(), "sid-1"); err != nil {
		t.Fatalf("backend delete: %v", err)
	}
	got2, ok := ss.Get("sid-1")
	if !ok || got2.Subject != "sub-1" {
		t.Fatal("expected cache hit after backend delete")
	}
	// Delete clears both cache + backend — subsequent Get misses cleanly.
	ss.Delete("sid-1")
	if _, ok := ss.Get("sid-1"); ok {
		t.Fatal("expected miss after Delete")
	}
}

func TestSQLStore_CacheTTLEviction(t *testing.T) {
	backend := newBackendT(t)
	// 50ms TTL so the test stays fast without stressing the scheduler.
	ss := NewSQLStore(backend, WithCacheTTL(50*time.Millisecond), WithCacheSize(8))
	sess := Session{ID: "sid-a", Subject: "s", ExpiresAt: time.Now().Add(time.Hour)}
	if err := ss.Create(sess); err != nil {
		t.Fatal(err)
	}
	// Drop the backend row so a cache miss returns empty. As long as the
	// cache entry is fresh, Get must succeed.
	if err := backend.DeleteSession(context.Background(), "sid-a"); err != nil {
		t.Fatal(err)
	}
	if _, ok := ss.Get("sid-a"); !ok {
		t.Fatal("expected cache hit before TTL")
	}
	// After TTL expires the cache entry is dropped and Get falls through
	// to the (now empty) backend, returning miss.
	time.Sleep(80 * time.Millisecond)
	if _, ok := ss.Get("sid-a"); ok {
		t.Fatal("expected miss after TTL expiry")
	}
}

func TestSQLStore_CacheTTLCapped(t *testing.T) {
	// Requesting a TTL > 30s must clamp to 30s — cluster-wide invalidation
	// after logout depends on this bound.
	backend := newBackendT(t)
	ss := NewSQLStore(backend, WithCacheTTL(5*time.Minute))
	if ss.cacheTTL != 30*time.Second {
		t.Fatalf("cacheTTL=%v want 30s", ss.cacheTTL)
	}
}

func TestSQLStore_LRUCapacityEviction(t *testing.T) {
	backend := newBackendT(t)
	ss := NewSQLStore(backend, WithCacheSize(2))
	now := time.Now()
	for i, id := range []string{"a", "b", "c"} {
		s := Session{ID: id, Subject: id, ExpiresAt: now.Add(time.Hour)}
		if err := ss.Create(s); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	// `a` should have been evicted (size=2, LRU). Confirm by deleting it
	// at the backend and asserting the next Get is a miss.
	if err := backend.DeleteSession(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	if _, ok := ss.Get("a"); ok {
		t.Fatal("expected a to be evicted from LRU")
	}
	// `c` is still fresh in the cache.
	if err := backend.DeleteSession(context.Background(), "c"); err != nil {
		t.Fatal(err)
	}
	if _, ok := ss.Get("c"); !ok {
		t.Fatal("expected c to still be cached")
	}
}

func TestSQLStore_SweeperPrunesBackend(t *testing.T) {
	backend := newBackendT(t)
	ss := NewSQLStore(backend)
	now := time.Now()
	alive := Session{ID: "live", Subject: "live", ExpiresAt: now.Add(time.Hour)}
	dead := Session{ID: "dead", Subject: "dead", ExpiresAt: now.Add(-time.Hour)}
	if err := ss.Create(alive); err != nil {
		t.Fatal(err)
	}
	if err := ss.Create(dead); err != nil {
		t.Fatal(err)
	}
	n, err := backend.PruneExpiredSessions(context.Background(), now)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("pruned=%d want 1", n)
	}
	// After DB prune the cache still holds 'dead' up to cacheTTL — that's
	// acceptable (bounded staleness) but Get must eventually miss. Bypass
	// the cache to confirm the backend row is gone.
	if _, err := backend.GetSession(context.Background(), "dead"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("dead row still present: %v", err)
	}
}
