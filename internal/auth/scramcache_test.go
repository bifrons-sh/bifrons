package auth

import (
	"bytes"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestScramCacheKey_Stability(t *testing.T) {
	// Same (pw, salt, iters) must hash to the same key across invocations.
	salt := []byte("0123456789abcdef")
	k1 := scramCacheKey("hunter2", salt, 15000)
	k2 := scramCacheKey("hunter2", salt, 15000)
	if k1 != k2 {
		t.Fatalf("unstable key: %q vs %q", k1, k2)
	}
	if len(k1) != 64 {
		t.Fatalf("key length = %d, want 64 hex chars", len(k1))
	}
}

func TestScramCacheKey_SeparatesFields(t *testing.T) {
	// "\x00" separators prevent cross-field collisions. Without them, pw="ab"+
	// iters=12345 could collide with pw="a" + iters=b12345 etc.
	cases := []struct {
		pw    string
		salt  []byte
		iters int
	}{
		{"a", []byte("b"), 15000},
		{"ab", []byte(""), 15000},
		{"a", []byte("b"), 15001},
		{"", []byte("ab"), 15000},
	}
	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		k := scramCacheKey(c.pw, c.salt, c.iters)
		if _, dup := seen[k]; dup {
			t.Fatalf("collision for %+v: %q", c, k)
		}
		seen[k] = struct{}{}
	}
}

func TestDeriveSalt_Deterministic(t *testing.T) {
	s1 := deriveSalt("hunter2")
	s2 := deriveSalt("hunter2")
	if !bytes.Equal(s1, s2) {
		t.Fatalf("non-deterministic salt: %x vs %x", s1, s2)
	}
	if len(s1) != derivedSaltLen {
		t.Fatalf("salt length = %d, want %d", len(s1), derivedSaltLen)
	}
	if bytes.Equal(s1, deriveSalt("hunter3")) {
		t.Fatal("different passwords must derive different salts")
	}
}

func TestSCRAMCache_GetMissReturnsFalse(t *testing.T) {
	c := NewSCRAMCache(4, time.Minute)
	if _, ok := c.Get("pw", []byte("salt"), 15000); ok {
		t.Fatal("empty cache reported hit")
	}
	if h, m, e := c.Stats(); h != 0 || m != 1 || e != 0 {
		t.Fatalf("stats after miss = (%d,%d,%d)", h, m, e)
	}
}

func TestSCRAMCache_PutGet(t *testing.T) {
	c := NewSCRAMCache(4, time.Minute)
	creds, err := scramStoredCredentialsWithSalt("pw", []byte("0123456789abcdef"), 15000)
	if err != nil {
		t.Fatal(err)
	}
	c.Put("pw", []byte("0123456789abcdef"), 15000, creds)

	got, ok := c.Get("pw", []byte("0123456789abcdef"), 15000)
	if !ok {
		t.Fatal("expected hit after Put")
	}
	if got.Iters != creds.Iters || !bytes.Equal(got.StoredKey, creds.StoredKey) {
		t.Fatalf("returned creds differ from stored")
	}
	if h, _, _ := c.Stats(); h != 1 {
		t.Fatalf("hits = %d, want 1", h)
	}
}

func TestSCRAMCache_EvictsAtCapacity(t *testing.T) {
	const cap = 3
	c := NewSCRAMCache(cap, time.Minute)
	// Fill beyond capacity — first entry must be evicted.
	for i := 0; i < cap+2; i++ {
		pw := "pw" + strconv.Itoa(i)
		salt := deriveSalt(pw)
		creds, err := scramStoredCredentialsWithSalt(pw, salt, 15000)
		if err != nil {
			t.Fatal(err)
		}
		c.Put(pw, salt, 15000, creds)
	}
	if c.Len() != cap {
		t.Fatalf("cache size = %d, want %d", c.Len(), cap)
	}
	_, _, evictions := c.Stats()
	if evictions != 2 {
		t.Fatalf("evictions = %d, want 2", evictions)
	}
	// The two oldest (pw0, pw1) should be gone.
	if _, ok := c.Get("pw0", deriveSalt("pw0"), 15000); ok {
		t.Fatal("pw0 should have been evicted")
	}
	if _, ok := c.Get("pw4", deriveSalt("pw4"), 15000); !ok {
		t.Fatal("pw4 should still be present")
	}
}

func TestSCRAMCache_LRUOrderingOnGet(t *testing.T) {
	c := NewSCRAMCache(2, time.Minute)
	salt := []byte("0123456789abcdef")
	a, _ := scramStoredCredentialsWithSalt("a", salt, 15000)
	b, _ := scramStoredCredentialsWithSalt("b", salt, 15000)
	c.Put("a", salt, 15000, a)
	c.Put("b", salt, 15000, b)
	// Touch "a" so "b" becomes LRU.
	if _, ok := c.Get("a", salt, 15000); !ok {
		t.Fatal("expected hit for a")
	}
	// Insert a third entry — "b" must be evicted, not "a".
	third, _ := scramStoredCredentialsWithSalt("cc", salt, 15000)
	c.Put("cc", salt, 15000, third)

	if _, ok := c.Get("a", salt, 15000); !ok {
		t.Fatal("a should have been retained (most recently used)")
	}
	if _, ok := c.Get("b", salt, 15000); ok {
		t.Fatal("b should have been evicted")
	}
}

func TestSCRAMCache_TTLExpiry(t *testing.T) {
	c := NewSCRAMCache(4, 10*time.Millisecond)
	// Drive time via the injectable now() so the test doesn't sleep.
	var virtual time.Time
	var mu sync.Mutex
	c.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return virtual
	}
	mu.Lock()
	virtual = time.Unix(0, 0)
	mu.Unlock()

	salt := deriveSalt("pw")
	creds, _ := scramStoredCredentialsWithSalt("pw", salt, 15000)
	c.Put("pw", salt, 15000, creds)

	mu.Lock()
	virtual = virtual.Add(5 * time.Millisecond)
	mu.Unlock()
	if _, ok := c.Get("pw", salt, 15000); !ok {
		t.Fatal("entry should still be fresh")
	}

	mu.Lock()
	virtual = virtual.Add(time.Hour)
	mu.Unlock()
	if _, ok := c.Get("pw", salt, 15000); ok {
		t.Fatal("entry should have expired")
	}
	if c.Len() != 0 {
		t.Fatalf("expired entry should have been pruned on lookup; len = %d", c.Len())
	}
}

func TestSCRAMCache_UpdatesExistingEntry(t *testing.T) {
	c := NewSCRAMCache(4, time.Minute)
	salt := deriveSalt("pw")
	first, _ := scramStoredCredentialsWithSalt("pw", salt, 15000)
	second, _ := scramStoredCredentialsWithSalt("pw", salt, 20000)

	c.Put("pw", salt, 15000, first)
	c.Put("pw", salt, 15000, second) // same key, replace in place
	if c.Len() != 1 {
		t.Fatalf("len = %d, want 1 (should replace not duplicate)", c.Len())
	}
	got, ok := c.Get("pw", salt, 15000)
	if !ok {
		t.Fatal("expected hit")
	}
	if got.Iters != second.Iters {
		t.Fatalf("iters = %d, want %d (replacement not stored)", got.Iters, second.Iters)
	}
}

func TestSCRAMCache_NilCacheFallsThrough(t *testing.T) {
	got, err := CachedSCRAMStoredCredentials(nil, "pw", DefaultSCRAMIters)
	if err != nil {
		t.Fatalf("nil cache should fall through, got err: %v", err)
	}
	if got.Iters != DefaultSCRAMIters {
		t.Fatalf("iters = %d, want %d", got.Iters, DefaultSCRAMIters)
	}
}

func TestCachedSCRAMStoredCredentials_SecondCallHits(t *testing.T) {
	c := NewSCRAMCache(4, time.Minute)
	_, err := CachedSCRAMStoredCredentials(c, "pw", DefaultSCRAMIters)
	if err != nil {
		t.Fatal(err)
	}
	_, err = CachedSCRAMStoredCredentials(c, "pw", DefaultSCRAMIters)
	if err != nil {
		t.Fatal(err)
	}
	h, m, _ := c.Stats()
	if h != 1 || m != 1 {
		t.Fatalf("stats = (hits=%d, misses=%d), want (1,1)", h, m)
	}
}

func TestCachedSCRAMStoredCredentials_RejectsWeakIters(t *testing.T) {
	c := NewSCRAMCache(4, time.Minute)
	if _, err := CachedSCRAMStoredCredentials(c, "pw", 1024); err == nil {
		t.Fatal("expected rejection of iters < 4096")
	}
}

// TestSCRAMCache_RaceClean stresses the cache from many goroutines. Run with
// `go test -race` to catch data races on the mu/ll/m trio.
func TestSCRAMCache_RaceClean(t *testing.T) {
	c := NewSCRAMCache(32, time.Minute)
	var wg sync.WaitGroup
	const workers = 16
	const iter = 200
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iter; i++ {
				pw := fmt.Sprintf("pw-%d-%d", w%4, i%8) // deliberate overlap for hits
				_, err := CachedSCRAMStoredCredentials(c, pw, DefaultSCRAMIters)
				if err != nil {
					t.Errorf("compute failed: %v", err)
					return
				}
				c.Stats()
				c.Len()
			}
		}(w)
	}
	wg.Wait()
}

// BenchmarkSCRAMCache_MissVsHit demonstrates the ~100× speedup claimed in the
// phase-2.2 spec. Miss = full PBKDF2 (15k iters). Hit = map lookup + sha256 of
// the cache key.
func BenchmarkSCRAMCache_Miss(b *testing.B) {
	for i := 0; i < b.N; i++ {
		c := NewSCRAMCache(4, time.Minute)
		if _, err := CachedSCRAMStoredCredentials(c, "hunter2", DefaultSCRAMIters); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSCRAMCache_Hit(b *testing.B) {
	c := NewSCRAMCache(4, time.Minute)
	if _, err := CachedSCRAMStoredCredentials(c, "hunter2", DefaultSCRAMIters); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := CachedSCRAMStoredCredentials(c, "hunter2", DefaultSCRAMIters); err != nil {
			b.Fatal(err)
		}
	}
}

// TestBenchmark_HitIsAtLeast100xFaster asserts the spec's performance target
// programmatically so regressions are caught by `go test`, not only by manual
// `go test -bench`. Uses testing.Benchmark to measure both paths.
func TestBenchmark_HitIsAtLeast100xFaster(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping bench-backed perf assertion in -short mode")
	}
	miss := testing.Benchmark(BenchmarkSCRAMCache_Miss)
	hit := testing.Benchmark(BenchmarkSCRAMCache_Hit)
	if miss.NsPerOp() == 0 || hit.NsPerOp() == 0 {
		t.Fatalf("benchmarks produced zero ns/op: miss=%v hit=%v", miss, hit)
	}
	ratio := float64(miss.NsPerOp()) / float64(hit.NsPerOp())
	t.Logf("miss=%d ns/op  hit=%d ns/op  ratio=%.1fx", miss.NsPerOp(), hit.NsPerOp(), ratio)
	// Spec target is ~100×; use 50× as the floor to absorb CI noise (the real
	// ratio on modern CPUs is ~1000× since PBKDF2-15k is multi-ms and a hit is
	// sub-microsecond).
	if ratio < 50 {
		t.Fatalf("cache hit only %.1fx faster than miss; spec requires ~100×", ratio)
	}
}
