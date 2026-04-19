package auth

import (
	"container/list"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xdg-go/scram"
)

// DefaultSCRAMCacheSize is the default LRU capacity for SCRAMCache when
// callers pass a non-positive size. Sized to comfortably fit the working set
// of a single proxy node (~hundreds of concurrent users) without pressuring
// the GC — each entry is ~200B.
const DefaultSCRAMCacheSize = 1024

// DefaultSCRAMCacheTTL is the default entry lifetime. Bounds the window in
// which a leaked DB mapping would help an attacker; 5m balances that risk
// against hit rate for bursty reconnect patterns.
const DefaultSCRAMCacheTTL = 5 * time.Minute

// saltDerivationContext is mixed into the deterministic salt derivation so
// the derived salt cannot be confused with any other HMAC output computed
// from the same password. Versioned so we can rotate later without breaking
// in-flight caches (just bump the suffix and old entries age out via TTL).
const saltDerivationContext = "poc-proxies/scramcache/salt/v1"

// derivedSaltLen is the byte length of the deterministic salt. 16 matches
// what SCRAMStoredCredentials generates randomly and the MongoDB/PG defaults.
const derivedSaltLen = 16

// SCRAMCache is a bounded LRU cache of SCRAM-SHA-256 stored credentials keyed
// by (password, salt, iters). PBKDF2 at 15k iters is ~8–10ms of CPU per call;
// caching collapses the hot path to a map lookup (microseconds) after the first
// miss per credential. Entries expire after ttl to bound the staleness window.
//
// The cache is safe for concurrent use; a single sync.Mutex guards both the
// map and the LRU list. Lock-free reads weren't worth the complexity: the
// critical section is a handful of pointer assignments and contention would
// only matter at millions of ops/sec per proxy, which is not where this code
// spends its day.
type SCRAMCache struct {
	mu   sync.Mutex
	ll   *list.List               // front = most recently used
	m    map[string]*list.Element // key -> element; element.Value = *scramEntry
	cap  int
	ttl  time.Duration
	now  func() time.Time // injectable for tests
	hits atomic.Uint64
	miss atomic.Uint64
	evic atomic.Uint64
}

type scramEntry struct {
	key       string
	value     scram.StoredCredentials
	expiresAt time.Time
}

// NewSCRAMCache creates a cache with the given capacity and TTL. Non-positive
// values fall back to DefaultSCRAMCacheSize / DefaultSCRAMCacheTTL so callers
// can wire in flag values directly without pre-validating.
func NewSCRAMCache(size int, ttl time.Duration) *SCRAMCache {
	if size <= 0 {
		size = DefaultSCRAMCacheSize
	}
	if ttl <= 0 {
		ttl = DefaultSCRAMCacheTTL
	}
	return &SCRAMCache{
		ll:  list.New(),
		m:   make(map[string]*list.Element, size),
		cap: size,
		ttl: ttl,
		now: time.Now,
	}
}

// Stats returns cumulative counters: hits, misses, evictions. Plumbed to the
// obs sidecar so operators can tune -scram-cache-size based on real hit rate.
func (c *SCRAMCache) Stats() (hits, misses, evictions uint64) {
	return c.hits.Load(), c.miss.Load(), c.evic.Load()
}

// scramCacheKey returns the cache key for a (password, salt, iters) triple.
// sha256 gives a fixed-width 64-hex-char key regardless of input sizes, which
// keeps the map memory footprint predictable and the hashing cost trivial
// compared to the PBKDF2 work we're avoiding. The "\x00" separator prevents
// ambiguity across field boundaries (e.g. password ending in a digit adjacent
// to iters bytes could otherwise collide across different inputs).
func scramCacheKey(password string, salt []byte, iters int) string {
	h := sha256.New()
	h.Write([]byte(password))
	h.Write([]byte{0})
	h.Write(salt)
	h.Write([]byte{0})
	h.Write([]byte(strconv.Itoa(iters)))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)
}

// deriveSalt produces a deterministic 16-byte salt from password so that
// repeated lookups for the same password converge on the same cache key.
// HMAC(password, saltDerivationContext) is not reversible, so leaking the
// derived salt does not help an attacker recover the password any more than
// leaking the password hash already would. This is the trade-off called out
// in the Phase 2.2 spec: we lose per-connection salt uniqueness but gain the
// ~100× speedup on reconnects.
func deriveSalt(password string) []byte {
	mac := hmac.New(sha256.New, []byte(saltDerivationContext))
	mac.Write([]byte(password))
	sum := mac.Sum(nil)
	out := make([]byte, derivedSaltLen)
	copy(out, sum[:derivedSaltLen])
	return out
}

// Get looks up stored credentials by (password, salt, iters). Returns
// (creds, true) on a fresh hit, or (_, false) on miss / expired entry.
// Expired entries are removed eagerly so subsequent Puts don't race against
// them.
func (c *SCRAMCache) Get(password string, salt []byte, iters int) (scram.StoredCredentials, bool) {
	key := scramCacheKey(password, salt, iters)
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.m[key]
	if !ok {
		c.miss.Add(1)
		return scram.StoredCredentials{}, false
	}
	entry := el.Value.(*scramEntry)
	if c.now().After(entry.expiresAt) {
		c.ll.Remove(el)
		delete(c.m, key)
		c.miss.Add(1)
		return scram.StoredCredentials{}, false
	}
	c.ll.MoveToFront(el)
	c.hits.Add(1)
	return entry.value, true
}

// Put stores stored credentials under (password, salt, iters). If the cache
// is at capacity the least-recently-used entry is evicted.
func (c *SCRAMCache) Put(password string, salt []byte, iters int, creds scram.StoredCredentials) {
	key := scramCacheKey(password, salt, iters)
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.m[key]; ok {
		entry := el.Value.(*scramEntry)
		entry.value = creds
		entry.expiresAt = c.now().Add(c.ttl)
		c.ll.MoveToFront(el)
		return
	}

	entry := &scramEntry{
		key:       key,
		value:     creds,
		expiresAt: c.now().Add(c.ttl),
	}
	el := c.ll.PushFront(entry)
	c.m[key] = el

	if c.ll.Len() > c.cap {
		oldest := c.ll.Back()
		if oldest != nil {
			c.ll.Remove(oldest)
			delete(c.m, oldest.Value.(*scramEntry).key)
			c.evic.Add(1)
		}
	}
}

// Len returns the current number of entries (including any not-yet-pruned
// expired ones). Useful for tests; not exposed as a metric.
func (c *SCRAMCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

// CachedSCRAMStoredCredentials computes or retrieves SCRAM-SHA-256 stored
// credentials for password. A nil cache falls back to a plain compute so
// callers don't need to special-case the "caching disabled" path. The salt is
// derived deterministically from password so repeated calls hit the cache;
// see deriveSalt for the security trade-off.
func CachedSCRAMStoredCredentials(c *SCRAMCache, password string, iters int) (scram.StoredCredentials, error) {
	if iters < 4096 {
		return scram.StoredCredentials{}, fmt.Errorf("SCRAM iters %d below RFC 5802 minimum", iters)
	}
	if c == nil {
		return SCRAMStoredCredentials(password, iters)
	}
	salt := deriveSalt(password)
	if creds, ok := c.Get(password, salt, iters); ok {
		return creds, nil
	}
	creds, err := scramStoredCredentialsWithSalt(password, salt, iters)
	if err != nil {
		return scram.StoredCredentials{}, err
	}
	c.Put(password, salt, iters, creds)
	return creds, nil
}

// scramStoredCredentialsWithSalt is the deterministic-salt counterpart to
// SCRAMStoredCredentials. Kept unexported because random-salt generation is
// the right default for fresh credential creation; deterministic salts only
// make sense inside the cache.
func scramStoredCredentialsWithSalt(password string, salt []byte, iters int) (scram.StoredCredentials, error) {
	saltedPassword, err := pbkdf2.Key(sha256.New, password, salt, iters, sha256.Size)
	if err != nil {
		return scram.StoredCredentials{}, fmt.Errorf("pbkdf2: %w", err)
	}

	clientKeyMAC := hmac.New(sha256.New, saltedPassword)
	clientKeyMAC.Write([]byte("Client Key"))
	clientKey := clientKeyMAC.Sum(nil)

	storedKeyHash := sha256.Sum256(clientKey)

	serverKeyMAC := hmac.New(sha256.New, saltedPassword)
	serverKeyMAC.Write([]byte("Server Key"))
	serverKey := serverKeyMAC.Sum(nil)

	return scram.StoredCredentials{
		KeyFactors: scram.KeyFactors{
			Salt:  string(salt),
			Iters: iters,
		},
		StoredKey: storedKeyHash[:],
		ServerKey: serverKey,
	}, nil
}
