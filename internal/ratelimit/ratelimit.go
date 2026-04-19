// Package ratelimit implements a small, in-memory keyed token-bucket
// rate limiter used by the portal (per-IP / per-user on sensitive endpoints)
// and the proxy accept loop (pre-handshake DoS shield).
//
// Design choices:
//   - Token buckets, not leaky buckets: burst capacity is desirable (a legit
//     client occasionally firing three requests in quick succession must not
//     be penalised) while the steady-state refill rate enforces the budget.
//   - Keyed by arbitrary string (caller decides IP vs user). A TTL sweeper
//     evicts idle entries so a long-lived portal doesn't accumulate one
//     bucket per ever-seen IP.
//   - Clock is injectable to keep tests deterministic — the production path
//     uses the real wall clock, tests use a FakeClock that advances on demand.
//   - No third-party deps: golang.org/x/time/rate would work but would pull
//     an entire module for a sub-hundred-line primitive. Stdlib is enough.
package ratelimit

import (
	"sync"
	"time"
)

// Clock abstracts time.Now for tests. The zero-alloc production impl is
// realClock{}; fakes expose Advance to manipulate virtual time.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// FakeClock is a manually-advanceable clock used by the test suite.
// Safe for concurrent reads+Advance from multiple goroutines.
type FakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// NewFakeClock returns a FakeClock pinned to t.
func NewFakeClock(t time.Time) *FakeClock { return &FakeClock{now: t} }

// Now returns the current virtual time.
func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the virtual clock forward by d.
func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// Config tunes a Buckets set.
//
//	Rate  — tokens added per second (float for sub-hertz buckets; most callers
//	        pass burst/window — see PerMinute helper).
//	Burst — maximum tokens a bucket can hold; also the initial level.
//	TTL   — idle buckets evicted after this long; <=0 disables eviction (not
//	        recommended for unbounded key spaces like client IPs).
type Config struct {
	Rate  float64
	Burst int
	TTL   time.Duration
}

// PerMinute builds a Config that permits n events/minute with full burst.
// Convenience wrapper to keep call-sites readable: PerMinute(60) == 1/s.
func PerMinute(n int) Config {
	return Config{
		Rate:  float64(n) / 60.0,
		Burst: n,
		TTL:   10 * time.Minute,
	}
}

// bucket is the per-key state. Access is guarded by the parent Buckets mutex
// (sharding is not worth the complexity at 1k req/s — the spec target).
type bucket struct {
	tokens   float64
	last     time.Time
	lastSeen time.Time
}

// Buckets is a set of token buckets keyed by string. Zero value is not usable;
// construct via New.
type Buckets struct {
	cfg   Config
	clock Clock

	mu sync.Mutex
	m  map[string]*bucket
}

// New constructs a Buckets with the default (wall) clock.
func New(cfg Config) *Buckets {
	return NewWithClock(cfg, realClock{})
}

// NewWithClock is the test-friendly constructor. clock must be non-nil.
func NewWithClock(cfg Config, clock Clock) *Buckets {
	if clock == nil {
		clock = realClock{}
	}
	return &Buckets{cfg: cfg, clock: clock, m: make(map[string]*bucket)}
}

// Allow reports whether a single event against key fits inside its bucket
// budget. Side-effect: consumes one token on success, refills lazily on
// every call (O(1); no background goroutine needed for refill).
func (b *Buckets) Allow(key string) bool {
	if b.cfg.Burst <= 0 {
		// Disabled — degrade open. Operators explicitly opt out by zeroing the flag.
		return true
	}
	now := b.clock.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	bk, ok := b.m[key]
	if !ok {
		bk = &bucket{tokens: float64(b.cfg.Burst), last: now}
		b.m[key] = bk
	} else {
		// Lazy refill: add (elapsed * rate) tokens, capped at burst.
		elapsed := now.Sub(bk.last).Seconds()
		if elapsed > 0 {
			bk.tokens += elapsed * b.cfg.Rate
			if bk.tokens > float64(b.cfg.Burst) {
				bk.tokens = float64(b.cfg.Burst)
			}
			bk.last = now
		}
	}
	bk.lastSeen = now
	if bk.tokens >= 1 {
		bk.tokens -= 1
		return true
	}
	return false
}

// Sweep evicts buckets idle for longer than cfg.TTL. Cheap enough to call on
// a timer in the hot-key case (thousands of distinct IPs) — map iteration is
// the O(n) bit, but n is bounded by the unique-key rate across TTL.
// Returns the number of entries removed, primarily for tests.
func (b *Buckets) Sweep() int {
	if b.cfg.TTL <= 0 {
		return 0
	}
	cutoff := b.clock.Now().Add(-b.cfg.TTL)
	b.mu.Lock()
	defer b.mu.Unlock()
	removed := 0
	for k, bk := range b.m {
		if bk.lastSeen.Before(cutoff) {
			delete(b.m, k)
			removed++
		}
	}
	return removed
}

// Len returns the current bucket count. Tests use this to assert eviction.
func (b *Buckets) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.m)
}
