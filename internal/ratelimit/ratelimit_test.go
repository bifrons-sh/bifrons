package ratelimit

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAllow_Table drives the core Allow decision matrix: burst fill, steady-
// state replenishment across a fake clock, and TTL eviction of idle keys.
func TestAllow_Table(t *testing.T) {
	type step struct {
		advance time.Duration
		key     string
		want    bool // Allow's expected return
	}
	cases := []struct {
		name  string
		cfg   Config
		steps []step
	}{
		{
			name: "burst fills then denies",
			cfg:  Config{Rate: 1.0, Burst: 3, TTL: time.Minute},
			steps: []step{
				{0, "a", true},
				{0, "a", true},
				{0, "a", true},
				{0, "a", false}, // burst exhausted
			},
		},
		{
			name: "replenish restores one token per rate window",
			cfg:  Config{Rate: 1.0, Burst: 2, TTL: time.Minute},
			steps: []step{
				{0, "a", true},
				{0, "a", true},
				{0, "a", false},           // empty
				{time.Second, "a", true},  // +1 token
				{0, "a", false},           // drained again
				{2 * time.Second, "a", true}, // +2 but cap at burst=2
				{0, "a", true},
				{0, "a", false},
			},
		},
		{
			name: "independent keys do not share budget",
			cfg:  Config{Rate: 1.0, Burst: 1, TTL: time.Minute},
			steps: []step{
				{0, "alice", true},
				{0, "alice", false},
				{0, "bob", true}, // different key, own bucket
				{0, "bob", false},
			},
		},
		{
			name: "zero burst degrades open",
			cfg:  Config{Rate: 0, Burst: 0, TTL: 0},
			steps: []step{
				{0, "x", true},
				{0, "x", true},
				{0, "x", true},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fc := NewFakeClock(time.Unix(0, 0))
			b := NewWithClock(tc.cfg, fc)
			for i, s := range tc.steps {
				if s.advance > 0 {
					fc.Advance(s.advance)
				}
				got := b.Allow(s.key)
				if got != s.want {
					t.Fatalf("step %d: Allow(%q)=%v want %v", i, s.key, got, s.want)
				}
			}
		})
	}
}

// TestSweep_EvictsIdleKeys verifies the TTL sweep drops buckets that haven't
// been touched within cfg.TTL — the whole point of a TTL: unbounded key spaces
// (client IPs) must not leak memory.
func TestSweep_EvictsIdleKeys(t *testing.T) {
	fc := NewFakeClock(time.Unix(0, 0))
	b := NewWithClock(Config{Rate: 1, Burst: 2, TTL: time.Minute}, fc)

	b.Allow("stale")
	b.Allow("fresh")
	if got := b.Len(); got != 2 {
		t.Fatalf("Len=%d want 2", got)
	}

	// Advance past TTL for "stale", touch "fresh" to reset its lastSeen.
	fc.Advance(30 * time.Second)
	b.Allow("fresh")
	fc.Advance(45 * time.Second) // total: stale=75s idle, fresh=45s idle

	removed := b.Sweep()
	if removed != 1 {
		t.Fatalf("Sweep removed %d want 1", removed)
	}
	if got := b.Len(); got != 1 {
		t.Fatalf("Len after sweep=%d want 1", got)
	}
}

// TestSweep_DisabledWhenTTLZero — an operator setting TTL=0 accepts unbounded
// growth in exchange for a trivially simpler model (e.g. a known fixed user set).
// Sweep must no-op in that configuration.
func TestSweep_DisabledWhenTTLZero(t *testing.T) {
	fc := NewFakeClock(time.Unix(0, 0))
	b := NewWithClock(Config{Rate: 1, Burst: 2, TTL: 0}, fc)
	b.Allow("a")
	fc.Advance(24 * time.Hour)
	if removed := b.Sweep(); removed != 0 {
		t.Fatalf("Sweep=%d want 0 (disabled)", removed)
	}
}

// TestPerMinute sanity-checks the helper: 60/min = 1/s sustained.
func TestPerMinute(t *testing.T) {
	cfg := PerMinute(60)
	if cfg.Burst != 60 {
		t.Errorf("Burst=%d want 60", cfg.Burst)
	}
	if cfg.Rate < 0.99 || cfg.Rate > 1.01 {
		t.Errorf("Rate=%f want ~1.0", cfg.Rate)
	}
	if cfg.TTL <= 0 {
		t.Errorf("TTL=%v want >0", cfg.TTL)
	}
}

// TestConcurrentHammer stress-tests the limiter under -race with 1k req/s
// equivalent: 64 goroutines each firing 500 Allow calls against random keys.
// Spec target: "no lock contention visible". We don't assert latency directly
// (env-dependent) but we do assert correctness — exactly burst tokens must be
// consumed when a single key is hammered by all goroutines in parallel.
func TestConcurrentHammer(t *testing.T) {
	const (
		goroutines = 64
		iters      = 500
		burst      = 100
	)
	b := New(Config{Rate: 0, Burst: burst, TTL: time.Minute}) // rate=0 isolates the burst

	var allowed atomic.Int64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				if b.Allow("single-key") {
					allowed.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	if got := allowed.Load(); got != int64(burst) {
		t.Fatalf("allowed=%d want exactly %d (burst) under concurrent hammer", got, burst)
	}
}

// TestConcurrentHammer_DistinctKeys proves no contention across keys: every
// request against a unique key is allowed (burst never depleted), and the map
// ends up with exactly N entries.
func TestConcurrentHammer_DistinctKeys(t *testing.T) {
	const goroutines = 64
	b := New(Config{Rate: 1, Burst: 1, TTL: time.Minute})
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		key := "k-" + itoa(g)
		go func(k string) {
			defer wg.Done()
			if !b.Allow(k) {
				t.Errorf("first Allow(%q) must succeed", k)
			}
		}(key)
	}
	wg.Wait()
	if got := b.Len(); got != goroutines {
		t.Errorf("Len=%d want %d", got, goroutines)
	}
}

// itoa — avoid pulling strconv into a test file purely for label-building.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
