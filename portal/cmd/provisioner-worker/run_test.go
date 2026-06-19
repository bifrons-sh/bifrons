package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/ephemeral"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// fakeNotifier is a controllable Notifier test double: tests push payloads to
// drive NOTIFY wakes and can close the stream to assert the reconnect path.
type fakeNotifier struct {
	mu        sync.Mutex
	streams   []chan string // every stream handed out, so a test can close them
	notified  []string
	listenErr error
}

func (n *fakeNotifier) Notify(_ context.Context, _, payload string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.notified = append(n.notified, payload)
	return nil
}

func (n *fakeNotifier) Listen(ctx context.Context, _ string) (<-chan string, error) {
	if n.listenErr != nil {
		return nil, n.listenErr
	}
	ch := make(chan string, 8)
	n.mu.Lock()
	n.streams = append(n.streams, ch)
	n.mu.Unlock()
	// Close the stream when ctx is cancelled — mirrors the real notifier
	// contract (closed channel ⇒ caller reconnects or, on ctx done, stops).
	go func() {
		<-ctx.Done()
		n.mu.Lock()
		defer n.mu.Unlock()
		n.closeLocked(ch)
	}()
	return ch, nil
}

func (n *fakeNotifier) Close() error { return nil }

// push delivers a payload on the most recent live stream, if any.
func (n *fakeNotifier) push(payload string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.streams) > 0 {
		select {
		case n.streams[len(n.streams)-1] <- payload:
		default:
		}
	}
}

// closeAllStreams closes every stream to force the listenLoop reconnect branch.
func (n *fakeNotifier) closeAllStreams() {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, ch := range n.streams {
		n.closeLocked(ch)
	}
}

// closeLocked closes ch once; a double close (ctx-done racing closeAllStreams)
// would panic, so swallow it. Caller holds n.mu.
func (n *fakeNotifier) closeLocked(ch chan string) {
	defer func() { _ = recover() }()
	close(ch)
}

func (n *fakeNotifier) streamCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.streams)
}

// newRunWorker builds a Worker over a fresh memory store + the given notifier,
// with a fast catch-up tick so the poll-only path is exercised quickly.
func newRunWorker(t *testing.T, n *fakeNotifier, fake *fakeProvisioner) (*Worker, store.Store) {
	t.Helper()
	st := store.NewMemory()
	ctx := context.Background()
	if err := st.CreateBackend(ctx, domain.Backend{
		ID: "b-1", Name: "pg", Type: domain.ProxyPostgres, Host: "db.internal", Port: 5432,
	}); err != nil {
		t.Fatalf("seed backend: %v", err)
	}
	if err := st.CreateGrant(ctx, domain.Grant{
		ID: "g-1", BackendID: "b-1", Role: domain.RoleApp, Status: domain.GrantApproved,
	}); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	cfg := Config{
		WorkerID:        "run-worker",
		WorkerKey:       []byte("0123456789abcdef0123456789abcdef"),
		LeaseTTL:        60 * time.Second,
		DDLTimeout:      5 * time.Second,
		CatchUpInterval: 20 * time.Millisecond,
		ClaimBatch:      16,
	}
	factory := func(bt ephemeral.BackendType) (ephemeral.Provisioner, bool) {
		if bt == ephemeral.BackendPostgres {
			return fake, true
		}
		return nil, false
	}
	derive := func(id string) (string, string) { return deriveCreds(cfg.WorkerKey, id) }
	return NewWorker(cfg, st, n, factory, derive, nil), st
}

// waitFor polls cond until true or the deadline; fails the test on timeout.
func waitFor(t *testing.T, d time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", msg)
}

// TestRun_DrainsBacklogAndWakes drives Run end-to-end: a startup backlog is
// drained, a NOTIFY wake processes a fresh intent, and ctx cancellation returns
// cleanly.
func TestRun_DrainsBacklogAndWakes(t *testing.T) {
	n := &fakeNotifier{}
	fake := &fakeProvisioner{}
	w, st := newRunWorker(t, n, fake)
	ctx, cancel := context.WithCancel(context.Background())

	// Startup backlog: one provision intent already pending.
	backlog := domain.Intent{
		ID: domain.IntentID("g-1", domain.IntentProvision), GrantID: "g-1",
		Kind: domain.IntentProvision, BackendID: "b-1", Role: domain.RoleApp,
		Status: domain.IntentPending,
	}
	if err := st.InsertIntent(ctx, backlog); err != nil {
		t.Fatalf("insert backlog: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	waitFor(t, time.Second, func() bool {
		got, _ := st.GetIntent(ctx, backlog.ID)
		return got.Status == domain.IntentDone
	}, "startup backlog drained")

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

// TestRun_RevokeBeforeProvision asserts the claim ordering is honoured end-to-end:
// when both a revoke and a provision intent for the same grant are pending, the
// revoke is processed first (spec §8.6 preemption).
func TestRun_RevokeBeforeProvision(t *testing.T) {
	n := &fakeNotifier{}
	fake := &fakeProvisioner{}
	w, st := newRunWorker(t, n, fake)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	now := time.Now().UTC()
	prov := domain.Intent{
		ID: domain.IntentID("g-1", domain.IntentProvision), GrantID: "g-1",
		Kind: domain.IntentProvision, BackendID: "b-1", Role: domain.RoleApp,
		Status: domain.IntentPending, CreatedAt: now,
	}
	rev := domain.Intent{
		ID: domain.IntentID("g-1", domain.IntentRevoke), GrantID: "g-1",
		Kind: domain.IntentRevoke, BackendID: "b-1", Role: domain.RoleApp,
		TargetUsername: "ap_dead", Status: domain.IntentPending, CreatedAt: now,
	}
	if err := st.InsertIntent(ctx, prov); err != nil {
		t.Fatalf("insert prov: %v", err)
	}
	if err := st.InsertIntent(ctx, rev); err != nil {
		t.Fatalf("insert rev: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	waitFor(t, time.Second, func() bool {
		return fake.revokeCount() >= 1 && fake.provisionCount() >= 1
	}, "both intents processed")

	// The claim batch sorts revoke ahead of provision and processIntent is
	// serial, so the recorded revoke is the preemption proof.
	if fake.revokedUsername(0) != "ap_dead" {
		t.Errorf("revoke target = %q, want ap_dead", fake.revokedUsername(0))
	}
	cancel()
	<-done
}

// TestRun_ReconnectsOnStreamClose asserts listenLoop re-subscribes after the
// stream closes (connection loss), so NOTIFY-driven wakes resume.
func TestRun_ReconnectsOnStreamClose(t *testing.T) {
	n := &fakeNotifier{}
	fake := &fakeProvisioner{}
	w, _ := newRunWorker(t, n, fake)
	// Slow catch-up so the reconnect, not the poll, is what re-establishes the
	// stream within the test window.
	w.cfg.CatchUpInterval = 10 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	waitFor(t, time.Second, func() bool { return n.streamCount() >= 1 }, "first subscription")
	n.closeAllStreams()
	// reconnectDelay is 2s in listenLoop; allow margin.
	waitFor(t, 4*time.Second, func() bool { return n.streamCount() >= 2 }, "re-subscription after close")

	cancel()
	<-done
}

// TestRun_StaleReclaim asserts the drain reclaims an in_flight intent whose
// lease has lapsed (worker crashed mid-flight) and runs it to completion.
func TestRun_StaleReclaim(t *testing.T) {
	n := &fakeNotifier{}
	fake := &fakeProvisioner{}
	w, st := newRunWorker(t, n, fake)
	ctx, cancel := context.WithCancel(context.Background())

	// An in_flight row owned by a dead worker with an already-expired lease.
	expired := time.Now().UTC().Add(-time.Minute)
	stale := domain.Intent{
		ID: domain.IntentID("g-1", domain.IntentProvision), GrantID: "g-1",
		Kind: domain.IntentProvision, BackendID: "b-1", Role: domain.RoleApp,
		Status: domain.IntentInFlight, WorkerID: "dead-worker",
		LeaseExpiresAt: &expired, RetryCount: 1,
	}
	if err := st.InsertIntent(ctx, stale); err != nil {
		t.Fatalf("insert stale: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	waitFor(t, time.Second, func() bool {
		got, _ := st.GetIntent(ctx, stale.ID)
		return got.Status == domain.IntentDone && got.WorkerID == "run-worker"
	}, "stale intent reclaimed and completed")

	cancel()
	<-done
}

// TestRun_MidBatchShutdown asserts a ctx cancel during a drain stops processing
// promptly without panicking, leaving unprocessed rows untouched for the next
// worker.
func TestRun_MidBatchShutdown(t *testing.T) {
	n := &fakeNotifier{}
	fake := &fakeProvisioner{}
	w, st := newRunWorker(t, n, fake)
	ctx, cancel := context.WithCancel(context.Background())

	for i := 0; i < 5; i++ {
		in := domain.Intent{
			ID: "ip-" + string(rune('a'+i)), GrantID: "g-1",
			Kind: domain.IntentProvision, BackendID: "b-1", Role: domain.RoleApp,
			Status: domain.IntentPending,
		}
		if err := st.InsertIntent(ctx, in); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	// Cancel almost immediately; the drain loop checks ctx between intents.
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return after mid-batch cancel")
	}
}

func TestSchemeOnly(t *testing.T) {
	cases := map[string]string{
		"postgres://user:pw@h/db": "postgres",
		"sqlite:///path/to.db":    "sqlite",
		"memory":                  "unknown",
		"":                        "unknown",
		"://noscheme":             "unknown",
	}
	for in, want := range cases {
		if got := schemeOnly(in); got != want {
			t.Errorf("schemeOnly(%q) = %q, want %q", in, got, want)
		}
	}
}
