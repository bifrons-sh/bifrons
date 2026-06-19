package provisioning

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/store"
)

func TestBuildIntentFreezesRoutingContext(t *testing.T) {
	const ttl = 90 * time.Minute
	g := domain.Grant{
		ID:                "g-abc",
		BackendID:         "b-1",
		Database:          "payments",
		Role:              domain.RoleApp,
		EphemeralUsername: "ap_deadbeef",
	}

	tests := []struct {
		name         string
		build        func(domain.Grant) domain.Intent
		wantKind     domain.IntentKind
		wantTarget   string
		wantDuration int
	}{
		{
			name: "provision freezes context + ttl, no target username",
			// ttl is supplied explicitly (the api passes h.credentialTTL); at
			// /claim the grant has no ExpiresAt yet, so the duration must come
			// from the param, not the grant.
			build:        func(g domain.Grant) domain.Intent { return ProvisionIntent(g, ttl) },
			wantKind:     domain.IntentProvision,
			wantTarget:   "", // worker derives the name on provision
			wantDuration: 90 * 60,
		},
		{
			name:         "revoke carries the ephemeral username to drop, no ttl",
			build:        RevokeIntent,
			wantKind:     domain.IntentRevoke,
			wantTarget:   "ap_deadbeef",
			wantDuration: 0, // revoke needs no TTL
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.build(g)

			if want := domain.IntentID(g.ID, tc.wantKind); in.ID != want {
				t.Errorf("ID = %q, want deterministic %q", in.ID, want)
			}
			if in.GrantID != g.ID {
				t.Errorf("GrantID = %q, want %q", in.GrantID, g.ID)
			}
			if in.Kind != tc.wantKind {
				t.Errorf("Kind = %q, want %q", in.Kind, tc.wantKind)
			}
			if in.BackendID != g.BackendID {
				t.Errorf("BackendID = %q, want %q", in.BackendID, g.BackendID)
			}
			if in.Database != g.Database {
				t.Errorf("Database = %q, want %q", in.Database, g.Database)
			}
			if in.Role != g.Role {
				t.Errorf("Role = %q, want %q", in.Role, g.Role)
			}
			if in.Status != domain.IntentPending {
				t.Errorf("Status = %q, want %q", in.Status, domain.IntentPending)
			}
			if in.TargetUsername != tc.wantTarget {
				t.Errorf("TargetUsername = %q, want %q", in.TargetUsername, tc.wantTarget)
			}
			if in.RequestedDurationSec != tc.wantDuration {
				t.Errorf("RequestedDurationSec = %d, want %d", in.RequestedDurationSec, tc.wantDuration)
			}
		})
	}
}

func TestProvisionIntentTTLFrozenFromParam(t *testing.T) {
	g := domain.Grant{ID: "g-x", BackendID: "b-1", Role: domain.RoleRO}
	// A non-positive ttl means "no explicit expiry" → zeroed, not invented.
	if got := ProvisionIntent(g, 0).RequestedDurationSec; got != 0 {
		t.Errorf("RequestedDurationSec = %d, want 0 for ttl<=0", got)
	}
	if got := ProvisionIntent(g, -time.Minute).RequestedDurationSec; got != 0 {
		t.Errorf("RequestedDurationSec = %d, want 0 for negative ttl", got)
	}
	// A positive ttl is frozen from the param (seconds), independent of the
	// grant's ExpiresAt (nil here, as it is at /claim time).
	if got := ProvisionIntent(g, 30*time.Minute).RequestedDurationSec; got != 30*60 {
		t.Errorf("RequestedDurationSec = %d, want %d frozen from ttl", got, 30*60)
	}
}

func TestValidateChannelRejectsBadIdentifiers(t *testing.T) {
	tests := []struct {
		channel string
		wantErr bool
	}{
		{"provision_intent", false},
		{"provision_result", false},
		{"_underscore_lead", false},
		{"a1_2_3", false},
		{"", true},
		{"Capitalised", true},       // postgres folds unquoted to lower-case
		{"has space", true},         // injection surface
		{"drop;table", true},        // injection surface
		{"with\"quote", true},       // injection surface
		{"name; NOTIFY evil", true}, // injection surface
		{"1leadingdigit", true},     // not a valid ident start
		{"trailing-dash", true},     // dash not allowed
	}
	for _, tc := range tests {
		t.Run(tc.channel, func(t *testing.T) {
			err := validateChannel(tc.channel)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateChannel(%q) err = %v, wantErr = %v", tc.channel, err, tc.wantErr)
			}
		})
	}
}

func TestWaitForResultReturnsImmediatelyOnDoneIntent(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemory()
	t.Cleanup(func() { _ = s.Close() })
	c := NewClient(s, &noopNotifier{}, nil)

	g := domain.Grant{ID: "g-done", BackendID: "b-1", Role: domain.RoleApp}
	in := ProvisionIntent(g, 0)
	if err := s.InsertIntent(ctx, in); err != nil {
		t.Fatalf("InsertIntent: %v", err)
	}
	// Simulate a fast worker that finished before we ever waited: claim then
	// complete the row so its status is terminal.
	const worker = "w-1"
	if _, err := s.ClaimPendingIntents(ctx, worker, nil, time.Minute, 10); err != nil {
		t.Fatalf("ClaimPendingIntents: %v", err)
	}
	if err := s.CompleteIntent(ctx, in.ID, worker, "ap_user", "secret"); err != nil {
		t.Fatalf("CompleteIntent: %v", err)
	}

	start := time.Now()
	got, err := c.WaitForResult(ctx, in.ID, 5*time.Second)
	if err != nil {
		t.Fatalf("WaitForResult: %v", err)
	}
	if got.Status != domain.IntentDone {
		t.Errorf("Status = %q, want %q", got.Status, domain.IntentDone)
	}
	// Must not have waited on the (5s) timeout for an already-terminal intent.
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("WaitForResult blocked %v on an already-done intent, want near-instant", elapsed)
	}
}

func TestWaitForResultTimesOutToPendingIntent(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemory()
	t.Cleanup(func() { _ = s.Close() })
	// noopNotifier => poll-only mode; no worker ever completes the row.
	c := NewClient(s, &noopNotifier{}, nil)

	g := domain.Grant{ID: "g-pending", BackendID: "b-1", Role: domain.RoleApp}
	in := ProvisionIntent(g, 0)
	if err := s.InsertIntent(ctx, in); err != nil {
		t.Fatalf("InsertIntent: %v", err)
	}

	got, err := c.WaitForResult(ctx, in.ID, 400*time.Millisecond)
	if err != nil {
		t.Fatalf("WaitForResult should return the pending intent (not an error) on timeout: %v", err)
	}
	if got.Status != domain.IntentPending {
		t.Errorf("Status = %q, want %q (caller maps to 202)", got.Status, domain.IntentPending)
	}
	if got.ID != in.ID {
		t.Errorf("ID = %q, want %q", got.ID, in.ID)
	}
}

func TestWaitForResultPropagatesCtxCancel(t *testing.T) {
	s := store.NewMemory()
	t.Cleanup(func() { _ = s.Close() })
	c := NewClient(s, &noopNotifier{}, nil)

	g := domain.Grant{ID: "g-cancel", BackendID: "b-1", Role: domain.RoleApp}
	in := ProvisionIntent(g, 0)
	if err := s.InsertIntent(context.Background(), in); err != nil {
		t.Fatalf("InsertIntent: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before waiting

	if _, err := c.WaitForResult(ctx, in.ID, time.Second); err == nil {
		t.Error("WaitForResult on a cancelled ctx should surface the ctx error")
	}
}

func TestEmitProvisionInsertsAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemory()
	t.Cleanup(func() { _ = s.Close() })
	c := NewClient(s, &noopNotifier{}, nil)

	g := domain.Grant{ID: "g-emit", BackendID: "b-1", Database: "db", Role: domain.RoleApp}

	first, err := c.EmitProvision(ctx, g, 0)
	if err != nil {
		t.Fatalf("EmitProvision: %v", err)
	}
	stored, err := s.GetIntent(ctx, first.ID)
	if err != nil {
		t.Fatalf("GetIntent after emit: %v", err)
	}
	if stored.GrantID != g.ID || stored.Kind != domain.IntentProvision {
		t.Errorf("stored intent = %+v, want grant %q kind provision", stored, g.ID)
	}
	// Re-emit must be a no-op success (ON CONFLICT DO NOTHING), not an error.
	if _, err := c.EmitProvision(ctx, g, 0); err != nil {
		t.Errorf("re-EmitProvision should be idempotent, got %v", err)
	}
}

// TestRetryProvisionResetsFailedIntent covers HIGH-2 producer-side: a failed
// provision intent is re-armed to pending so the worker can re-claim it.
func TestRetryProvisionResetsFailedIntent(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemory()
	t.Cleanup(func() { _ = s.Close() })
	c := NewClient(s, &noopNotifier{}, nil)

	g := domain.Grant{ID: "g-retry", BackendID: "b-1", Role: domain.RoleApp}
	in := ProvisionIntent(g, 0)
	if err := s.InsertIntent(ctx, in); err != nil {
		t.Fatalf("InsertIntent: %v", err)
	}
	// Drive it to failed via claim + fail.
	const worker = "w-1"
	if _, err := s.ClaimPendingIntents(ctx, worker, nil, time.Minute, 10); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := s.FailIntent(ctx, in.ID, worker, "transient_network", "blip", 3); err != nil {
		t.Fatalf("Fail: %v", err)
	}

	if err := c.RetryProvision(ctx, g, 0); err != nil {
		t.Fatalf("RetryProvision: %v", err)
	}
	got, err := s.GetIntent(ctx, in.ID)
	if err != nil {
		t.Fatalf("GetIntent: %v", err)
	}
	if got.Status != domain.IntentPending || got.RetryCount != 0 || got.ErrorClass != "" {
		t.Errorf("intent not re-armed: %+v", got)
	}
	// Retrying a non-failed (now pending) row surfaces the store's ErrNotFound.
	if err := c.RetryProvision(ctx, g, 0); err == nil {
		t.Error("RetryProvision on a non-failed intent should surface an error")
	}
}

// cancelTrackingNotifier is a noop-style notifier that exposes the context
// handed to Listen — so a test can assert Close() tears the listener's context
// down. listenCtx is published over a buffered channel because the listener now
// starts in its own goroutine (M5 single-flight), so the test must wait for it
// rather than read a field racily.
type cancelTrackingNotifier struct {
	gotCtx chan context.Context
}

func newCancelTrackingNotifier() *cancelTrackingNotifier {
	return &cancelTrackingNotifier{gotCtx: make(chan context.Context, 1)}
}

func (n *cancelTrackingNotifier) Notify(context.Context, string, string) error { return nil }

func (n *cancelTrackingNotifier) Listen(ctx context.Context, _ string) (<-chan string, error) {
	select {
	case n.gotCtx <- ctx:
	default:
	}
	out := make(chan string)
	go func() {
		defer close(out)
		<-ctx.Done()
	}()
	return out, nil
}

func (n *cancelTrackingNotifier) Close() error { return nil }

// TestClientCloseStopsListener covers MEDIUM-2: Close cancels the shared result
// listener's context (so its goroutine + connection don't leak) and is safe to
// call when never started and when called twice.
func TestClientCloseStopsListener(t *testing.T) {
	s := store.NewMemory()
	t.Cleanup(func() { _ = s.Close() })

	// Close on a Client that never started a listener must not panic.
	NewClient(s, &noopNotifier{}, nil).Close()

	n := newCancelTrackingNotifier()
	c := NewClient(s, n, nil)

	// Start the listener via a subscribe (the lazy-start path); the goroutine
	// publishes its ctx once Listen runs.
	c.subscribe(context.Background(), "ip-x")
	var listenCtx context.Context
	select {
	case listenCtx = <-n.gotCtx:
	case <-time.After(2 * time.Second):
		t.Fatal("listener never started")
	}
	if listenCtx.Err() != nil {
		t.Fatal("listener context cancelled before Close")
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Close cancels asynchronously w.r.t. the listener goroutine; wait for the
	// ctx to observe the cancellation.
	select {
	case <-listenCtx.Done():
	case <-time.After(2 * time.Second):
		t.Error("Close did not cancel the listener context")
	}
	// Idempotent: a second Close is a no-op, no panic.
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// fakeStream is one Listen subscription's stream plus a single-close guard, so
// the test (simulating conn loss) and the ctx-cancel path can't double-close it.
type fakeStream struct {
	ch   chan string
	once sync.Once
}

func (s *fakeStream) drop() { s.once.Do(func() { close(s.ch) }) }

// fakeStreamNotifier lets a test drive the result stream directly: it captures
// each subscription so the test can push a payload (simulating a pg NOTIFY) or
// drop it (simulating a conn loss), exercising the fast path without postgres.
// Notify is a no-op; the test injects via the stream.
type fakeStreamNotifier struct {
	streams chan *fakeStream // published once per Listen call
}

func newFakeStreamNotifier() *fakeStreamNotifier {
	return &fakeStreamNotifier{streams: make(chan *fakeStream, 4)}
}

func (n *fakeStreamNotifier) Notify(context.Context, string, string) error { return nil }

func (n *fakeStreamNotifier) Listen(ctx context.Context, _ string) (<-chan string, error) {
	s := &fakeStream{ch: make(chan string)}
	// Drop the stream on ctx cancel so the Client's listener loop exits cleanly
	// on Close, matching a real notifier's contract.
	go func() {
		<-ctx.Done()
		s.drop()
	}()
	n.streams <- s
	return s.ch, nil
}

func (n *fakeStreamNotifier) Close() error { return nil }

// TestWaitForResultWakesOnNotification covers M8(a): a parked WaitForResult must
// wake via the result NOTIFY fast path, NOT by falling through to the poll/timeout
// timer. We push the intent id into the Listen stream after the worker writes the
// terminal row, then assert WaitForResult returns well inside the (long) timeout.
func TestWaitForResultWakesOnNotification(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemory()
	t.Cleanup(func() { _ = s.Close() })
	n := newFakeStreamNotifier()
	c := NewClient(s, n, nil)
	t.Cleanup(func() { _ = c.Close() })

	g := domain.Grant{ID: "g-notify", BackendID: "b-1", Role: domain.RoleApp}
	in := ProvisionIntent(g, 0)
	if err := s.InsertIntent(ctx, in); err != nil {
		t.Fatalf("InsertIntent: %v", err)
	}

	// Grab the listener's stream (the lazy listener starts on first subscribe,
	// which WaitForResult does). We need it before we can push a notification.
	resultCh := make(chan domain.Intent, 1)
	go func() {
		// A multi-second timeout so a wakeup-via-timer would be obviously slower
		// than a wakeup-via-NOTIFY; the poll cadence is 200ms.
		got, err := c.WaitForResult(ctx, in.ID, 10*time.Second)
		if err != nil {
			t.Errorf("WaitForResult: %v", err)
		}
		resultCh <- got
	}()

	var stream *fakeStream
	select {
	case stream = <-n.streams:
	case <-time.After(2 * time.Second):
		t.Fatal("listener never subscribed")
	}

	// Worker completes the row, THEN we NOTIFY — the wake must trigger an
	// immediate re-read that observes the terminal status.
	const worker = "w-1"
	if _, err := s.ClaimPendingIntents(ctx, worker, nil, time.Minute, 10); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := s.CompleteIntent(ctx, in.ID, worker, "ap_user", "secret"); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	woke := time.Now()
	stream.ch <- in.ID // simulate pg NOTIFY on ChannelProvisionResult

	select {
	case got := <-resultCh:
		if got.Status != domain.IntentDone {
			t.Errorf("Status = %q, want %q", got.Status, domain.IntentDone)
		}
		// Woke via the notification, not the 10s timeout. Allow generous slack
		// for scheduler jitter but well under a poll interval's worst case.
		if d := time.Since(woke); d > 2*time.Second {
			t.Errorf("woke after %v, want near-instant via NOTIFY", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WaitForResult did not wake on the notification")
	}
}

// TestWaitForResultWakesOnStreamClose covers M4: when the listener's stream
// drops (conn loss), already-parked waiters must be woken so they re-read and
// either return (result landed) or re-park — never strand until a fresh
// subscribe. Here the result lands, then the stream closes; the waiter must
// observe the terminal row without waiting out the long timeout.
func TestWaitForResultWakesOnStreamClose(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemory()
	t.Cleanup(func() { _ = s.Close() })
	n := newFakeStreamNotifier()
	c := NewClient(s, n, nil)
	t.Cleanup(func() { _ = c.Close() })

	g := domain.Grant{ID: "g-drop", BackendID: "b-1", Role: domain.RoleApp}
	in := ProvisionIntent(g, 0)
	if err := s.InsertIntent(ctx, in); err != nil {
		t.Fatalf("InsertIntent: %v", err)
	}

	resultCh := make(chan domain.Intent, 1)
	go func() {
		got, err := c.WaitForResult(ctx, in.ID, 10*time.Second)
		if err != nil {
			t.Errorf("WaitForResult: %v", err)
		}
		resultCh <- got
	}()

	var stream *fakeStream
	select {
	case stream = <-n.streams:
	case <-time.After(2 * time.Second):
		t.Fatal("listener never subscribed")
	}

	const worker = "w-1"
	if _, err := s.ClaimPendingIntents(ctx, worker, nil, time.Minute, 10); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := s.CompleteIntent(ctx, in.ID, worker, "ap_user", "secret"); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	woke := time.Now()
	stream.drop() // simulate conn loss: listener wakes all parked waiters

	select {
	case got := <-resultCh:
		if got.Status != domain.IntentDone {
			t.Errorf("Status = %q, want %q", got.Status, domain.IntentDone)
		}
		if d := time.Since(woke); d > 2*time.Second {
			t.Errorf("woke after %v, want near-instant via stream-close wakeup", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WaitForResult was not woken by the stream close (M4)")
	}
}
