package notify

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/entra"
)

func newMailEvent() Event {
	return Event{
		User:    domain.User{Username: "alice", DisplayName: "Alice"},
		Backend: domain.Backend{Host: "h", Port: 5432, Name: "pg-prod"},
		Grant: domain.Grant{
			ID: "g-1", Role: domain.RoleApp, Reason: "ticket-42",
			ApproverHint: "bob@example.com", T1ApprovedBy: "sub-bob",
			RequestedBy: "sub-alice",
			RequestedAt: time.Now().UTC(),
			BackendID:   "b-1",
		},
	}
}

func waitForSent(t *testing.T, fc *entra.FakeClient, want int) []entra.SentMail {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s := fc.SentSnapshot()
		if len(s) >= want {
			return s
		}
		time.Sleep(5 * time.Millisecond)
	}
	return fc.SentSnapshot()
}

// TestEntraMail_NilWhenUnconfigured: a missing client or sender returns nil
// so the router's fan-out wiring can pass the builder through unconditionally.
func TestEntraMail_NilWhenUnconfigured(t *testing.T) {
	if NewEntraMailNotifier(EntraConfig{Sender: "x@y"}) != nil {
		t.Error("nil client should return nil notifier")
	}
	if NewEntraMailNotifier(EntraConfig{Client: entra.NewFakeClient()}) != nil {
		t.Error("empty sender should return nil notifier")
	}
}

// TestEntraMail_OnGrantCreated: the validator email is dispatched to the
// ApproverHint, the per-kind counter increments, and the portal link appears
// when PublicURL is set.
func TestEntraMail_OnGrantCreated(t *testing.T) {
	fc := entra.NewFakeClient()
	m := NewEntraMetrics()
	n := NewEntraMailNotifier(EntraConfig{
		Client: fc, Sender: "noreply@x", PublicURL: "https://p.example",
		Metrics: m, Logger: silentLogger(),
	})
	if n == nil {
		t.Fatal("notifier nil")
	}
	if err := n.OnGrantCreated(context.Background(), newMailEvent()); err != nil {
		t.Fatal(err)
	}
	n.Wait()

	sent := waitForSent(t, fc, 1)
	if len(sent) != 1 {
		t.Fatalf("sent=%d want 1", len(sent))
	}
	msg := sent[0]
	if len(msg.Message.To) != 1 || msg.Message.To[0] != "bob@example.com" {
		t.Errorf("To=%v", msg.Message.To)
	}
	if !strings.Contains(msg.Message.TextBody, "Alice requested app access on pg-prod") {
		t.Errorf("body missing template text: %q", msg.Message.TextBody)
	}
	if !strings.Contains(msg.Message.TextBody, "https://p.example/ui/grants/g-1") {
		t.Errorf("body missing link: %q", msg.Message.TextBody)
	}
	if val, _, _ := m.SnapshotByKind(); val != 1 {
		t.Errorf("validator counter=%d want 1", val)
	}
}

// TestEntraMail_SkipCreateWithEmptyApprover: without an ApproverHint the
// validator-request mail is skipped (the portal couldn't resolve a recipient).
func TestEntraMail_SkipCreateWithEmptyApprover(t *testing.T) {
	fc := entra.NewFakeClient()
	n := NewEntraMailNotifier(EntraConfig{Client: fc, Sender: "x@y", Logger: silentLogger()})
	e := newMailEvent()
	e.Grant.ApproverHint = ""
	if err := n.OnGrantCreated(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	n.Wait()
	if got := len(fc.SentSnapshot()); got != 0 {
		t.Errorf("sent=%d want 0", got)
	}
}

// TestEntraMail_OnValidatorApproved_UsesT2Mailbox: the T2-mailbox fallback
// feeds the recipient list; the kind counter bumps admin_request.
func TestEntraMail_OnValidatorApproved_UsesT2Mailbox(t *testing.T) {
	fc := entra.NewFakeClient()
	m := NewEntraMetrics()
	n := NewEntraMailNotifier(EntraConfig{
		Client: fc, Sender: "x@y", T2Mailbox: "admins@example.com",
		Metrics: m, Logger: silentLogger(),
	})
	_ = n.OnValidatorApproved(context.Background(), newMailEvent())
	n.Wait()
	sent := waitForSent(t, fc, 1)
	if len(sent) != 1 || sent[0].Message.To[0] != "admins@example.com" {
		t.Fatalf("sent=%+v", sent)
	}
	if _, admin, _ := m.SnapshotByKind(); admin != 1 {
		t.Errorf("admin counter=%d want 1", admin)
	}
}

// TestEntraMail_T2GroupResolution: with a T2Lookup the recipients come
// from the lookup (stubbed here), deduped and merged with T2Mailbox.
// In production the lookup is wired to store.ListGroupMembers; this test
// stays decoupled from the store layer.
func TestEntraMail_T2GroupResolution(t *testing.T) {
	fc := entra.NewFakeClient()
	n := NewEntraMailNotifier(EntraConfig{
		Client: fc, Sender: "x@y",
		T2Mailbox: "admins@example.com",
		T2Lookup: func(context.Context, domain.Backend) ([]string, error) {
			return []string{"admin1@example.com", "admin2@example.com", "admins@example.com"}, nil
		},
		Logger: silentLogger(),
	})
	_ = n.OnValidatorApproved(context.Background(), newMailEvent())
	n.Wait()
	sent := waitForSent(t, fc, 1)
	if len(sent) != 1 {
		t.Fatalf("sent=%d want 1", len(sent))
	}
	to := sent[0].Message.To
	if len(to) != 3 {
		t.Errorf("want 3 dedup'd recipients, got %d: %v", len(to), to)
	}
	// Dedup is case-insensitive; the mailbox appears only once.
	var count int
	for _, addr := range to {
		if strings.EqualFold(addr, "admins@example.com") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("duplicate dedup failed: %v", to)
	}
}

// TestEntraMail_OnApproved_AndDenied: the outcome mail goes to the requester;
// separate kinds still route through the same outcome counter.
func TestEntraMail_OnApproved_AndDenied(t *testing.T) {
	fc := entra.NewFakeClient()
	fc.UsersByID = map[string]entra.User{
		"sub-alice": {Mail: "alice@example.com"},
	}
	m := NewEntraMetrics()
	n := NewEntraMailNotifier(EntraConfig{
		Client: fc, Sender: "x@y", Metrics: m, Logger: silentLogger(),
	})
	_ = n.OnApproved(context.Background(), newMailEvent())
	_ = n.OnDenied(context.Background(), newMailEvent())
	n.Wait()

	sent := waitForSent(t, fc, 2)
	if len(sent) != 2 {
		t.Fatalf("sent=%d want 2 (approved + denied)", len(sent))
	}
	for _, s := range sent {
		if s.Message.To[0] != "alice@example.com" {
			t.Errorf("outcome To=%v want alice@example.com", s.Message.To)
		}
	}
	if _, _, outcome := m.SnapshotByKind(); outcome != 2 {
		t.Errorf("outcome counter=%d want 2", outcome)
	}
}

// TestEntraMail_FailedSend_BumpsFailureCounter: a SendMail error must flow
// through to the failure counter without surfacing back to the caller.
func TestEntraMail_FailedSend_BumpsFailureCounter(t *testing.T) {
	fc := entra.NewFakeClient()
	fc.SendErr = errors.New("transient")
	m := NewEntraMetrics()
	n := NewEntraMailNotifier(EntraConfig{
		Client: fc, Sender: "x@y", Metrics: m, Logger: silentLogger(),
	})
	if err := n.OnGrantCreated(context.Background(), newMailEvent()); err != nil {
		t.Errorf("OnGrantCreated should not surface delivery errors, got %v", err)
	}
	n.Wait()
	_, failed, _, _ := m.Snapshot()
	if failed != 1 {
		t.Errorf("failed counter=%d want 1", failed)
	}
}

// TestEntraMetrics_IncHelpers: the counter-increment helpers the handler
// uses directly must map to the right slots.
func TestEntraMetrics_IncHelpers(t *testing.T) {
	m := NewEntraMetrics()
	m.IncPolicyRejected()
	m.IncPolicyRejected()
	m.IncValidatorLookupFailed()
	_, _, rejected, valFail := m.Snapshot()
	if rejected != 2 || valFail != 1 {
		t.Errorf("snapshot: rejected=%d valFail=%d", rejected, valFail)
	}
	// Nil receiver must be a safe no-op so handler paths don't need to guard.
	var nilM *EntraMetrics
	nilM.IncPolicyRejected()
	nilM.IncValidatorLookupFailed()
	if sent, failed, rej, mf := nilM.Snapshot(); sent != 0 || failed != 0 || rej != 0 || mf != 0 {
		t.Errorf("nil snapshot must be zeros, got %d %d %d %d", sent, failed, rej, mf)
	}
}
