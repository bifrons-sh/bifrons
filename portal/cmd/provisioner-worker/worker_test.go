package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/ephemeral"
	"github.com/babs/poc-proxies/portal/internal/provisioning"
	"github.com/babs/poc-proxies/portal/internal/store"
)

func TestDeriveCreds_Deterministic(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	u1, p1 := deriveCreds(key, "ip-abc123")
	u2, p2 := deriveCreds(key, "ip-abc123")
	if u1 != u2 || p1 != p2 {
		t.Fatalf("not deterministic: (%q,%q) vs (%q,%q)", u1, p1, u2, p2)
	}
	if !strings.HasPrefix(u1, "ap_") || len(u1) != len("ap_")+16 {
		t.Errorf("username shape wrong: %q", u1)
	}
	if p1 == "" {
		t.Error("empty password")
	}
	// A different intent id yields a different credential.
	u3, p3 := deriveCreds(key, "ip-other")
	if u3 == u1 && p3 == p1 {
		t.Error("distinct intent ids produced identical creds")
	}
	// A different key yields a different credential for the same intent.
	uk, pk := deriveCreds([]byte("ffffffffffffffffffffffffffffffff"), "ip-abc123")
	if uk == u1 && pk == p1 {
		t.Error("distinct keys produced identical creds")
	}
}

// fakeProvisioner records calls and can be told to fail. It is mutex-guarded so
// the Run-driven tests (worker goroutine writes, test goroutine reads) are
// race-clean under -race.
type fakeProvisioner struct {
	mu          sync.Mutex
	provisioned []ephemeral.ProvisionRequest
	revoked     []ephemeral.ProvisionedAccount
	provErr     error
	revokeErr   error
}

func (f *fakeProvisioner) Provision(_ context.Context, req ephemeral.ProvisionRequest) (ephemeral.ProvisionedAccount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.provisioned = append(f.provisioned, req)
	if f.provErr != nil {
		return ephemeral.ProvisionedAccount{}, f.provErr
	}
	return ephemeral.ProvisionedAccount{Username: req.Username, Password: req.Password}, nil
}

func (f *fakeProvisioner) Revoke(_ context.Context, acct ephemeral.ProvisionedAccount) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, acct)
	return f.revokeErr
}

// provisionCount / revokeCount / revokedAt give race-safe read access for the
// Run tests.
func (f *fakeProvisioner) provisionCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.provisioned)
}

func (f *fakeProvisioner) revokeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.revoked)
}

func (f *fakeProvisioner) revokedUsername(i int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.revoked[i].Username
}

// newTestWorker seeds a memory store with a backend + grant and returns a Worker
// wired to a fake provisioner + noop notifier. The 32-byte worker key is fixed.
func newTestWorker(t *testing.T, fake *fakeProvisioner) (*Worker, store.Store) {
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
	cfg := Config{WorkerID: "test-worker", WorkerKey: []byte("0123456789abcdef0123456789abcdef"), LeaseTTL: 60 * time.Second}
	factory := func(bt ephemeral.BackendType) (ephemeral.Provisioner, bool) {
		if bt == ephemeral.BackendPostgres {
			return fake, true
		}
		return nil, false
	}
	derive := func(id string) (string, string) { return deriveCreds(cfg.WorkerKey, id) }
	noop, _ := provisioning.NewNotifier(ctx, "memory", nil)
	return NewWorker(cfg, st, noop, factory, derive, nil), st
}

func TestProcessIntent_ProvisionHappyPath(t *testing.T) {
	fake := &fakeProvisioner{}
	w, st := newTestWorker(t, fake)
	ctx := context.Background()

	intent := domain.Intent{
		ID: domain.IntentID("g-1", domain.IntentProvision), GrantID: "g-1",
		Kind: domain.IntentProvision, BackendID: "b-1", Role: domain.RoleApp,
		Status: domain.IntentInFlight, WorkerID: "test-worker",
	}
	if err := st.InsertIntent(ctx, intent); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := w.processIntent(ctx, intent); err != nil {
		t.Fatalf("processIntent: %v", err)
	}

	wantUser, wantPass := deriveCreds(w.cfg.WorkerKey, intent.ID)
	if len(fake.provisioned) != 1 {
		t.Fatalf("want 1 provision call, got %d", len(fake.provisioned))
	}
	req := fake.provisioned[0]
	if req.Username != wantUser || req.Password != wantPass {
		t.Errorf("provision did not use deterministic creds: %q/%q", req.Username, req.Password)
	}
	if req.Host != "db.internal" || req.Port != 5432 {
		t.Errorf("backend host/port not resolved: %q:%d", req.Host, req.Port)
	}

	got, err := st.GetIntent(ctx, intent.ID)
	if err != nil {
		t.Fatalf("get intent: %v", err)
	}
	if got.Status != domain.IntentDone {
		t.Errorf("status = %q, want done", got.Status)
	}
	if got.ResultUsername != wantUser || got.ResultPassword != wantPass {
		t.Errorf("stored result creds = %q/%q, want %q/%q", got.ResultUsername, got.ResultPassword, wantUser, wantPass)
	}
}

func TestProcessIntent_RevokeHappyPath(t *testing.T) {
	fake := &fakeProvisioner{}
	w, st := newTestWorker(t, fake)
	ctx := context.Background()

	intent := domain.Intent{
		ID: domain.IntentID("g-1", domain.IntentRevoke), GrantID: "g-1",
		Kind: domain.IntentRevoke, BackendID: "b-1", Role: domain.RoleApp,
		TargetUsername: "ap_dead", Status: domain.IntentInFlight, WorkerID: "test-worker",
	}
	if err := st.InsertIntent(ctx, intent); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := w.processIntent(ctx, intent); err != nil {
		t.Fatalf("processIntent: %v", err)
	}
	if len(fake.revoked) != 1 {
		t.Fatalf("want 1 revoke call, got %d", len(fake.revoked))
	}
	if fake.revoked[0].Username != "ap_dead" {
		t.Errorf("revoke target = %q, want ap_dead", fake.revoked[0].Username)
	}
	got, err := st.GetIntent(ctx, intent.ID)
	if err != nil {
		t.Fatalf("get intent: %v", err)
	}
	if got.Status != domain.IntentDone {
		t.Errorf("status = %q, want done", got.Status)
	}
	if got.ResultUsername != "" || got.ResultPassword != "" {
		t.Errorf("revoke must leave result creds empty, got %q/%q", got.ResultUsername, got.ResultPassword)
	}
}

// TestProcessIntent_RevokeDerivesSiblingUsername covers HIGH-1: a revoke intent
// with an empty TargetUsername (grant revoked while provision was still in flight,
// so no creds were ever recorded) must DROP the sibling provision intent's
// deterministically-derived username — not a no-op.
func TestProcessIntent_RevokeDerivesSiblingUsername(t *testing.T) {
	fake := &fakeProvisioner{}
	w, st := newTestWorker(t, fake)
	ctx := context.Background()

	intent := domain.Intent{
		ID: domain.IntentID("g-1", domain.IntentRevoke), GrantID: "g-1",
		Kind: domain.IntentRevoke, BackendID: "b-1", Role: domain.RoleApp,
		TargetUsername: "", // no creds recorded — derive from sibling provision id
		Status:         domain.IntentInFlight, WorkerID: "test-worker",
	}
	if err := st.InsertIntent(ctx, intent); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := w.processIntent(ctx, intent); err != nil {
		t.Fatalf("processIntent: %v", err)
	}
	if len(fake.revoked) != 1 {
		t.Fatalf("want 1 revoke call, got %d", len(fake.revoked))
	}
	// The dropped name must equal what runProvision would have created for the
	// sibling provision intent of the same grant.
	wantUser, _ := deriveCreds(w.cfg.WorkerKey, domain.IntentID("g-1", domain.IntentProvision))
	if fake.revoked[0].Username != wantUser {
		t.Errorf("revoke target = %q, want sibling-derived %q", fake.revoked[0].Username, wantUser)
	}
	if got, _ := st.GetIntent(ctx, intent.ID); got.Status != domain.IntentDone {
		t.Errorf("status = %q, want done", got.Status)
	}
}

// TestProcessIntent_RevokeWinsRace covers H3 (spec §8.6): a grant that reached a
// terminal state (REVOKED) while a provision intent was still in flight must NOT
// create the backend user. The provision is skipped and completed with empty
// result creds so no orphan ap_<hmac> account is left behind.
func TestProcessIntent_RevokeWinsRace(t *testing.T) {
	fake := &fakeProvisioner{}
	w, st := newTestWorker(t, fake)
	ctx := context.Background()

	// Flip the seeded grant to REVOKED — simulating a revoke that landed after
	// the provision intent was claimed but before its CREATE ran.
	g, err := st.GetGrant(ctx, "g-1")
	if err != nil {
		t.Fatalf("get grant: %v", err)
	}
	g.Status = domain.GrantRevoked
	if err := st.UpdateGrant(ctx, g); err != nil {
		t.Fatalf("revoke grant: %v", err)
	}

	intent := domain.Intent{
		ID: domain.IntentID("g-1", domain.IntentProvision), GrantID: "g-1",
		Kind: domain.IntentProvision, BackendID: "b-1", Role: domain.RoleApp,
		Status: domain.IntentInFlight, WorkerID: "test-worker",
	}
	if err := st.InsertIntent(ctx, intent); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := w.processIntent(ctx, intent); err != nil {
		t.Fatalf("processIntent: %v", err)
	}
	if len(fake.provisioned) != 0 {
		t.Errorf("provision ran despite terminal grant: %d calls", len(fake.provisioned))
	}
	got, err := st.GetIntent(ctx, intent.ID)
	if err != nil {
		t.Fatalf("get intent: %v", err)
	}
	if got.Status != domain.IntentDone {
		t.Errorf("status = %q, want done (superseded)", got.Status)
	}
	if got.ResultUsername != "" || got.ResultPassword != "" {
		t.Errorf("superseded provision must leave creds empty, got %q/%q", got.ResultUsername, got.ResultPassword)
	}
}

func TestProcessIntent_TerminalError(t *testing.T) {
	fake := &fakeProvisioner{provErr: errors.New("permission denied for role app")}
	w, st := newTestWorker(t, fake)
	ctx := context.Background()

	intent := domain.Intent{
		ID: domain.IntentID("g-1", domain.IntentProvision), GrantID: "g-1",
		Kind: domain.IntentProvision, BackendID: "b-1", Role: domain.RoleApp,
		Status: domain.IntentInFlight, WorkerID: "test-worker",
	}
	if err := st.InsertIntent(ctx, intent); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := w.processIntent(ctx, intent); err == nil {
		t.Fatal("expected error on terminal failure")
	}
	got, err := st.GetIntent(ctx, intent.ID)
	if err != nil {
		t.Fatalf("get intent: %v", err)
	}
	if got.Status != domain.IntentFailed {
		t.Errorf("status = %q, want failed", got.Status)
	}
	if got.ErrorClass != classTerminalPermission {
		t.Errorf("error_class = %q, want %q", got.ErrorClass, classTerminalPermission)
	}
	// Terminal error must not retry.
	if len(fake.provisioned) != 1 {
		t.Errorf("terminal error retried: %d calls", len(fake.provisioned))
	}
	// error_detail hygiene: single line, ≤120 chars.
	if strings.ContainsAny(got.ErrorDetail, "\n\r") || len(got.ErrorDetail) > 120 {
		t.Errorf("error_detail violates hygiene: %q", got.ErrorDetail)
	}
}

func TestProcessIntent_UnknownBackend(t *testing.T) {
	fake := &fakeProvisioner{}
	w, st := newTestWorker(t, fake)
	ctx := context.Background()

	intent := domain.Intent{
		ID: "ip-orphan", GrantID: "g-1", Kind: domain.IntentProvision,
		BackendID: "b-missing", Role: domain.RoleApp,
		Status: domain.IntentInFlight, WorkerID: "test-worker",
	}
	if err := st.InsertIntent(ctx, intent); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := w.processIntent(ctx, intent); err == nil {
		t.Fatal("expected error for missing backend")
	}
	got, _ := st.GetIntent(ctx, intent.ID)
	if got.ErrorClass != classTerminalIntentInval {
		t.Errorf("error_class = %q, want %q", got.ErrorClass, classTerminalIntentInval)
	}
}

func TestRedactDetail(t *testing.T) {
	cases := []struct {
		in   string
		want func(string) bool
	}{
		{"line one\nline two", func(s string) bool { return !strings.Contains(s, "\n") }},
		{"CREATE ROLE foo failed", func(s string) bool { return !strings.Contains(strings.ToUpper(s), "CREATE") }},
		{strings.Repeat("x", 300), func(s string) bool { return len(s) <= 120 }},
	}
	for _, c := range cases {
		got := redactDetail(errors.New(c.in))
		if !c.want(got) {
			t.Errorf("redactDetail(%q) = %q failed hygiene", c.in, got)
		}
	}
}
