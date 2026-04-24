package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/babs/poc-proxies/portal/internal/config"
	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/ephemeral"
	"github.com/babs/poc-proxies/portal/internal/policy"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// mockProvisioner implements ephemeral.Provisioner with controllable outcomes
// and records every call so tests can assert the hook fired.
type mockProvisioner struct {
	mu             sync.Mutex
	provisionCalls int
	revokeCalls    int
	provisionErr   error
	revokeErr      error
	acct           ephemeral.ProvisionedAccount
}

func (m *mockProvisioner) Provision(_ context.Context, req ephemeral.ProvisionRequest) (ephemeral.ProvisionedAccount, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.provisionCalls++
	if m.provisionErr != nil {
		return ephemeral.ProvisionedAccount{}, m.provisionErr
	}
	acct := ephemeral.ProvisionedAccount{
		Username:    "portal_grant_test",
		Password:    "hex-pw",
		BackendID:   req.BackendID,
		BackendType: req.BackendType,
		Host:        req.Host,
		Port:        req.Port,
		Database:    req.Database,
		GrantID:     req.GrantID,
		CreatedAt:   time.Now().UTC(),
	}
	m.acct = acct
	return acct, nil
}

func (m *mockProvisioner) Revoke(_ context.Context, _ ephemeral.ProvisionedAccount) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revokeCalls++
	return m.revokeErr
}

func (m *mockProvisioner) ProvisionCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.provisionCalls
}

func (m *mockProvisioner) RevokeCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.revokeCalls
}

// newEphemeralPortal returns a test portal with the ephemeral manager wired.
// mock is the Provisioner for Mongo (the test backend type); other backends
// are unbound.
func newEphemeralPortal(t *testing.T, cfg *config.Config, mock ephemeral.Provisioner) (*httptest.Server, store.Store, *ephemeral.Manager) {
	t.Helper()
	s := store.NewMemory()
	mgr := ephemeral.NewManager(map[ephemeral.BackendType]ephemeral.Provisioner{
		ephemeral.BackendMongo: mock,
	}, ephemeral.NewMetrics(), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	eng := policy.New(s)
	h := NewRouter(cfg, s, eng, slog.New(slog.NewJSONHandler(io.Discard, nil)), WithEphemeralManager(mgr))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, s, mgr
}

func seedEphemeralGrant(t *testing.T, s store.Store) (domain.User, domain.Backend, domain.Grant) {
	t.Helper()
	ctx := context.Background()
	u := domain.User{ID: "u-eph", Username: "alice", Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	// dual_or so the static-bearer test path can clear approval in a single
	// call (four-eyes guard in dual_strict rejects same-actor double-approve;
	// these tests focus on /claim semantics, not the workflow modes).
	b := domain.Backend{ID: "b-eph", Name: "mongo", Type: domain.ProxyMongo, Host: "127.0.0.1", Port: 27017,
		ApprovalMode: domain.ApprovalDualOr}
	if err := s.CreateBackend(ctx, b); err != nil {
		t.Fatal(err)
	}
	// DBA account present so the provisioner isn't short-circuited to
	// ErrNoDBACredential on the backend.
	if err := s.UpsertBackendAccount(ctx, domain.BackendAccount{
		ID: "ba-dba", BackendID: b.ID, Role: domain.RoleDBA, Username: "root", Password: "rootpw",
	}); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)
	g := domain.Grant{
		ID: "g-eph", UserID: u.ID, BackendID: b.ID, Status: domain.GrantPending,
		Role: domain.RoleApp, Database: "orders", PortalPassword: "p-pw",
		// PolicyMode=ephemeral so /claim triggers the provisioner. With no
		// Entra wired, create() leaves PolicyMode empty (defaults permanent),
		// so seeding directly here is the only way to exercise ephemeral.
		PolicyMode:  policy.ModeEphemeral,
		RequestedAt: time.Now(), ExpiresAt: &exp, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateGrant(ctx, g); err != nil {
		t.Fatal(err)
	}
	return u, b, g
}

// approveAndClaim walks PENDING → VALIDATOR_APPROVED → APPROVED → ACTIVE via
// /approve (twice) and /claim. Static-bearer covers both gates so tests stay
// session-free.
func approveAndClaim(t *testing.T, srv *httptest.Server, id string) (claimResp *http.Response) {
	t.Helper()
	hdrs := map[string]string{"Authorization": "Bearer api-tok"}
	// Backend is seeded with ApprovalDualOr in seedEphemeralGrant — a single
	// approve call collapses PENDING → APPROVED. Pre-bridge tests called
	// approve twice (PENDING → VALIDATOR_APPROVED → APPROVED) which now
	// trips the four-eyes guard in dual_strict mode.
	{
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/grants/"+id+"/approve", nil)
		for k, v := range hdrs {
			req.Header.Set(k, v)
		}
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Fatalf("approve status=%d", r.StatusCode)
		}
	}
	cr, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/grants/"+id+"/claim", nil)
	for k, v := range hdrs {
		cr.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(cr)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestClaim_Ephemeral_Success: in the tri-phase flow ephemeral provisioning
// fires at /claim, not at /approve. Walk the full PENDING→VALIDATOR_APPROVED→
// APPROVED→ACTIVE path then assert the provisioner was called exactly once.
func TestClaim_Ephemeral_Success(t *testing.T) {
	mock := &mockProvisioner{}
	cfg := &config.Config{
		UserToken: "api-tok",
		Windows: config.Windows{Validation: time.Hour, Claim: time.Hour, CredentialTTL: time.Hour},
	}
	srv, s, _ := newEphemeralPortal(t, cfg, mock)
	_, _, g := seedEphemeralGrant(t, s)

	resp := approveAndClaim(t, srv, g.ID)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("claim status=%d body=%s", resp.StatusCode, body)
	}
	if mock.ProvisionCount() != 1 {
		t.Errorf("provision calls=%d", mock.ProvisionCount())
	}
	stored, _ := s.GetGrant(context.Background(), g.ID)
	if stored.EphemeralUsername == "" {
		t.Error("expected EphemeralUsername populated on stored grant")
	}
	if stored.Status != domain.GrantActive {
		t.Errorf("expected ACTIVE after claim, got %s", stored.Status)
	}
}

// TestClaim_Ephemeral_FailureKeepsApproved: a /claim that hits a provisioner
// failure must NOT flip the grant to ACTIVE — caller can retry.
func TestClaim_Ephemeral_FailureKeepsApproved(t *testing.T) {
	mock := &mockProvisioner{provisionErr: errors.New("backend unreachable")}
	cfg := &config.Config{UserToken: "api-tok", Windows: config.Windows{Validation: time.Hour, Claim: time.Hour}}
	srv, s, _ := newEphemeralPortal(t, cfg, mock)
	_, _, g := seedEphemeralGrant(t, s)

	resp := approveAndClaim(t, srv, g.ID)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 on provisioner failure, got %d", resp.StatusCode)
	}
	stored, _ := s.GetGrant(context.Background(), g.ID)
	if stored.Status != domain.GrantApproved {
		t.Errorf("expected APPROVED after failed claim, got %s", stored.Status)
	}
	if stored.EphemeralUsername != "" {
		t.Errorf("EphemeralUsername should be empty on failed claim, got %q", stored.EphemeralUsername)
	}
}

func TestRevoke_CallsProvisionerRevoke(t *testing.T) {
	mock := &mockProvisioner{}
	cfg := &config.Config{UserToken: "api-tok", Windows: config.Windows{Validation: time.Hour, Claim: time.Hour, CredentialTTL: time.Hour}}
	srv, s, _ := newEphemeralPortal(t, cfg, mock)
	_, _, g := seedEphemeralGrant(t, s)

	// Walk to ACTIVE so ephemeral is provisioned.
	cresp := approveAndClaim(t, srv, g.ID)
	cresp.Body.Close()
	if mock.ProvisionCount() != 1 {
		t.Fatalf("expected provision, got %d", mock.ProvisionCount())
	}

	del, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/v1/grants/"+g.ID, nil)
	del.Header.Set("Authorization", "Bearer api-tok")
	delResp, err := http.DefaultClient.Do(del)
	if err != nil {
		t.Fatal(err)
	}
	defer delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status=%d", delResp.StatusCode)
	}
	if mock.RevokeCount() != 1 {
		t.Errorf("revoke calls=%d", mock.RevokeCount())
	}
	stored, _ := s.GetGrant(context.Background(), g.ID)
	if stored.EphemeralUsername != "" {
		t.Errorf("EphemeralUsername should be cleared after revoke, got %q", stored.EphemeralUsername)
	}
}

// TestClaim_NoDBACredential_FallsBackToSharedAccount: if the provisioner
// reports ErrNoDBACredential, the /claim path falls back to the shared
// BackendAccount and the grant still flips to ACTIVE.
func TestClaim_NoDBACredential_FallsBackToSharedAccount(t *testing.T) {
	mock := &mockProvisioner{provisionErr: ephemeral.ErrNoDBACredential}
	cfg := &config.Config{UserToken: "api-tok", Windows: config.Windows{Validation: time.Hour, Claim: time.Hour, CredentialTTL: time.Hour}}
	srv, s, _ := newEphemeralPortal(t, cfg, mock)
	_, _, g := seedEphemeralGrant(t, s)

	resp := approveAndClaim(t, srv, g.ID)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 fallback, got %d body=%s", resp.StatusCode, body)
	}
	stored, _ := s.GetGrant(context.Background(), g.ID)
	if stored.Status != domain.GrantActive {
		t.Errorf("expected ACTIVE fallback, got %s", stored.Status)
	}
	if stored.EphemeralUsername != "" {
		t.Errorf("expected empty EphemeralUsername in fallback, got %q", stored.EphemeralUsername)
	}
}

// TestGrantJSON_DoesNotLeakEphemeralPassword asserts the JSON encoding
// never serializes the password (json:"-") even when we specifically request
// the grant.
func TestGrantJSON_DoesNotLeakEphemeralPassword(t *testing.T) {
	g := domain.Grant{
		ID: "g-1", EphemeralUsername: "portal_grant_abc", EphemeralPassword: "secret-pw",
	}
	raw, _ := json.Marshal(g)
	if containsPassword(raw, "secret-pw") {
		t.Errorf("Grant JSON leaks ephemeral password: %s", raw)
	}
	if !bytes.Contains(raw, []byte(`"ephemeral_username":"portal_grant_abc"`)) {
		t.Errorf("expected username in JSON, got %s", raw)
	}
}

func containsPassword(body []byte, pw string) bool {
	return bytes.Contains(body, []byte(pw))
}

// TestClaim_AdminOnBehalf_EmitsAuditRow: an admin (static-bearer) claiming a
// grant they don't own must leave exactly one AuditEntry with the portal
// lifecycle sentinel, so operators can reconstruct who handed creds to whom.
func TestClaim_AdminOnBehalf_EmitsAuditRow(t *testing.T) {
	mock := &mockProvisioner{}
	cfg := &config.Config{
		UserToken: "api-tok",
		Windows: config.Windows{Validation: time.Hour, Claim: time.Hour, CredentialTTL: time.Hour},
	}
	srv, s, _ := newEphemeralPortal(t, cfg, mock)
	_, _, g := seedEphemeralGrant(t, s)

	resp := approveAndClaim(t, srv, g.ID)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("claim status=%d", resp.StatusCode)
	}

	entries, err := s.ListAudit(context.Background(), store.AuditFilter{GrantID: g.ID, Limit: 10})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	var onBehalf []domain.AuditEntry
	for _, e := range entries {
		if e.ProxyType == "portal" && bytes.Contains([]byte(e.Query), []byte("admin_on_behalf_claim")) {
			onBehalf = append(onBehalf, e)
		}
	}
	if len(onBehalf) != 1 {
		t.Fatalf("want 1 admin_on_behalf_claim audit row, got %d (all=%d)", len(onBehalf), len(entries))
	}
	if onBehalf[0].Username != "api-bearer" {
		t.Errorf("audit username=%q want api-bearer", onBehalf[0].Username)
	}

	// Idempotent re-claim on an already-ACTIVE grant must NOT append another
	// audit row — otherwise polling inflates the trail. Call /claim directly
	// (the grant is already ACTIVE, re-approving would 409).
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/grants/"+g.ID+"/claim", nil)
	req.Header.Set("Authorization", "Bearer api-tok")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("re-claim status=%d want 200", resp2.StatusCode)
	}
	entries, _ = s.ListAudit(context.Background(), store.AuditFilter{GrantID: g.ID, Limit: 10})
	onBehalf = onBehalf[:0]
	for _, e := range entries {
		if e.ProxyType == "portal" && bytes.Contains([]byte(e.Query), []byte("admin_on_behalf_claim")) {
			onBehalf = append(onBehalf, e)
		}
	}
	if len(onBehalf) != 1 {
		t.Errorf("re-claim appended audit rows; want still 1, got %d", len(onBehalf))
	}
}

// TestClaim_FailedValidation_SkipsAudit: an admin claim that is rejected by
// status validation (e.g. PENDING grant, dual-gate not satisfied) must NOT
// persist an admin_on_behalf_claim audit row — the claim never happened.
func TestClaim_FailedValidation_SkipsAudit(t *testing.T) {
	mock := &mockProvisioner{}
	cfg := &config.Config{
		UserToken: "api-tok",
		Windows: config.Windows{Validation: time.Hour, Claim: time.Hour, CredentialTTL: time.Hour},
	}
	srv, s, _ := newEphemeralPortal(t, cfg, mock)
	_, _, g := seedEphemeralGrant(t, s)
	// Note: NO approve — grant stays PENDING. Claim must 409.

	cr, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/grants/"+g.ID+"/claim", nil)
	cr.Header.Set("Authorization", "Bearer api-tok")
	resp, err := http.DefaultClient.Do(cr)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("want 409 on PENDING claim, got %d", resp.StatusCode)
	}

	entries, _ := s.ListAudit(context.Background(), store.AuditFilter{GrantID: g.ID, Limit: 10})
	for _, e := range entries {
		if e.ProxyType == "portal" && bytes.Contains([]byte(e.Query), []byte("admin_on_behalf_claim")) {
			t.Errorf("failed claim leaked audit row: %+v", e)
		}
	}
}
