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
	h := NewRouterWithMetrics(cfg, s, eng, nil, slog.New(slog.NewJSONHandler(io.Discard, nil)), nil, nil, mgr)
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
	b := domain.Backend{ID: "b-eph", Name: "mongo", Type: domain.ProxyMongo, Host: "127.0.0.1", Port: 27017}
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
		RequestedAt: time.Now(), ExpiresAt: &exp, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateGrant(ctx, g); err != nil {
		t.Fatal(err)
	}
	return u, b, g
}

func TestApprove_Ephemeral_Success(t *testing.T) {
	mock := &mockProvisioner{}
	cfg := &config.Config{UserToken: "api-tok"}
	srv, s, _ := newEphemeralPortal(t, cfg, mock)
	_, _, g := seedEphemeralGrant(t, s)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/grants/"+g.ID+"/approve", bytes.NewReader(nil))
	req.Header.Set("Authorization", "Bearer api-tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("approve status=%d body=%s", resp.StatusCode, body)
	}
	if mock.ProvisionCount() != 1 {
		t.Errorf("provision calls=%d", mock.ProvisionCount())
	}

	stored, _ := s.GetGrant(context.Background(), g.ID)
	if stored.EphemeralUsername == "" {
		t.Error("expected EphemeralUsername populated on stored grant")
	}
	// JSON response must never leak the ephemeral password.
	body, _ := io.ReadAll(resp.Body)
	if len(body) > 0 && containsPassword(body, "hex-pw") {
		t.Errorf("response body leaks ephemeral password: %s", body)
	}
}

func TestApprove_Ephemeral_FailureRollsBackToPending(t *testing.T) {
	mock := &mockProvisioner{provisionErr: errors.New("backend unreachable")}
	cfg := &config.Config{UserToken: "api-tok"}
	srv, s, _ := newEphemeralPortal(t, cfg, mock)
	_, _, g := seedEphemeralGrant(t, s)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/grants/"+g.ID+"/approve", bytes.NewReader(nil))
	req.Header.Set("Authorization", "Bearer api-tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 on provisioner failure, got %d", resp.StatusCode)
	}
	stored, _ := s.GetGrant(context.Background(), g.ID)
	if stored.Status != domain.GrantPending {
		t.Errorf("expected PENDING after rollback, got %s", stored.Status)
	}
	if stored.ApprovedAt != nil || stored.ApprovedBy != "" {
		t.Errorf("approver metadata should be cleared on rollback: %+v", stored)
	}
	if stored.EphemeralUsername != "" {
		t.Errorf("EphemeralUsername should be empty on rollback, got %q", stored.EphemeralUsername)
	}
}

func TestRevoke_CallsProvisionerRevoke(t *testing.T) {
	mock := &mockProvisioner{}
	cfg := &config.Config{UserToken: "api-tok"}
	srv, s, _ := newEphemeralPortal(t, cfg, mock)
	_, _, g := seedEphemeralGrant(t, s)

	// Approve first so the grant becomes revocable + ephemeral is set.
	app, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/grants/"+g.ID+"/approve", nil)
	app.Header.Set("Authorization", "Bearer api-tok")
	appResp, _ := http.DefaultClient.Do(app)
	appResp.Body.Close()
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

func TestApprove_NoDBACredential_FallsBackToSharedAccount(t *testing.T) {
	// Provisioner returns ErrNoDBACredential — handler should log a warning
	// and keep the grant APPROVED with no ephemeral fields set.
	mock := &mockProvisioner{provisionErr: ephemeral.ErrNoDBACredential}
	cfg := &config.Config{UserToken: "api-tok"}
	srv, s, _ := newEphemeralPortal(t, cfg, mock)
	_, _, g := seedEphemeralGrant(t, s)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/grants/"+g.ID+"/approve", nil)
	req.Header.Set("Authorization", "Bearer api-tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 fallback, got %d body=%s", resp.StatusCode, body)
	}
	stored, _ := s.GetGrant(context.Background(), g.ID)
	if stored.Status != domain.GrantApproved {
		t.Errorf("expected APPROVED fallback, got %s", stored.Status)
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
