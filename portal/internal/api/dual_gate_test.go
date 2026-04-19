package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/babs/poc-proxies/portal/internal/config"
	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/oidc"
	"github.com/babs/poc-proxies/portal/internal/policy"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// seedDualGate plants a PENDING grant with ManagerSubject already populated
// so the dual-gate dispatch tests don't need to wire Entra. Returns the
// grant ID + the helper user/backend.
func seedDualGate(t *testing.T, s store.Store, managerSub string) string {
	t.Helper()
	ctx := context.Background()
	_ = s.CreateUser(ctx, domain.User{ID: "u-1", Username: "alice", Status: "active"})
	_ = s.CreateBackend(ctx, domain.Backend{ID: "b-1", Name: "pg", Type: domain.ProxyPostgres, Host: "10.0.0.10", Port: 5432})
	_ = s.UpsertBackendAccount(ctx, domain.BackendAccount{ID: "ba-1", BackendID: "b-1", Role: domain.RoleApp, Username: "app", Password: "pw"})
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	g := domain.Grant{
		ID: "g-dual", UserID: "u-1", BackendID: "b-1", Status: domain.GrantPending,
		Role: domain.RoleApp, Database: "orders", PortalPassword: "p-pw",
		ManagerSubject:   managerSub,
		RequestedBy:      "sub-alice",
		RequestedAt:      now,
		RequestExpiresAt: &exp,
		CreatedAt:        now, UpdatedAt: now,
	}
	if err := s.CreateGrant(ctx, g); err != nil {
		t.Fatal(err)
	}
	return g.ID
}

// withSession-style portal builder: the OIDC session is injected by a thin
// middleware wrapper so the dual-gate dispatch sees the right Subject.
func newDualGatePortal(t *testing.T, sess *oidc.Session) (*httptest.Server, store.Store) {
	t.Helper()
	s := store.NewMemory()
	cfg := &config.Config{
		ValidationWindow: time.Hour,
		ClaimWindow:      time.Hour,
		CredentialTTL:    time.Hour,
	}
	h := NewRouter(cfg, s, policy.New(s), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if sess != nil {
		h = withSession(h, sess)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, s
}

func TestDualGate_ManagerApproveMovesToManagerApproved(t *testing.T) {
	mgrSess := &oidc.Session{Subject: "sub-manager", ExpiresAt: time.Now().Add(time.Hour)}
	srv, s := newDualGatePortal(t, mgrSess)
	id := seedDualGate(t, s, "sub-manager")

	resp := postJSON(t, srv.URL+"/api/v1/grants/"+id+"/approve", nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("manager approve status=%d body=%s", resp.StatusCode, body)
	}
	var g domain.Grant
	_ = json.NewDecoder(resp.Body).Decode(&g)
	if g.Status != domain.GrantManagerApproved {
		t.Errorf("status=%s want MANAGER_APPROVED", g.Status)
	}
	if g.ManagerApprovedBy == "" || g.ManagerApprovedAt == nil {
		t.Errorf("manager metadata missing: %+v", g)
	}
	if g.ApprovedBy != "" || g.ApprovedAt != nil {
		t.Errorf("admin metadata should NOT be set on manager half: %+v", g)
	}
}

func TestDualGate_AdminOnPendingIsForbidden(t *testing.T) {
	adminSess := &oidc.Session{Subject: "sub-admin", IsAdmin: true, ExpiresAt: time.Now().Add(time.Hour)}
	srv, s := newDualGatePortal(t, adminSess)
	id := seedDualGate(t, s, "sub-some-other-manager")

	resp := postJSON(t, srv.URL+"/api/v1/grants/"+id+"/approve", nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("admin-on-PENDING expected 403, got %d body=%s", resp.StatusCode, body)
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] == "" {
		t.Error("expected error message naming the open gate")
	}
}

func TestDualGate_AdminApproveAfterManagerLandsApproved(t *testing.T) {
	adminSess := &oidc.Session{Subject: "sub-admin", IsAdmin: true, ExpiresAt: time.Now().Add(time.Hour)}
	srv, s := newDualGatePortal(t, adminSess)
	id := seedDualGate(t, s, "sub-some-manager")

	// Pre-flip to MANAGER_APPROVED so admin dispatch is the one under test.
	g, _ := s.GetGrant(context.Background(), id)
	now := time.Now().UTC()
	g.Status = domain.GrantManagerApproved
	g.ManagerApprovedBy = "sub-some-manager"
	g.ManagerApprovedAt = &now
	if err := s.UpdateGrant(context.Background(), g); err != nil {
		t.Fatal(err)
	}

	resp := postJSON(t, srv.URL+"/api/v1/grants/"+id+"/approve", nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("admin approve status=%d body=%s", resp.StatusCode, body)
	}
	var got domain.Grant
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got.Status != domain.GrantApproved {
		t.Errorf("status=%s want APPROVED", got.Status)
	}
	if got.ClaimExpiresAt == nil {
		t.Error("ClaimExpiresAt should be set after admin approve")
	}
}

func TestDualGate_NeitherManagerNorAdminIsForbidden(t *testing.T) {
	stranger := &oidc.Session{Subject: "sub-stranger", ExpiresAt: time.Now().Add(time.Hour)}
	srv, s := newDualGatePortal(t, stranger)
	id := seedDualGate(t, s, "sub-some-manager")

	// Pre-flip to MANAGER_APPROVED so the stranger sits at the admin gate.
	g, _ := s.GetGrant(context.Background(), id)
	now := time.Now().UTC()
	g.Status = domain.GrantManagerApproved
	g.ManagerApprovedBy = "sub-some-manager"
	g.ManagerApprovedAt = &now
	if err := s.UpdateGrant(context.Background(), g); err != nil {
		t.Fatal(err)
	}

	resp := postJSON(t, srv.URL+"/api/v1/grants/"+id+"/approve", nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("stranger expected 403, got %d", resp.StatusCode)
	}
}

// TestClaim_HappyPath_SecondCallIsIdempotent: an APPROVED grant becomes ACTIVE
// on first /claim, second call within TTL returns the same creds.
func TestClaim_HappyPath_SecondCallIsIdempotent(t *testing.T) {
	srv, s := newDualGatePortal(t, nil) // static-bearer-style: no session
	// Bearer-less open mode: the api uses no auth guard when both providers
	// + UserToken are empty. Owner check still allows sess==nil → admin path.
	id := seedDualGate(t, s, "")
	// Walk to APPROVED.
	g, _ := s.GetGrant(context.Background(), id)
	now := time.Now().UTC()
	cl := now.Add(time.Hour)
	g.Status = domain.GrantApproved
	g.ApprovedBy = "test"
	g.ApprovedAt = &now
	g.ClaimExpiresAt = &cl
	if err := s.UpdateGrant(context.Background(), g); err != nil {
		t.Fatal(err)
	}

	first := postJSON(t, srv.URL+"/api/v1/grants/"+id+"/claim", nil, nil)
	defer first.Body.Close()
	if first.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(first.Body)
		t.Fatalf("first claim status=%d body=%s", first.StatusCode, body)
	}
	var fc claimResponse
	_ = json.NewDecoder(first.Body).Decode(&fc)
	if fc.PortalPassword != "p-pw" {
		t.Errorf("portal_password=%q want p-pw", fc.PortalPassword)
	}
	if fc.ExpiresAt.IsZero() || fc.ExpiresAt.Before(time.Now()) {
		t.Errorf("expires_at invalid: %v", fc.ExpiresAt)
	}

	// Second claim while ACTIVE: same creds, status still ACTIVE.
	second := postJSON(t, srv.URL+"/api/v1/grants/"+id+"/claim", nil, nil)
	defer second.Body.Close()
	if second.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(second.Body)
		t.Fatalf("second claim status=%d body=%s", second.StatusCode, body)
	}
	var sc claimResponse
	_ = json.NewDecoder(second.Body).Decode(&sc)
	if sc.PortalPassword != fc.PortalPassword {
		t.Errorf("re-claim returned different portal_password: %q vs %q", sc.PortalPassword, fc.PortalPassword)
	}
	stored, _ := s.GetGrant(context.Background(), id)
	if stored.Status != domain.GrantActive {
		t.Errorf("status=%s want ACTIVE", stored.Status)
	}
}

// TestClaim_AfterTTL_Returns410: an ACTIVE grant past ExpiresAt rejects /claim
// with 410 Gone.
func TestClaim_AfterTTL_Returns410(t *testing.T) {
	srv, s := newDualGatePortal(t, nil)
	id := seedDualGate(t, s, "")
	g, _ := s.GetGrant(context.Background(), id)
	past := time.Now().Add(-time.Minute)
	g.Status = domain.GrantActive
	g.ExpiresAt = &past
	if err := s.UpdateGrant(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	resp := postJSON(t, srv.URL+"/api/v1/grants/"+id+"/claim", nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("expected 410, got %d", resp.StatusCode)
	}
}

// TestClaim_NonOwnerNonAdminIsForbidden: a stranger session can't claim
// somebody else's APPROVED grant.
func TestClaim_NonOwnerNonAdminIsForbidden(t *testing.T) {
	stranger := &oidc.Session{Subject: "sub-stranger", PortalUserID: "u-9", ExpiresAt: time.Now().Add(time.Hour)}
	srv, s := newDualGatePortal(t, stranger)
	id := seedDualGate(t, s, "")
	g, _ := s.GetGrant(context.Background(), id)
	now := time.Now().UTC()
	cl := now.Add(time.Hour)
	g.Status = domain.GrantApproved
	g.ApprovedBy = "test"
	g.ApprovedAt = &now
	g.ClaimExpiresAt = &cl
	g.RequestedBy = "sub-alice" // not the stranger
	g.UserID = "u-1"            // not the stranger's portal user
	if err := s.UpdateGrant(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	resp := postJSON(t, srv.URL+"/api/v1/grants/"+id+"/claim", nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for non-owner non-admin, got %d", resp.StatusCode)
	}
}
