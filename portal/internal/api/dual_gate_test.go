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

// seedDualGate plants a PENDING grant with T1Subject already populated
// so the dual-gate dispatch tests don't need to wire Entra. Returns the
// grant ID + the helper user/backend. Also seeds a "t2" group whose member
// is "sub-admin" + wires the backend's T2GroupSlug to it, so any test
// sending a session with Subject="sub-admin" is naturally T2-eligible
// (matches the §7.8.1 split — operator role no longer auto-grants T2).
func seedDualGate(t *testing.T, s store.Store, validatorSub string) string {
	t.Helper()
	ctx := context.Background()
	_ = s.CreateUser(ctx, domain.User{ID: "u-1", Username: "alice", Status: "active"})
	// Plant a T2 admin user so its ExternalID can land in the group.
	_ = s.CreateUser(ctx, domain.User{ID: "u-admin", Username: "admin", ExternalID: "sub-admin", Status: "active"})
	_ = s.CreateUser(ctx, domain.User{ID: "u-super", Username: "super", ExternalID: "sub-super", Status: "active"})
	g := domain.Group{ID: "grp-t2", Slug: "t2-team", DisplayName: "T2 admins"}
	_ = s.UpsertGroup(ctx, g)
	_ = s.AddGroupMember(ctx, g.ID, "u-admin")
	_ = s.AddGroupMember(ctx, g.ID, "u-super")
	_ = s.CreateBackend(ctx, domain.Backend{
		ID: "b-1", Name: "pg", Type: domain.ProxyPostgres, Host: "10.0.0.10", Port: 5432,
		T2GroupSlug: "t2-team",
	})
	_ = s.UpsertBackendAccount(ctx, domain.BackendAccount{ID: "ba-1", BackendID: "b-1", Role: domain.RoleApp, Username: "app", Password: "pw"})
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	gr := domain.Grant{
		ID: "g-dual", UserID: "u-1", BackendID: "b-1", Status: domain.GrantPending,
		Role: domain.RoleApp, Database: "orders", PortalPassword: "p-pw",
		T1Subject:        validatorSub,
		RequestedBy:      "sub-alice",
		RequestedAt:      now,
		RequestExpiresAt: &exp,
		CreatedAt:        now, UpdatedAt: now,
	}
	if err := s.CreateGrant(ctx, gr); err != nil {
		t.Fatal(err)
	}
	return gr.ID
}

// withSession-style portal builder: the OIDC session is injected by a thin
// middleware wrapper so the dual-gate dispatch sees the right Subject.
func newDualGatePortal(t *testing.T, sess *oidc.Session) (*httptest.Server, store.Store) {
	t.Helper()
	s := store.NewMemory()
	cfg := &config.Config{
		Windows: config.Windows{Validation: time.Hour, Claim: time.Hour, CredentialTTL: time.Hour},
	}
	h := NewRouter(cfg, s, policy.New(s), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if sess != nil {
		h = withSession(h, sess)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, s
}

func TestDualGate_ValidatorApproveMovesToValidatorApproved(t *testing.T) {
	valSess := &oidc.Session{Subject: "sub-validator", ExpiresAt: time.Now().Add(time.Hour)}
	srv, s := newDualGatePortal(t, valSess)
	id := seedDualGate(t, s, "sub-validator")

	resp := postJSON(t, srv.URL+"/api/v1/grants/"+id+"/approve", nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("validator approve status=%d body=%s", resp.StatusCode, body)
	}
	var g domain.Grant
	_ = json.NewDecoder(resp.Body).Decode(&g)
	if g.Status != domain.GrantValidatorApproved {
		t.Errorf("status=%s want VALIDATOR_APPROVED", g.Status)
	}
	if g.T1ApprovedBy == "" || g.T1ApprovedAt == nil {
		t.Errorf("validator metadata missing: %+v", g)
	}
	if g.T2ApprovedBy != "" || g.T2ApprovedAt != nil {
		t.Errorf("admin metadata should NOT be set on validator half: %+v", g)
	}
}

func TestDualGate_AdminOnPendingIsForbidden(t *testing.T) {
	adminSess := &oidc.Session{Subject: "sub-admin", IsOperator: true, ExpiresAt: time.Now().Add(time.Hour)}
	srv, s := newDualGatePortal(t, adminSess)
	id := seedDualGate(t, s, "sub-some-other-validator")

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

func TestDualGate_AdminApproveAfterValidatorLandsApproved(t *testing.T) {
	adminSess := &oidc.Session{Subject: "sub-admin", IsOperator: true, ExpiresAt: time.Now().Add(time.Hour)}
	srv, s := newDualGatePortal(t, adminSess)
	id := seedDualGate(t, s, "sub-some-validator")

	// Pre-flip to VALIDATOR_APPROVED so admin dispatch is the one under test.
	g, _ := s.GetGrant(context.Background(), id)
	now := time.Now().UTC()
	g.Status = domain.GrantValidatorApproved
	g.T1ApprovedBy = "sub-some-validator"
	g.T1ApprovedAt = &now
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

func TestDualGate_NeitherValidatorNorAdminIsForbidden(t *testing.T) {
	stranger := &oidc.Session{Subject: "sub-stranger", ExpiresAt: time.Now().Add(time.Hour)}
	srv, s := newDualGatePortal(t, stranger)
	id := seedDualGate(t, s, "sub-some-validator")

	// Pre-flip to VALIDATOR_APPROVED so the stranger sits at the admin gate.
	g, _ := s.GetGrant(context.Background(), id)
	now := time.Now().UTC()
	g.Status = domain.GrantValidatorApproved
	g.T1ApprovedBy = "sub-some-validator"
	g.T1ApprovedAt = &now
	if err := s.UpdateGrant(context.Background(), g); err != nil {
		t.Fatal(err)
	}

	resp := postJSON(t, srv.URL+"/api/v1/grants/"+id+"/approve", nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("stranger expected 403, got %d", resp.StatusCode)
	}
}

// --- dual_strict on-behalf override + four-eyes regression coverage ---
//
// Bridge implementation of specs/phase-7-validation-ui.md §7.8.1 + §7.8.7.
// Backends in dual_strict require two distinct actors by default; a T2
// (operator) stepping in for an absent natural T1 must declare the override
// at gate1 with a reason of at least 20 chars, and that declaration is the
// only path by which the same actor can subsequently clear gate2.

// TestDualStrict_OperatorOnBehalf_RequiresBody: operator hits gate1 without
// the on_behalf_of_t1 body → 403 with an instructive message.
func TestDualStrict_OperatorOnBehalf_RequiresBody(t *testing.T) {
	adminSess := &oidc.Session{Subject: "sub-admin", IsOperator: true, ExpiresAt: time.Now().Add(time.Hour)}
	srv, s := newDualGatePortal(t, adminSess)
	id := seedDualGate(t, s, "sub-some-validator")
	// seedDualGate writes the backend with zero-value ApprovalMode — memory
	// store fills in dual_strict, matching production default.
	_ = s

	resp := postJSON(t, srv.URL+"/api/v1/grants/"+id+"/approve", nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 403 without on_behalf body, got %d body=%s", resp.StatusCode, b)
	}
}

// TestDualStrict_OperatorOnBehalf_ShortReason: on_behalf body with a reason
// shorter than the 20-char minimum is rejected with 400.
func TestDualStrict_OperatorOnBehalf_ShortReason(t *testing.T) {
	adminSess := &oidc.Session{Subject: "sub-admin", IsOperator: true, ExpiresAt: time.Now().Add(time.Hour)}
	srv, s := newDualGatePortal(t, adminSess)
	id := seedDualGate(t, s, "sub-some-validator")
	_ = s

	body := map[string]any{"on_behalf_of_t1": true, "reason": "too short"}
	resp := postJSON(t, srv.URL+"/api/v1/grants/"+id+"/approve", body, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400 for short reason, got %d body=%s", resp.StatusCode, b)
	}
}

// TestDualStrict_OperatorOnBehalf_HappyPath: operator with a valid override
// at gate1 clears PENDING → VALIDATOR_APPROVED with the on-behalf flag + reason
// recorded. The SAME operator then clears gate2 → APPROVED without tripping
// the four-eyes guard, since the gate1 override justified the chain.
func TestDualStrict_OperatorOnBehalf_HappyPath(t *testing.T) {
	adminSess := &oidc.Session{Subject: "sub-admin", IsOperator: true, ExpiresAt: time.Now().Add(time.Hour)}
	srv, s := newDualGatePortal(t, adminSess)
	id := seedDualGate(t, s, "sub-natural-t1")
	_ = s

	// Gate1 with override.
	body := map[string]any{
		"on_behalf_of_t1": true,
		"reason":          "INC-4521: T1 Bob on PTO; prod outage needs DB access today",
	}
	r1 := postJSON(t, srv.URL+"/api/v1/grants/"+id+"/approve", body, nil)
	defer r1.Body.Close()
	if r1.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(r1.Body)
		t.Fatalf("gate1 on-behalf expected 200, got %d body=%s", r1.StatusCode, b)
	}
	got, _ := s.GetGrant(context.Background(), id)
	if got.Status != domain.GrantValidatorApproved {
		t.Fatalf("gate1: status=%s want VALIDATOR_APPROVED", got.Status)
	}
	if !got.T1ApprovedOnBehalf {
		t.Error("T1ApprovedOnBehalf should be TRUE after override")
	}
	if len(got.T1OnBehalfReason) < onBehalfReasonMinLen {
		t.Errorf("T1OnBehalfReason not persisted: %q", got.T1OnBehalfReason)
	}

	// Gate2 by the SAME operator — normally would 409 on four-eyes, but the
	// gate1 override lets the chain complete.
	r2 := postJSON(t, srv.URL+"/api/v1/grants/"+id+"/approve", nil, nil)
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(r2.Body)
		t.Fatalf("gate2 after on-behalf expected 200, got %d body=%s", r2.StatusCode, b)
	}
	final, _ := s.GetGrant(context.Background(), id)
	if final.Status != domain.GrantApproved {
		t.Errorf("gate2: status=%s want APPROVED", final.Status)
	}
}

// TestDualStrict_FourEyesGuard_BlocksNaturalT1Stacking: when the natural T1
// has cleared gate1 (no on-behalf flag), attempting to clear gate2 as the
// same principal returns 409 — the four-eyes invariant holds for
// non-override paths.
func TestDualStrict_FourEyesGuard_BlocksNaturalT1Stacking(t *testing.T) {
	// Principal that is BOTH the natural T1 AND an operator (the "super
	// approver" stacking from §7.8.7).
	sess := &oidc.Session{Subject: "sub-super", IsOperator: true, ExpiresAt: time.Now().Add(time.Hour)}
	srv, s := newDualGatePortal(t, sess)
	id := seedDualGate(t, s, "sub-super")
	_ = s

	// Gate1 as natural T1 — no on_behalf body needed.
	r1 := postJSON(t, srv.URL+"/api/v1/grants/"+id+"/approve", nil, nil)
	defer r1.Body.Close()
	if r1.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(r1.Body)
		t.Fatalf("gate1 natural-T1 expected 200, got %d body=%s", r1.StatusCode, b)
	}

	// Gate2 as same principal — 409 (four-eyes).
	r2 := postJSON(t, srv.URL+"/api/v1/grants/"+id+"/approve", nil, nil)
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusConflict {
		b, _ := io.ReadAll(r2.Body)
		t.Fatalf("gate2 same-actor expected 409, got %d body=%s", r2.StatusCode, b)
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
	g.T2ApprovedBy = "test"
	g.T2ApprovedAt = &now
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
	g.T2ApprovedBy = "test"
	g.T2ApprovedAt = &now
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
