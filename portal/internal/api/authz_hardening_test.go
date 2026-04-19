package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/babs/poc-proxies/portal/internal/config"
	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/entra"
	"github.com/babs/poc-proxies/portal/internal/oidc"
	"github.com/babs/poc-proxies/portal/internal/policy"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// seedPendingGrant creates a user + backend + PENDING grant; returns the ids.
func seedPendingGrant(t *testing.T, s store.Store, managerSub string) (userID, backendID, grantID string) {
	t.Helper()
	ctx := context.Background()
	u := domain.User{ID: "u-a", Username: "alice", Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	b := domain.Backend{ID: "b-a", Name: "pg-prod", Type: domain.ProxyPostgres, Host: "10.0.0.1", Port: 5432}
	if err := s.CreateBackend(ctx, b); err != nil {
		t.Fatal(err)
	}
	g := domain.Grant{
		ID: "g-a", UserID: u.ID, BackendID: b.ID, Status: domain.GrantPending,
		Role: domain.RoleApp, Database: "orders", PortalPassword: "p-pw",
		ManagerSubject: managerSub,
		RequestedAt:    time.Now(), CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateGrant(ctx, g); err != nil {
		t.Fatal(err)
	}
	return u.ID, b.ID, g.ID
}

// TestPatch_RejectsStatusChange: PATCH used to accept a status field and flip
// the grant — bypassing /approve's ephemeral-DBA precondition, claim_window
// stamping, and outcome email. The patch handler must now refuse status.
func TestPatch_RejectsStatusChange(t *testing.T) {
	cfg := &config.Config{UserToken: "api-tok"}
	srv, s := newTestPortal(t, cfg)
	_, _, gid := seedPendingGrant(t, s, "sub-mgr")

	body, _ := json.Marshal(map[string]any{"status": "APPROVED", "reason": "try-bypass"})
	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/v1/grants/"+gid, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer api-tok")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("want 400 on status smuggle, got %d body=%s", resp.StatusCode, raw)
	}
	// Grant must still be PENDING — PATCH mutated nothing.
	g, _ := s.GetGrant(context.Background(), gid)
	if g.Status != domain.GrantPending {
		t.Errorf("status=%s want PENDING (PATCH must not change status)", g.Status)
	}
}

// TestPatch_AllowsReasonOnly: PATCH with only a reason field still works —
// that's the legitimate mutable-field path.
func TestPatch_AllowsReasonOnly(t *testing.T) {
	cfg := &config.Config{UserToken: "api-tok"}
	srv, s := newTestPortal(t, cfg)
	_, _, gid := seedPendingGrant(t, s, "sub-mgr")

	body, _ := json.Marshal(map[string]any{"reason": "updated-context"})
	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/v1/grants/"+gid, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer api-tok")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("want 200, got %d body=%s", resp.StatusCode, raw)
	}
	g, _ := s.GetGrant(context.Background(), gid)
	if g.Reason != "updated-context" {
		t.Errorf("reason=%q want updated-context", g.Reason)
	}
	if g.Status != domain.GrantPending {
		t.Errorf("status unexpectedly changed to %s", g.Status)
	}
}

// TestCreate_NonAdminOIDC_SelfScopeEnforced: with Entra wired, a non-admin
// OIDC session used to be able to create a grant for ANY user_id — the trio
// policy checked the caller's groups but not the target. Must now 403.
func TestCreate_NonAdminOIDC_SelfScopeEnforced(t *testing.T) {
	fc := entra.NewFakeClient()
	fc.GroupsByUser["sub-alice"] = []entra.Group{{ID: "guid-dev"}}
	fc.Managers["sub-alice"] = entra.User{ID: "sub-bob", Mail: "bob@example.com"}

	pol := policy.NewRequestPolicy(map[string]map[policy.Trio]policy.AccessMode{
		"guid-dev": {{Instance: "pg-prod", Database: "orders", Level: "app"}: policy.ModePermanent},
	})
	cfg := &config.Config{}
	deps := RouterDeps{
		Entra: fc, RequestPol: pol,
		EntraSender: "noreply@example.com", EntraMetrics: NewEntraMetrics(),
	}
	sess := &oidc.Session{Subject: "sub-alice", PortalUserID: "u-alice", ExpiresAt: time.Now().Add(time.Hour)}

	s := store.NewMemory()
	_ = s.CreateUser(context.Background(), domain.User{ID: "u-alice", Username: "alice", Status: "active"})
	_ = s.CreateUser(context.Background(), domain.User{ID: "u-bob", Username: "bob", Status: "active"})
	_ = s.CreateBackend(context.Background(), domain.Backend{ID: "b-1", Name: "pg-prod", Type: domain.ProxyPostgres, Host: "10.0.0.10", Port: 5432})
	h := NewRouter(cfg, store.Store(s), policy.New(s), slog.New(slog.NewJSONHandler(io.Discard, nil)), deps.Options()...)
	h = withSession(h, sess)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	// alice submits a grant for bob — same trio she's allowed, but bob is not her.
	body := map[string]any{
		"user_id": "u-bob", "backend_addr": "10.0.0.10:5432", "role": "app",
		"database": "orders", "reason": "on-behalf-try",
	}
	resp := postJSON(t, srv.URL+"/api/v1/grants", body, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("want 403 (self-scope), got %d body=%s", resp.StatusCode, raw)
	}
}

// TestApprove_StaticBearerDemoted_WhenEntraConfigured: when Entra is wired and
// the grant has a recorded ManagerSubject, a static-bearer caller must not
// satisfy the manager half of the gate — otherwise a single shared token
// collapses the four-eyes guarantee.
func TestApprove_StaticBearerDemoted_WhenEntraConfigured(t *testing.T) {
	fc := entra.NewFakeClient()
	cfg := &config.Config{UserToken: "api-tok"}
	deps := RouterDeps{Entra: fc}

	s := store.NewMemory()
	_, _, gid := seedPendingGrant(t, s, "sub-mgr")
	h := NewRouter(cfg, store.Store(s), policy.New(s), slog.New(slog.NewJSONHandler(io.Discard, nil)), deps.Options()...)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/grants/"+gid+"/approve", nil)
	req.Header.Set("Authorization", "Bearer api-tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("want 403 (static bearer demoted), got %d body=%s", resp.StatusCode, raw)
	}
	g, _ := s.GetGrant(context.Background(), gid)
	if g.Status != domain.GrantPending {
		t.Errorf("status=%s want PENDING (manager gate must stay closed)", g.Status)
	}
}

// TestApprove_StaticBearer_WorksWhenEntraUnwired: without Entra wiring,
// static-bearer retains the legacy both-gates behaviour so automation that
// pre-dates the dual-gate split keeps working.
func TestApprove_StaticBearer_WorksWhenEntraUnwired(t *testing.T) {
	cfg := &config.Config{UserToken: "api-tok"}
	srv, s := newTestPortal(t, cfg) // no Entra deps
	_, _, gid := seedPendingGrant(t, s, "sub-mgr")

	// Two /approve calls walk PENDING → MANAGER_APPROVED → APPROVED via bearer.
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/grants/"+gid+"/approve", nil)
		req.Header.Set("Authorization", "Bearer api-tok")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("approve %d status=%d", i, resp.StatusCode)
		}
	}
	g, _ := s.GetGrant(context.Background(), gid)
	if g.Status != domain.GrantApproved {
		t.Errorf("status=%s want APPROVED", g.Status)
	}
}

// TestGetGrant_NonAdminOwner: owner can GET their own grant detail; a
// different non-admin user gets 404 (probe-resistant).
func TestGetGrant_NonAdminOwner(t *testing.T) {
	cfg := &config.Config{}
	s := store.NewMemory()
	_, _, gid := seedPendingGrant(t, s, "sub-mgr")

	h := NewRouter(cfg, store.Store(s), policy.New(s), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	// Owner session.
	owner := &oidc.Session{Subject: "sub-a", PortalUserID: "u-a", ExpiresAt: time.Now().Add(time.Hour)}
	srv := httptest.NewServer(withSession(h, owner))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/api/v1/grants/" + gid)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("owner GET status=%d want 200", resp.StatusCode)
	}

	// Separate portal — stranger session on same store.
	h2 := NewRouter(cfg, store.Store(s), policy.New(s), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	stranger := &oidc.Session{Subject: "sub-x", PortalUserID: "u-x", ExpiresAt: time.Now().Add(time.Hour)}
	srv2 := httptest.NewServer(withSession(h2, stranger))
	t.Cleanup(srv2.Close)

	resp2, err := http.Get(srv2.URL + "/api/v1/grants/" + gid)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("stranger GET status=%d want 404 (probe-resistant)", resp2.StatusCode)
	}
}

// TestRateLimit_SubResource: POSTing to /grants/:id/claim more than the
// configured per-IP burst must start returning 429.
func TestRateLimit_SubResource(t *testing.T) {
	cfg := &config.Config{
		UserToken:       "api-tok",
		AuthRatePerIP:   5, // 5/min → burst 5 then 429
		AuthRatePerUser: 1000,
	}
	srv, s, _ := newTestPortalWithMetrics(t, cfg)
	// Seed an APPROVED grant so /claim would be 200 without the limiter.
	ctx := context.Background()
	_ = s.CreateUser(ctx, domain.User{ID: "u-a", Username: "alice", Status: "active"})
	_ = s.CreateBackend(ctx, domain.Backend{ID: "b-a", Name: "x", Type: domain.ProxyMongo, Host: "127.0.0.1", Port: 27017})
	ce := time.Now().Add(time.Hour)
	_ = s.CreateGrant(ctx, domain.Grant{
		ID: "g-rl", UserID: "u-a", BackendID: "b-a", Status: domain.GrantApproved,
		Role: domain.RoleApp, Database: "orders", PortalPassword: "p",
		ClaimExpiresAt: &ce, RequestedAt: time.Now(), CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})

	var got429 bool
	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/grants/g-rl/claim", nil)
		req.Header.Set("Authorization", "Bearer api-tok")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			break
		}
		if resp.StatusCode >= 500 {
			t.Fatalf("call %d status=%d body=%s", i, resp.StatusCode, body)
		}
	}
	if !got429 {
		t.Error("sub-resource path not rate-limited: expected at least one 429 within 20 calls")
	}
}

// TestNewSecret_Entropy: the new helper must produce 256 bits (64 hex chars)
// and be non-deterministic.
func TestNewSecret_Entropy(t *testing.T) {
	a := domain.NewSecret()
	b := domain.NewSecret()
	if len(a) != 64 {
		t.Errorf("secret len=%d want 64 hex chars (256 bits)", len(a))
	}
	if a == b {
		t.Error("two consecutive NewSecret() calls returned the same value")
	}
	// Must be hex.
	if strings.Trim(a, "0123456789abcdef") != "" {
		t.Errorf("secret %q has non-hex chars", a)
	}
}
