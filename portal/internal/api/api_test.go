package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/babs/poc-proxies/internal/auth"
	"github.com/babs/poc-proxies/portal/internal/config"
	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/policy"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// newTestPortal spins up a portal handler on a pre-opened listener with optional tokens.
func newTestPortal(t *testing.T, cfg *config.Config) (*httptest.Server, store.Store) {
	t.Helper()
	s := store.NewMemory()
	eng := policy.New(s)
	h := NewRouter(cfg, s, eng, nil, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, s
}

// seedFull registers a user, backend, backend account, and an approved grant.
func seedFull(t *testing.T, s store.Store, portalPW string) (domain.User, domain.Backend) {
	t.Helper()
	ctx := context.Background()
	u := domain.User{ID: "u-1", Username: "alice", Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	b := domain.Backend{ID: "b-1", Name: "mongo", Type: domain.ProxyMongo, Host: "127.0.0.1", Port: 27017}
	if err := s.CreateBackend(ctx, b); err != nil {
		t.Fatal(err)
	}
	// Backend password now lives behind a secrets ref; the engine resolves
	// env://TEST_PW at /auth time — exercising the Phase 1.4 happy path.
	acct := domain.BackendAccount{ID: "ba-1", BackendID: "b-1", Role: domain.RoleApp, Username: "app", PasswordRef: "env://TEST_PW"}
	if err := s.UpsertBackendAccount(ctx, acct); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)
	g := domain.Grant{
		ID: "g-1", UserID: u.ID, BackendID: b.ID, Status: domain.GrantApproved,
		Role: domain.RoleApp, Database: "orders", PortalPassword: portalPW,
		ExpiresAt: &exp, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateGrant(ctx, g); err != nil {
		t.Fatal(err)
	}
	return u, b
}

func postJSON(t *testing.T, url string, body any, headers map[string]string) *http.Response {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestAuthEndpoint_Success(t *testing.T) {
	t.Setenv("TEST_PW", "secret")
	cfg := &config.Config{ProxyToken: "super-secret"}
	srv, s := newTestPortal(t, cfg)
	seedFull(t, s, "portal-pw")

	body := auth.LookupRequest{Username: "alice", SourceIP: "10.0.0.1", ProxyType: "mongo", BackendServer: "127.0.0.1:27017"}
	resp := postJSON(t, srv.URL+"/api/v1/auth", body, map[string]string{"X-Portal-Token": "super-secret"})
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got auth.AuthResponse
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got.Password != "portal-pw" || got.BackendUser != "app" || got.GrantID != "g-1" {
		t.Errorf("bad response: %+v", got)
	}
}

func TestAuthEndpoint_TokenRequired(t *testing.T) {
	cfg := &config.Config{ProxyToken: "super-secret"}
	srv, _ := newTestPortal(t, cfg)

	resp := postJSON(t, srv.URL+"/api/v1/auth",
		auth.LookupRequest{Username: "x", ProxyType: "mongo", BackendServer: "a"}, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", resp.StatusCode)
	}
}

func TestAuthEndpoint_NoGrant(t *testing.T) {
	cfg := &config.Config{} // no token guard
	srv, _ := newTestPortal(t, cfg)
	resp := postJSON(t, srv.URL+"/api/v1/auth",
		auth.LookupRequest{Username: "ghost", ProxyType: "mongo", BackendServer: "127.0.0.1:27017"}, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestAuditEndpoint_AcceptsBatch(t *testing.T) {
	cfg := &config.Config{}
	srv, s := newTestPortal(t, cfg)

	batch := map[string]any{
		"entries": []domain.AuditEntry{
			{GrantID: "g-1", Username: "alice", Query: "SELECT 1", Timestamp: time.Now()},
			{GrantID: "g-1", Username: "alice", Query: "SELECT 2", Timestamp: time.Now()},
		},
	}
	resp := postJSON(t, srv.URL+"/api/v1/audit/query", batch, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("want 202, got %d", resp.StatusCode)
	}
	var got map[string]int
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got["accepted"] != 2 {
		t.Errorf("accepted=%d", got["accepted"])
	}
	stored, _ := s.ListAudit(context.Background(), store.AuditFilter{GrantID: "g-1"})
	if len(stored) != 2 {
		t.Errorf("stored=%d", len(stored))
	}
}

func TestGrantsCRUD(t *testing.T) {
	cfg := &config.Config{UserToken: "api-tok"}
	srv, s := newTestPortal(t, cfg)

	// Seed user+backend.
	u := domain.User{ID: "u-1", Username: "alice", Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	_ = s.CreateUser(context.Background(), u)
	b := domain.Backend{ID: "b-1", Name: "n", Type: domain.ProxyMongo, Host: "127.0.0.1", Port: 27017}
	_ = s.CreateBackend(context.Background(), b)

	hdrs := map[string]string{"Authorization": "Bearer api-tok"}

	// Create
	body := map[string]any{
		"user_id": u.ID, "backend_addr": b.Address(), "role": "app",
		"database": "orders", "requested_duration": "2h", "portal_password": "p-pw",
	}
	resp := postJSON(t, srv.URL+"/api/v1/grants", body, hdrs)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		all, _ := io.ReadAll(resp.Body)
		t.Fatalf("create grant status=%d body=%s", resp.StatusCode, string(all))
	}
	var created domain.Grant
	_ = json.NewDecoder(resp.Body).Decode(&created)
	// Default behaviour is PENDING — approval gate is the whole point of 1.2.
	if created.Status != domain.GrantPending {
		t.Errorf("expected PENDING, got %s", created.Status)
	}
	if created.RequestedBy == "" {
		t.Errorf("expected RequestedBy populated, got empty")
	}

	// List
	listResp, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/grants?user_id="+u.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	listResp.Header.Set("Authorization", "Bearer api-tok")
	lr, err := http.DefaultClient.Do(listResp)
	if err != nil {
		t.Fatal(err)
	}
	defer lr.Body.Close()
	if lr.StatusCode != 200 {
		t.Fatalf("list status=%d", lr.StatusCode)
	}
	var list []domain.Grant
	_ = json.NewDecoder(lr.Body).Decode(&list)
	if len(list) != 1 {
		t.Fatalf("expected 1 grant, got %d", len(list))
	}

	// Revoke
	delReq, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/v1/grants/"+created.ID, nil)
	delReq.Header.Set("Authorization", "Bearer api-tok")
	dresp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatal(err)
	}
	defer dresp.Body.Close()
	if dresp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status=%d", dresp.StatusCode)
	}
	after, _ := s.GetGrant(context.Background(), created.ID)
	if after.Status != domain.GrantRevoked {
		t.Errorf("expected REVOKED after delete, got %s", after.Status)
	}
}

func TestGrants_BearerRequired(t *testing.T) {
	cfg := &config.Config{UserToken: "api-tok"}
	srv, _ := newTestPortal(t, cfg)

	resp, err := http.Get(srv.URL + "/api/v1/grants")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

// seedUserBackendAccount creates a user, backend, and backend account so a
// grant can be promoted to APPROVED and exercised against /api/v1/auth.
func seedUserBackendAccount(t *testing.T, s store.Store) (domain.User, domain.Backend) {
	t.Helper()
	ctx := context.Background()
	u := domain.User{ID: "u-1", Username: "alice", Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	b := domain.Backend{ID: "b-1", Name: "mongo", Type: domain.ProxyMongo, Host: "127.0.0.1", Port: 27017}
	if err := s.CreateBackend(ctx, b); err != nil {
		t.Fatal(err)
	}
	acct := domain.BackendAccount{ID: "ba-1", BackendID: b.ID, Role: domain.RoleApp, Username: "app", Password: "secret"}
	if err := s.UpsertBackendAccount(ctx, acct); err != nil {
		t.Fatal(err)
	}
	return u, b
}

// TestGrants_PendingDeniesAuth asserts a newly created grant stays PENDING and
// that /api/v1/auth denies lookups for it — the four-eyes gate in action.
func TestGrants_PendingDeniesAuth(t *testing.T) {
	cfg := &config.Config{UserToken: "api-tok", ProxyToken: "proxy-tok"}
	srv, s := newTestPortal(t, cfg)
	u, b := seedUserBackendAccount(t, s)

	hdrs := map[string]string{"Authorization": "Bearer api-tok"}
	body := map[string]any{
		"user_id": u.ID, "backend_addr": b.Address(), "role": "app",
		"database": "orders", "portal_password": "p-pw",
	}
	resp := postJSON(t, srv.URL+"/api/v1/grants", body, hdrs)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status=%d", resp.StatusCode)
	}
	var g domain.Grant
	_ = json.NewDecoder(resp.Body).Decode(&g)
	if g.Status != domain.GrantPending {
		t.Fatalf("expected PENDING, got %s", g.Status)
	}

	// /auth must refuse — PENDING is not APPROVED so the policy engine filters
	// it out and returns ErrGrantExpired → 403.
	authReq := auth.LookupRequest{Username: "alice", ProxyType: "mongo", BackendServer: b.Address()}
	authResp := postJSON(t, srv.URL+"/api/v1/auth", authReq, map[string]string{"X-Portal-Token": "proxy-tok"})
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for PENDING grant, got %d", authResp.StatusCode)
	}
}

// TestGrants_ApproveFlow walks the full PENDING → APPROVED → usable lifecycle.
func TestGrants_ApproveFlow(t *testing.T) {
	cfg := &config.Config{UserToken: "api-tok", ProxyToken: "proxy-tok"}
	srv, s := newTestPortal(t, cfg)
	u, b := seedUserBackendAccount(t, s)

	hdrs := map[string]string{"Authorization": "Bearer api-tok"}
	body := map[string]any{
		"user_id": u.ID, "backend_addr": b.Address(), "role": "app",
		"database": "orders", "portal_password": "p-pw",
	}
	resp := postJSON(t, srv.URL+"/api/v1/grants", body, hdrs)
	defer resp.Body.Close()
	var g domain.Grant
	_ = json.NewDecoder(resp.Body).Decode(&g)

	// Approve.
	appResp := postJSON(t, srv.URL+"/api/v1/grants/"+g.ID+"/approve", nil, hdrs)
	defer appResp.Body.Close()
	if appResp.StatusCode != http.StatusOK {
		all, _ := io.ReadAll(appResp.Body)
		t.Fatalf("approve status=%d body=%s", appResp.StatusCode, all)
	}
	var approved domain.Grant
	_ = json.NewDecoder(appResp.Body).Decode(&approved)
	if approved.Status != domain.GrantApproved {
		t.Fatalf("expected APPROVED, got %s", approved.Status)
	}
	if approved.ApprovedBy == "" || approved.ApprovedAt == nil {
		t.Errorf("approver metadata missing: %+v", approved)
	}

	// /auth now succeeds.
	authReq := auth.LookupRequest{Username: "alice", ProxyType: "mongo", BackendServer: b.Address()}
	authResp := postJSON(t, srv.URL+"/api/v1/auth", authReq, map[string]string{"X-Portal-Token": "proxy-tok"})
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusOK {
		all, _ := io.ReadAll(authResp.Body)
		t.Fatalf("expected 200 after approve, got %d body=%s", authResp.StatusCode, all)
	}
}

// TestGrants_ApproveResetsExpiresAt verifies an approval delayed past the
// original ExpiresAt refreshes the window so the grant isn't DOA.
func TestGrants_ApproveResetsExpiresAt(t *testing.T) {
	cfg := &config.Config{UserToken: "api-tok"}
	srv, s := newTestPortal(t, cfg)
	u, b := seedUserBackendAccount(t, s)

	hdrs := map[string]string{"Authorization": "Bearer api-tok"}
	body := map[string]any{
		"user_id": u.ID, "backend_addr": b.Address(), "role": "app",
		"requested_duration": "1h",
	}
	resp := postJSON(t, srv.URL+"/api/v1/grants", body, hdrs)
	defer resp.Body.Close()
	var g domain.Grant
	_ = json.NewDecoder(resp.Body).Decode(&g)
	if g.ExpiresAt == nil {
		t.Fatal("ExpiresAt nil on create")
	}
	origExpiry := *g.ExpiresAt

	// Force the stored RequestedAt back two hours so the original ExpiresAt
	// is already in the past — simulates a laggy admin approval.
	stored, _ := s.GetGrant(context.Background(), g.ID)
	stored.RequestedAt = stored.RequestedAt.Add(-2 * time.Hour)
	past := stored.RequestedAt.Add(time.Hour)
	stored.ExpiresAt = &past
	_ = s.UpdateGrant(context.Background(), stored)

	appResp := postJSON(t, srv.URL+"/api/v1/grants/"+g.ID+"/approve", nil, hdrs)
	defer appResp.Body.Close()
	if appResp.StatusCode != http.StatusOK {
		t.Fatalf("approve status=%d", appResp.StatusCode)
	}
	var approved domain.Grant
	_ = json.NewDecoder(appResp.Body).Decode(&approved)
	if approved.ExpiresAt == nil {
		t.Fatal("ExpiresAt nil after approve")
	}
	// New expiry should be after now (not before) — the grant is live.
	if approved.ExpiresAt.Before(time.Now()) {
		t.Errorf("approved grant already expired: %v (orig=%v)", approved.ExpiresAt, origExpiry)
	}
}

// TestGrants_DenyIsTerminal verifies DENIED cannot be re-approved.
func TestGrants_DenyIsTerminal(t *testing.T) {
	cfg := &config.Config{UserToken: "api-tok"}
	srv, s := newTestPortal(t, cfg)
	u, b := seedUserBackendAccount(t, s)

	hdrs := map[string]string{"Authorization": "Bearer api-tok"}
	body := map[string]any{
		"user_id": u.ID, "backend_addr": b.Address(), "role": "app",
		"database": "orders", "portal_password": "p-pw",
	}
	resp := postJSON(t, srv.URL+"/api/v1/grants", body, hdrs)
	defer resp.Body.Close()
	var g domain.Grant
	_ = json.NewDecoder(resp.Body).Decode(&g)

	// Deny.
	denyResp := postJSON(t, srv.URL+"/api/v1/grants/"+g.ID+"/deny", nil, hdrs)
	defer denyResp.Body.Close()
	if denyResp.StatusCode != http.StatusOK {
		t.Fatalf("deny status=%d", denyResp.StatusCode)
	}
	var denied domain.Grant
	_ = json.NewDecoder(denyResp.Body).Decode(&denied)
	if denied.Status != domain.GrantDenied {
		t.Fatalf("expected DENIED, got %s", denied.Status)
	}
	if denied.DeniedBy == "" || denied.DeniedAt == nil {
		t.Errorf("denier metadata missing: %+v", denied)
	}

	// Re-approving a denied grant must return 409.
	reResp := postJSON(t, srv.URL+"/api/v1/grants/"+g.ID+"/approve", nil, hdrs)
	defer reResp.Body.Close()
	if reResp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 re-approve, got %d", reResp.StatusCode)
	}
}

// TestGrants_Webhook asserts the grant_requested webhook fires on create with
// the documented payload shape, and that the HMAC signature matches the body
// when ApprovalWebhookSecret is configured.
func TestGrants_Webhook(t *testing.T) {
	type capture struct {
		body []byte
		sig  string
	}
	received := make(chan capture, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		received <- capture{body: raw, sig: r.Header.Get("X-Portal-Signature")}
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()

	const secret = "webhook-secret-xyz"
	cfg := &config.Config{UserToken: "api-tok", ApprovalWebhookURL: webhook.URL, ApprovalWebhookSecret: secret}
	srv, s := newTestPortal(t, cfg)
	u, b := seedUserBackendAccount(t, s)

	hdrs := map[string]string{"Authorization": "Bearer api-tok"}
	body := map[string]any{
		"user_id": u.ID, "backend_addr": b.Address(), "role": "app",
		"database": "orders", "reason": "hotfix #42", "portal_password": "p-pw",
	}
	resp := postJSON(t, srv.URL+"/api/v1/grants", body, hdrs)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status=%d", resp.StatusCode)
	}
	var g domain.Grant
	_ = json.NewDecoder(resp.Body).Decode(&g)

	select {
	case got := <-received:
		var payload map[string]any
		if err := json.Unmarshal(got.body, &payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		for _, key := range []string{"grant_id", "user", "backend", "role", "reason", "requested_by"} {
			if _, ok := payload[key]; !ok {
				t.Errorf("webhook payload missing %q: %+v", key, payload)
			}
		}
		if payload["grant_id"] != g.ID {
			t.Errorf("grant_id mismatch: want %s got %v", g.ID, payload["grant_id"])
		}
		if payload["role"] != "app" {
			t.Errorf("role mismatch: got %v", payload["role"])
		}
		if payload["reason"] != "hotfix #42" {
			t.Errorf("reason mismatch: got %v", payload["reason"])
		}
		// HMAC-SHA256 signature: header = "sha256=<hex>", over the raw body.
		const prefix = "sha256="
		if !strings.HasPrefix(got.sig, prefix) {
			t.Fatalf("missing sha256= signature header: %q", got.sig)
		}
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(got.body)
		want := hex.EncodeToString(mac.Sum(nil))
		if got.sig[len(prefix):] != want {
			t.Errorf("signature mismatch\n got %s\nwant %s", got.sig[len(prefix):], want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook never fired")
	}
}

// TestGrants_AutoApprove verifies the bootstrap escape hatch collapses create
// straight into APPROVED with approver "auto-approve".
func TestGrants_AutoApprove(t *testing.T) {
	cfg := &config.Config{UserToken: "api-tok", AutoApprove: true}
	srv, s := newTestPortal(t, cfg)
	u, b := seedUserBackendAccount(t, s)

	hdrs := map[string]string{"Authorization": "Bearer api-tok"}
	body := map[string]any{
		"user_id": u.ID, "backend_addr": b.Address(), "role": "app",
		"database": "orders", "portal_password": "p-pw",
	}
	resp := postJSON(t, srv.URL+"/api/v1/grants", body, hdrs)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status=%d", resp.StatusCode)
	}
	var g domain.Grant
	_ = json.NewDecoder(resp.Body).Decode(&g)
	if g.Status != domain.GrantApproved {
		t.Fatalf("auto-approve expected APPROVED, got %s", g.Status)
	}
	if g.ApprovedBy != "auto-approve" {
		t.Errorf("expected approver 'auto-approve', got %q", g.ApprovedBy)
	}
}

func TestGrantStatus_ProxyGuarded(t *testing.T) {
	cfg := &config.Config{ProxyToken: "super-secret"}
	srv, s := newTestPortal(t, cfg)
	seedFull(t, s, "portal-pw")

	// Happy path with token.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/grants/status/g-1", nil)
	req.Header.Set("X-Portal-Token", "super-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	var got map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got["id"] != "g-1" || got["status"] != "APPROVED" {
		t.Errorf("unexpected payload: %+v", got)
	}

	// Without token → 401.
	req2, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/grants/status/g-1", nil)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", resp2.StatusCode)
	}

	// Revoke the grant and verify the status flips.
	g, _ := s.GetGrant(context.Background(), "g-1")
	g.Status = domain.GrantRevoked
	_ = s.UpdateGrant(context.Background(), g)

	req3, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/grants/status/g-1", nil)
	req3.Header.Set("X-Portal-Token", "super-secret")
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp3.StatusCode)
	}
	var got2 map[string]any
	_ = json.NewDecoder(resp3.Body).Decode(&got2)
	if got2["status"] != "REVOKED" {
		t.Errorf("expected REVOKED, got %v", got2["status"])
	}

	// Missing grant → 404.
	req4, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/grants/status/g-404", nil)
	req4.Header.Set("X-Portal-Token", "super-secret")
	resp4, err := http.DefaultClient.Do(req4)
	if err != nil {
		t.Fatal(err)
	}
	defer resp4.Body.Close()
	if resp4.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp4.StatusCode)
	}
}

func TestAdmin_SeedUserAndBackend(t *testing.T) {
	cfg := &config.Config{}
	srv, s := newTestPortal(t, cfg)

	u := postJSON(t, srv.URL+"/api/v1/users", map[string]string{"username": "bob"}, nil)
	defer u.Body.Close()
	if u.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(u.Body)
		t.Fatalf("create user status=%d body=%s", u.StatusCode, body)
	}

	b := postJSON(t, srv.URL+"/api/v1/backends",
		map[string]any{"name": "mongo-b", "type": "mongo", "host": "127.0.0.1", "port": 27018}, nil)
	defer b.Body.Close()
	if b.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(b.Body)
		t.Fatalf("create backend status=%d body=%s", b.StatusCode, body)
	}

	backends, _ := s.ListBackends(context.Background())
	if len(backends) != 1 {
		t.Fatalf("expected 1 backend, got %d", len(backends))
	}

	acct := postJSON(t, srv.URL+"/api/v1/backends/"+backends[0].ID+"/accounts",
		map[string]string{"role": "app", "username": "app", "password": "secret"}, nil)
	defer acct.Body.Close()
	if acct.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(acct.Body)
		t.Fatalf("upsert account status=%d body=%s", acct.StatusCode, body)
	}
}

