package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
	acct := domain.BackendAccount{ID: "ba-1", BackendID: "b-1", Role: domain.RoleApp, Username: "app", Password: "secret"}
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
	if created.Status != domain.GrantApproved {
		t.Errorf("expected auto-approved, got %s", created.Status)
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

