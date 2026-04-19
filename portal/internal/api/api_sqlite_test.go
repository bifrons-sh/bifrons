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

	// Register the sqlite driver — required for NewFromURL("sqlite::memory:").
	_ "github.com/babs/poc-proxies/portal/internal/store/sqlite"
)

// newSQLitePortal mirrors newTestPortal but uses a sqlite-backed store so the
// API surface is exercised against the persistent driver (phase 1.1 AC: API
// tests run unchanged against NewFromURL("sqlite::memory:")).
func newSQLitePortal(t *testing.T, cfg *config.Config) (*httptest.Server, store.Store) {
	t.Helper()
	s, err := store.NewFromURL("sqlite::memory:")
	if err != nil {
		t.Fatalf("sqlite open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	eng := policy.New(s)
	h := NewRouter(cfg, s, eng, nil, slog.New(slog.NewJSONHandler(io.Discard, nil)), nil)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, s
}

func TestSQLite_AuthEndpoint_Success(t *testing.T) {
	cfg := &config.Config{ProxyToken: "super-secret"}
	srv, s := newSQLitePortal(t, cfg)

	ctx := context.Background()
	now := time.Now().UTC()
	_ = s.CreateUser(ctx, domain.User{ID: "u-1", Username: "alice", Status: "active", CreatedAt: now, UpdatedAt: now})
	_ = s.CreateBackend(ctx, domain.Backend{ID: "b-1", Name: "mongo", Type: domain.ProxyMongo, Host: "127.0.0.1", Port: 27017, CreatedAt: now, UpdatedAt: now})
	_ = s.UpsertBackendAccount(ctx, domain.BackendAccount{ID: "ba-1", BackendID: "b-1", Role: domain.RoleApp, Username: "app", Password: "secret", CreatedAt: now, UpdatedAt: now})
	exp := now.Add(time.Hour)
	_ = s.CreateGrant(ctx, domain.Grant{
		ID: "g-1", UserID: "u-1", BackendID: "b-1", Status: domain.GrantApproved,
		Role: domain.RoleApp, Database: "orders", PortalPassword: "portal-pw",
		ExpiresAt: &exp, RequestedAt: now, CreatedAt: now, UpdatedAt: now,
	})

	body, _ := json.Marshal(auth.LookupRequest{Username: "alice", SourceIP: "10.0.0.1", ProxyType: "mongo", BackendServer: "127.0.0.1:27017"})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/auth", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Portal-Token", "super-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
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

func TestSQLite_AuditEndpoint_AcceptsBatchAndPersists(t *testing.T) {
	cfg := &config.Config{}
	srv, s := newSQLitePortal(t, cfg)

	batch := map[string]any{
		"entries": []domain.AuditEntry{
			{GrantID: "g-1", Username: "alice", Query: "SELECT 1", Timestamp: time.Now().UTC()},
			{GrantID: "g-1", Username: "alice", Query: "SELECT 2", Timestamp: time.Now().UTC()},
		},
	}
	raw, _ := json.Marshal(batch)
	resp, err := http.Post(srv.URL+"/api/v1/audit/query", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("want 202, got %d", resp.StatusCode)
	}
	stored, _ := s.ListAudit(context.Background(), store.AuditFilter{GrantID: "g-1"})
	if len(stored) != 2 {
		t.Fatalf("stored=%d", len(stored))
	}
}
