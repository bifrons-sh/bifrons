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
	"github.com/babs/poc-proxies/portal/internal/entra"
	"github.com/babs/poc-proxies/portal/internal/oidc"
	"github.com/babs/poc-proxies/portal/internal/policy"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// withSession wraps h with a middleware that injects sess into the request
// context using the same private key the real OIDC middleware uses. Keeps
// the Entra grant tests honest without spinning up a full OIDC provider.
func withSession(h http.Handler, sess *oidc.Session) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), sessionContextKey{}, sess)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// waitForEmail polls the fake client for up to 1s — the grant handler sends
// mail on a background goroutine, and httptest doesn't wait for it.
func waitForEmail(t *testing.T, fc *entra.FakeClient) []entra.SentMail {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		snap := fc.SentSnapshot()
		if len(snap) > 0 {
			return snap
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fc.SentSnapshot()
}

// TestGrants_Entra_AllowedByPolicy exercises the happy path: a non-admin OIDC
// user whose group is in the policy creates a grant → 201, ApproverHint is
// populated from the manager lookup, and SendMail is invoked with the
// manager's address as recipient.
func TestGrants_Entra_AllowedByPolicy(t *testing.T) {
	fc := entra.NewFakeClient()
	fc.GroupsByUser["sub-alice"] = []entra.Group{{ID: "guid-dev", DisplayName: "Devs"}}
	fc.Managers["sub-alice"] = entra.User{ID: "sub-bob", Mail: "bob@example.com", DisplayName: "Bob"}

	pol := policy.NewRequestPolicy(map[string]map[string][]string{
		"guid-dev": {"b-prod-pg": {"app"}},
	})
	metrics := NewEntraMetrics()

	cfg := &config.Config{}
	deps := RouterDeps{
		Entra: fc, RequestPol: pol,
		EntraSender: "noreply@example.com", PublicURL: "https://portal.example.com",
		EntraMetrics: metrics,
	}
	sess := &oidc.Session{Subject: "sub-alice", Email: "alice@example.com", ExpiresAt: time.Now().Add(time.Hour)}

	s := store.NewMemory()
	_ = s.CreateUser(context.Background(), domain.User{ID: "u-1", Username: "alice", DisplayName: "Alice", Status: "active"})
	bk := domain.Backend{ID: "b-prod-pg", Name: "pg-prod", Type: domain.ProxyPostgres, Host: "10.0.0.10", Port: 5432}
	_ = s.CreateBackend(context.Background(), bk)
	eng := policy.New(s)
	h := NewRouter(cfg, s, eng, nil, slog.New(slog.NewJSONHandler(io.Discard, nil)), nil, deps)
	h = withSession(h, sess)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	body := map[string]any{
		"user_id": "u-1", "backend_addr": "10.0.0.10:5432", "role": "app",
		"database": "orders", "reason": "ticket-42",
	}
	resp := postJSON(t, srv.URL+"/api/v1/grants", body, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("create status=%d body=%s", resp.StatusCode, raw)
	}
	var g domain.Grant
	_ = json.NewDecoder(resp.Body).Decode(&g)
	if g.Status != domain.GrantPending {
		t.Fatalf("want PENDING, got %s", g.Status)
	}
	if g.ApproverHint != "bob@example.com" {
		t.Errorf("ApproverHint=%q want bob@example.com", g.ApproverHint)
	}

	sent := waitForEmail(t, fc)
	if len(sent) != 1 {
		t.Fatalf("expected 1 email, got %d", len(sent))
	}
	if sent[0].From != "noreply@example.com" {
		t.Errorf("From=%q", sent[0].From)
	}
	if len(sent[0].Message.To) != 1 || sent[0].Message.To[0] != "bob@example.com" {
		t.Errorf("To=%+v", sent[0].Message.To)
	}
	if sent[0].Message.Subject == "" || sent[0].Message.TextBody == "" {
		t.Errorf("empty subject/body: %+v", sent[0].Message)
	}

	got, _, _, mgrFail := metrics.Snapshot()
	if got != 1 {
		t.Errorf("emailSent counter=%d want 1", got)
	}
	if mgrFail != 0 {
		t.Errorf("managerLookupFailed=%d want 0", mgrFail)
	}
}

// TestGrants_Entra_RejectedByPolicy asserts that a non-admin whose groups
// don't grant (backend, role) gets 403 and the grant isn't persisted.
func TestGrants_Entra_RejectedByPolicy(t *testing.T) {
	fc := entra.NewFakeClient()
	fc.GroupsByUser["sub-alice"] = []entra.Group{{ID: "guid-other"}}
	pol := policy.NewRequestPolicy(map[string]map[string][]string{
		"guid-dev": {"b-prod-pg": {"app"}},
	})
	metrics := NewEntraMetrics()

	cfg := &config.Config{}
	deps := RouterDeps{Entra: fc, RequestPol: pol, EntraSender: "n@e.com", EntraMetrics: metrics}
	sess := &oidc.Session{Subject: "sub-alice", ExpiresAt: time.Now().Add(time.Hour)}

	s := store.NewMemory()
	_ = s.CreateUser(context.Background(), domain.User{ID: "u-1", Username: "alice", Status: "active"})
	_ = s.CreateBackend(context.Background(), domain.Backend{ID: "b-prod-pg", Name: "pg", Type: domain.ProxyPostgres, Host: "10.0.0.10", Port: 5432})

	h := NewRouter(cfg, s, policy.New(s), nil, slog.New(slog.NewJSONHandler(io.Discard, nil)), nil, deps)
	h = withSession(h, sess)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	body := map[string]any{"user_id": "u-1", "backend_addr": "10.0.0.10:5432", "role": "app"}
	resp := postJSON(t, srv.URL+"/api/v1/grants", body, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}

	// No grant should have been persisted and no email sent.
	gs, _ := s.ListGrants(context.Background(), store.GrantFilter{})
	if len(gs) != 0 {
		t.Errorf("expected 0 grants after policy deny, got %d", len(gs))
	}
	if snap := fc.SentSnapshot(); len(snap) != 0 {
		t.Errorf("expected no emails on deny, got %d", len(snap))
	}
	_, _, rejected, _ := metrics.Snapshot()
	if rejected != 1 {
		t.Errorf("policyRejected=%d want 1", rejected)
	}
}

// TestGrants_Entra_ManagerNotFound asserts the manager-lookup 404 fallback:
// the grant is still created (PENDING), ApproverHint is empty, the lookup
// failure is counted, and no email is sent (no recipient).
func TestGrants_Entra_ManagerNotFound(t *testing.T) {
	fc := entra.NewFakeClient()
	fc.GroupsByUser["sub-alice"] = []entra.Group{{ID: "guid-dev"}}
	fc.ManagerMissing["sub-alice"] = true
	pol := policy.NewRequestPolicy(map[string]map[string][]string{
		"guid-dev": {"b-prod-pg": {"app"}},
	})
	metrics := NewEntraMetrics()

	cfg := &config.Config{}
	deps := RouterDeps{Entra: fc, RequestPol: pol, EntraSender: "n@e.com", EntraMetrics: metrics}
	sess := &oidc.Session{Subject: "sub-alice", ExpiresAt: time.Now().Add(time.Hour)}

	s := store.NewMemory()
	_ = s.CreateUser(context.Background(), domain.User{ID: "u-1", Username: "alice", Status: "active"})
	_ = s.CreateBackend(context.Background(), domain.Backend{ID: "b-prod-pg", Name: "pg", Type: domain.ProxyPostgres, Host: "10.0.0.10", Port: 5432})

	h := NewRouter(cfg, s, policy.New(s), nil, slog.New(slog.NewJSONHandler(io.Discard, nil)), nil, deps)
	h = withSession(h, sess)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	body := map[string]any{"user_id": "u-1", "backend_addr": "10.0.0.10:5432", "role": "app"}
	resp := postJSON(t, srv.URL+"/api/v1/grants", body, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("want 201, got %d body=%s", resp.StatusCode, raw)
	}
	var g domain.Grant
	_ = json.NewDecoder(resp.Body).Decode(&g)
	if g.ApproverHint != "" {
		t.Errorf("want empty ApproverHint on missing manager, got %q", g.ApproverHint)
	}
	// Give any background send a moment — but since there's no approver, the
	// handler must not fire the email path.
	time.Sleep(50 * time.Millisecond)
	if snap := fc.SentSnapshot(); len(snap) != 0 {
		t.Errorf("expected no emails when ApproverHint empty, got %d", len(snap))
	}
	_, _, _, mgrFail := metrics.Snapshot()
	if mgrFail != 1 {
		t.Errorf("managerLookupFailed=%d want 1", mgrFail)
	}
}

// TestGrants_Entra_AdminBypassesPolicy confirms an admin OIDC session skips
// the policy gate entirely — matches existing admin scaffold semantics.
func TestGrants_Entra_AdminBypassesPolicy(t *testing.T) {
	fc := entra.NewFakeClient()
	// Admin has no groups / no manager; the policy gate must not be hit.
	pol := policy.NewRequestPolicy(map[string]map[string][]string{
		"guid-other": {"b-prod-pg": {"app"}},
	})

	cfg := &config.Config{}
	deps := RouterDeps{Entra: fc, RequestPol: pol, EntraSender: "n@e.com", EntraMetrics: NewEntraMetrics()}
	sess := &oidc.Session{Subject: "sub-admin", IsAdmin: true, ExpiresAt: time.Now().Add(time.Hour)}

	s := store.NewMemory()
	_ = s.CreateUser(context.Background(), domain.User{ID: "u-1", Username: "alice", Status: "active"})
	_ = s.CreateBackend(context.Background(), domain.Backend{ID: "b-prod-pg", Name: "pg", Type: domain.ProxyPostgres, Host: "10.0.0.10", Port: 5432})

	h := NewRouter(cfg, s, policy.New(s), nil, slog.New(slog.NewJSONHandler(io.Discard, nil)), nil, deps)
	h = withSession(h, sess)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	body := map[string]any{"user_id": "u-1", "backend_addr": "10.0.0.10:5432", "role": "app"}
	resp := postJSON(t, srv.URL+"/api/v1/grants", body, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("admin create status=%d", resp.StatusCode)
	}
}
