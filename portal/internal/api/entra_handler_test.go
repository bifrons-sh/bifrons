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
	"github.com/babs/poc-proxies/portal/internal/notify"
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
// user whose group (from the portal store) is in the policy creates a grant →
// 201, ApproverHint is populated from the store-resolved validator, and SendMail
// is invoked with the validator's address as recipient.
func TestGrants_Entra_AllowedByPolicy(t *testing.T) {
	fc := entra.NewFakeClient()
	pol := policy.NewRequestPolicy(map[string]map[policy.Trio]policy.AccessMode{
		"dev-team": {{Instance: "pg-prod", Database: "orders", Level: "app"}: policy.ModePermanent},
	})
	metrics := notify.NewEntraMetrics()

	cfg := &config.Config{}
	deps := RouterDeps{
		Entra: fc, RequestPol: pol,
		EntraSender: "noreply@example.com", PublicURL: "https://portal.example.com",
		EntraMetrics: metrics,
	}
	sess := &oidc.Session{Subject: "sub-alice", PortalUserID: "u-1", Email: "alice@example.com", ExpiresAt: time.Now().Add(time.Hour)}

	ctx := context.Background()
	s := store.NewMemory()
	// Seed hierarchy in the store — no live IdP calls.
	_ = s.CreateUser(ctx, domain.User{ID: "u-bob", Username: "bob", Email: "bob@example.com", ExternalID: "sub-bob", Status: "active"})
	_ = s.CreateUser(ctx, domain.User{ID: "u-1", Username: "alice", DisplayName: "Alice", Status: "active", ValidatorUserID: "u-bob"})
	now := time.Now().UTC()
	_ = s.UpsertGroup(ctx, domain.Group{ID: "g-devs", Slug: "dev-team", DisplayName: "Devs", CreatedAt: now, UpdatedAt: now})
	_ = s.AddGroupMember(ctx, "g-devs", "u-1")
	bk := domain.Backend{ID: "b-prod-pg", Name: "pg-prod", Type: domain.ProxyPostgres, Host: "10.0.0.10", Port: 5432}
	_ = s.CreateBackend(ctx, bk)
	eng := policy.New(s)
	h := NewRouter(cfg, s, eng, slog.New(slog.NewJSONHandler(io.Discard, nil)), deps.Options()...)
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

	got, _, _, valFail := metrics.Snapshot()
	if got != 1 {
		t.Errorf("emailSent counter=%d want 1", got)
	}
	if valFail != 0 {
		t.Errorf("validatorLookupFailed=%d want 0", valFail)
	}
}

// TestGrants_Entra_RejectedByPolicy asserts that a non-admin whose groups
// don't grant (backend, role) gets 403 and the grant isn't persisted.
func TestGrants_Entra_RejectedByPolicy(t *testing.T) {
	fc := entra.NewFakeClient()
	pol := policy.NewRequestPolicy(map[string]map[policy.Trio]policy.AccessMode{
		"dev-team": {{Instance: "pg-prod", Database: "orders", Level: "app"}: policy.ModePermanent},
	})
	metrics := notify.NewEntraMetrics()

	cfg := &config.Config{}
	deps := RouterDeps{Entra: fc, RequestPol: pol, EntraSender: "n@e.com", EntraMetrics: metrics}
	sess := &oidc.Session{Subject: "sub-alice", PortalUserID: "u-1", ExpiresAt: time.Now().Add(time.Hour)}

	ctx := context.Background()
	s := store.NewMemory()
	_ = s.CreateUser(ctx, domain.User{ID: "u-1", Username: "alice", Status: "active"})
	// alice is in a DIFFERENT group than the one the policy allows.
	now := time.Now().UTC()
	_ = s.UpsertGroup(ctx, domain.Group{ID: "g-other", Slug: "other-team", CreatedAt: now, UpdatedAt: now})
	_ = s.AddGroupMember(ctx, "g-other", "u-1")
	_ = s.CreateBackend(ctx, domain.Backend{ID: "b-prod-pg", Name: "pg", Type: domain.ProxyPostgres, Host: "10.0.0.10", Port: 5432})

	h := NewRouter(cfg, s, policy.New(s), slog.New(slog.NewJSONHandler(io.Discard, nil)), deps.Options()...)
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

// TestGrants_Entra_ValidatorNotFound asserts the missing-validator path: when
// the requester has no ValidatorUserID on file, the grant is still created
// (PENDING), ApproverHint stays empty, and no email is sent (no recipient).
// The lookup counter stays at zero because there's no validator to miss.
func TestGrants_Entra_ValidatorNotFound(t *testing.T) {
	fc := entra.NewFakeClient()
	pol := policy.NewRequestPolicy(map[string]map[policy.Trio]policy.AccessMode{
		"dev-team": {{Instance: "pg", Database: "orders", Level: "app"}: policy.ModePermanent},
	})
	metrics := notify.NewEntraMetrics()

	cfg := &config.Config{}
	deps := RouterDeps{Entra: fc, RequestPol: pol, EntraSender: "n@e.com", EntraMetrics: metrics}
	sess := &oidc.Session{Subject: "sub-alice", PortalUserID: "u-1", ExpiresAt: time.Now().Add(time.Hour)}

	ctx := context.Background()
	s := store.NewMemory()
	_ = s.CreateUser(ctx, domain.User{ID: "u-1", Username: "alice", Status: "active"})
	now := time.Now().UTC()
	_ = s.UpsertGroup(ctx, domain.Group{ID: "g-devs", Slug: "dev-team", CreatedAt: now, UpdatedAt: now})
	_ = s.AddGroupMember(ctx, "g-devs", "u-1")
	_ = s.CreateBackend(ctx, domain.Backend{ID: "b-prod-pg", Name: "pg", Type: domain.ProxyPostgres, Host: "10.0.0.10", Port: 5432})

	h := NewRouter(cfg, s, policy.New(s), slog.New(slog.NewJSONHandler(io.Discard, nil)), deps.Options()...)
	h = withSession(h, sess)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	body := map[string]any{"user_id": "u-1", "backend_addr": "10.0.0.10:5432", "role": "app", "database": "orders"}
	resp := postJSON(t, srv.URL+"/api/v1/grants", body, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("want 201, got %d body=%s", resp.StatusCode, raw)
	}
	var g domain.Grant
	_ = json.NewDecoder(resp.Body).Decode(&g)
	if g.ApproverHint != "" {
		t.Errorf("want empty ApproverHint on missing validator, got %q", g.ApproverHint)
	}
	// Give any background send a moment — but since there's no approver, the
	// handler must not fire the email path.
	time.Sleep(50 * time.Millisecond)
	if snap := fc.SentSnapshot(); len(snap) != 0 {
		t.Errorf("expected no emails when ApproverHint empty, got %d", len(snap))
	}
	// No ValidatorUserID on the row → we skip silently (no store miss to count).
	_, _, _, valFail := metrics.Snapshot()
	if valFail != 0 {
		t.Errorf("validatorLookupFailed=%d want 0 (no validator recorded, not a miss)", valFail)
	}
}

// TestGrants_Entra_AdminBypassesPolicy confirms an admin OIDC session skips
// the policy gate entirely — matches existing admin scaffold semantics.
func TestGrants_Entra_AdminBypassesPolicy(t *testing.T) {
	fc := entra.NewFakeClient()
	// Admin has no groups / no validator; the policy gate must not be hit.
	pol := policy.NewRequestPolicy(map[string]map[policy.Trio]policy.AccessMode{
		"guid-other": {{Instance: "pg", Database: "orders", Level: "app"}: policy.ModePermanent},
	})

	cfg := &config.Config{}
	deps := RouterDeps{Entra: fc, RequestPol: pol, EntraSender: "n@e.com", EntraMetrics: notify.NewEntraMetrics()}
	sess := &oidc.Session{Subject: "sub-admin", IsAdmin: true, ExpiresAt: time.Now().Add(time.Hour)}

	s := store.NewMemory()
	_ = s.CreateUser(context.Background(), domain.User{ID: "u-1", Username: "alice", Status: "active"})
	_ = s.CreateBackend(context.Background(), domain.Backend{ID: "b-prod-pg", Name: "pg", Type: domain.ProxyPostgres, Host: "10.0.0.10", Port: 5432})

	h := NewRouter(cfg, s, policy.New(s), slog.New(slog.NewJSONHandler(io.Discard, nil)), deps.Options()...)
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
