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

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/notify"
	"github.com/babs/poc-proxies/portal/internal/oidc"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// injectSession wraps next with a middleware that stashes sess in the request
// context under the same key requireUserAuth uses at runtime. Lets tests
// exercise non-admin scoping without spinning up a real OIDC dance.
func injectSession(sess *oidc.Session, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), sessionContextKey{}, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// newScopingPortal builds a grantsHandler directly (avoiding the router's
// static-bearer fallback) so we can drive admin vs non-admin paths via
// context-injection alone.
func newScopingPortal(t *testing.T, sess *oidc.Session) (*httptest.Server, store.Store) {
	t.Helper()
	s := store.NewMemory()
	h := &grantsHandler{store: s, logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), notifier: notify.Noop{}}
	mux := http.NewServeMux()
	registerGrantRoutes(mux, h)
	srv := httptest.NewServer(injectSession(sess, mux))
	t.Cleanup(srv.Close)
	return srv, s
}

// seedTwoUsersAndGrants creates two users, a backend, and one grant per user,
// so list-scoping can be compared.
func seedTwoUsersAndGrants(t *testing.T, s store.Store) (alice, bob domain.User) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	alice = domain.User{ID: "u-alice", Username: "alice", ExternalID: "sub-alice", Status: "active", CreatedAt: now, UpdatedAt: now}
	bob = domain.User{ID: "u-bob", Username: "bob", ExternalID: "sub-bob", Status: "active", CreatedAt: now, UpdatedAt: now}
	if err := s.CreateUser(ctx, alice); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, bob); err != nil {
		t.Fatal(err)
	}
	b := domain.Backend{ID: "b-1", Name: "m", Type: domain.ProxyMongo, Host: "127.0.0.1", Port: 27017, CreatedAt: now, UpdatedAt: now}
	if err := s.CreateBackend(ctx, b); err != nil {
		t.Fatal(err)
	}
	for i, uid := range []string{alice.ID, bob.ID} {
		g := domain.Grant{
			ID: domain.NewID("g"), UserID: uid, BackendID: b.ID,
			Role: domain.RoleApp, Status: domain.GrantApproved,
			RequestedAt: now, CreatedAt: now.Add(time.Duration(i) * time.Second), UpdatedAt: now,
		}
		if err := s.CreateGrant(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	return alice, bob
}

// TestGrants_List_AdminSeesAll verifies an admin session (IsOperator=true) gets
// every grant regardless of user_id filter.
func TestGrants_List_AdminSeesAll(t *testing.T) {
	admin := &oidc.Session{ID: "s-admin", Subject: "sub-admin", IsOperator: true, PortalUserID: "u-admin", ExpiresAt: time.Now().Add(time.Hour)}
	srv, s := newScopingPortal(t, admin)
	seedTwoUsersAndGrants(t, s)

	resp, err := http.Get(srv.URL + "/api/v1/grants")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var got []domain.Grant
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if len(got) != 2 {
		t.Fatalf("admin should see 2 grants, got %d", len(got))
	}
}

// TestGrants_List_NonAdminScopedToSelf asserts a non-admin session only
// receives grants whose user_id matches its PortalUserID, even when the query
// explicitly asks for another user.
func TestGrants_List_NonAdminScopedToSelf(t *testing.T) {
	// Bob's session: not an admin.
	bob := &oidc.Session{ID: "s-bob", Subject: "sub-bob", IsOperator: false, PortalUserID: "u-bob", ExpiresAt: time.Now().Add(time.Hour)}
	srv, s := newScopingPortal(t, bob)
	seedTwoUsersAndGrants(t, s)

	// Even asking for alice's grants returns only bob's own.
	resp, err := http.Get(srv.URL + "/api/v1/grants?user_id=u-alice")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var got []domain.Grant
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if len(got) != 1 {
		t.Fatalf("bob should see 1 grant (his own), got %d", len(got))
	}
	if got[0].UserID != "u-bob" {
		t.Errorf("leaked someone else's grant: %+v", got[0])
	}
}

// TestGrants_Create_NonAdminSelfOnly asserts non-admin sessions can create
// grants for themselves (explicit or derived) but get 403 when targeting
// another user_id.
func TestGrants_Create_NonAdminSelfOnly(t *testing.T) {
	bob := &oidc.Session{ID: "s-bob", Subject: "sub-bob", IsOperator: false, PortalUserID: "u-bob", ExpiresAt: time.Now().Add(time.Hour)}
	srv, s := newScopingPortal(t, bob)
	_, _ = seedTwoUsersAndGrants(t, s)

	// Derived user_id: POST without user_id should succeed and bind to bob.
	resp := postJSON(t, srv.URL+"/api/v1/grants",
		map[string]any{"backend_addr": "127.0.0.1:27017", "role": "app", "portal_password": "pw"},
		nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("self-create status=%d body=%s", resp.StatusCode, body)
	}
	var g domain.Grant
	_ = json.NewDecoder(resp.Body).Decode(&g)
	if g.UserID != "u-bob" {
		t.Errorf("derived user_id = %s, want u-bob", g.UserID)
	}

	// Explicit other-user target: 403.
	resp2 := postJSON(t, srv.URL+"/api/v1/grants",
		map[string]any{"user_id": "u-alice", "backend_addr": "127.0.0.1:27017", "role": "app", "portal_password": "pw"},
		nil)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-user create expected 403, got %d", resp2.StatusCode)
	}
}

// TestGrants_Approve_AdminOnly asserts /approve still rejects non-admin
// sessions after the blanket ServeHTTP gate was removed.
func TestGrants_Approve_AdminOnly(t *testing.T) {
	bob := &oidc.Session{ID: "s-bob", Subject: "sub-bob", IsOperator: false, PortalUserID: "u-bob", ExpiresAt: time.Now().Add(time.Hour)}
	srv, s := newScopingPortal(t, bob)
	_, _ = seedTwoUsersAndGrants(t, s)

	// Create a pending grant directly in the store so we have something
	// to attempt to approve.
	ctx := context.Background()
	now := time.Now().UTC()
	g := domain.Grant{
		ID: "g-pending", UserID: "u-bob", BackendID: "b-1",
		Role: domain.RoleApp, Status: domain.GrantPending,
		RequestedAt: now, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.CreateGrant(ctx, g); err != nil {
		t.Fatal(err)
	}

	resp := postJSON(t, srv.URL+"/api/v1/grants/g-pending/approve", nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin approve expected 403, got %d", resp.StatusCode)
	}
}

// TestOIDCProvisioner_FirstLoginCreatesUser asserts the store-backed
// UserProvisioner materialises a new user on first-login and reuses it on
// subsequent calls for the same subject.
func TestOIDCProvisioner_FirstLoginCreatesUser(t *testing.T) {
	s := store.NewMemory()
	p := StoreUserProvisioner{Store: s}
	ctx := context.Background()

	uid1, isAdmin1, err := p.ProvisionOIDCUser(ctx, "sub-xyz", "carol@example.com", "carol", true)
	if err != nil {
		t.Fatal(err)
	}
	if uid1 == "" {
		t.Fatal("empty uid on first login")
	}
	if !isAdmin1 {
		t.Errorf("claim isOperator=true should carry through on first login")
	}

	// Verify the store row exists with the expected external_id.
	u, err := s.GetUserByExternalID(ctx, "sub-xyz")
	if err != nil {
		t.Fatalf("GetUserByExternalID after provisioning: %v", err)
	}
	if u.ID != uid1 {
		t.Errorf("store uid=%s provisioned uid=%s", u.ID, uid1)
	}
	if u.Username != "carol" {
		t.Errorf("username=%q, want carol", u.Username)
	}
	if u.ExternalID != "sub-xyz" {
		t.Errorf("external_id=%q, want sub-xyz", u.ExternalID)
	}
	if !u.IsOperator {
		t.Error("stored IsOperator lost")
	}

	// Second call for the same subject: same uid, admin flag tracks the
	// persisted value rather than the caller-supplied claim.
	uid2, isAdmin2, err := p.ProvisionOIDCUser(ctx, "sub-xyz", "carol@example.com", "carol", false)
	if err != nil {
		t.Fatal(err)
	}
	if uid2 != uid1 {
		t.Errorf("returning uid=%s, want %s", uid2, uid1)
	}
	if !isAdmin2 {
		t.Error("persisted IsOperator should override a now-false claim")
	}
}

// TestOIDCProvisioner_EmailFallbackUsername verifies that when
// preferred_username is empty we fall back to the email local-part, and if
// both are empty, to the raw subject.
func TestOIDCProvisioner_EmailFallbackUsername(t *testing.T) {
	s := store.NewMemory()
	p := StoreUserProvisioner{Store: s}
	ctx := context.Background()

	uid, _, err := p.ProvisionOIDCUser(ctx, "sub-a", "dan@example.com", "", false)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := s.GetUser(ctx, uid)
	if u.Username != "dan" {
		t.Errorf("username=%q, want email-prefix dan", u.Username)
	}

	uid2, _, err := p.ProvisionOIDCUser(ctx, "sub-b", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	u2, _ := s.GetUser(ctx, uid2)
	if u2.Username != "sub-b" {
		t.Errorf("username=%q, want raw subject", u2.Username)
	}
}
