package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/babs/poc-proxies/internal/auth"
	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/store"
)

func seed(t *testing.T) (*store.Memory, domain.User, domain.Backend) {
	t.Helper()
	m := store.NewMemory()
	ctx := context.Background()

	u := domain.User{ID: "u-1", Username: "alice", Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := m.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	b := domain.Backend{ID: "b-1", Name: "mongo-a", Type: domain.ProxyMongo, Host: "127.0.0.1", Port: 27017}
	if err := m.CreateBackend(ctx, b); err != nil {
		t.Fatal(err)
	}
	acct := domain.BackendAccount{ID: "ba-1", BackendID: "b-1", Role: domain.RoleApp, Username: "app_user", Password: "app_pw"}
	if err := m.UpsertBackendAccount(ctx, acct); err != nil {
		t.Fatal(err)
	}
	return m, u, b
}

func grant(u domain.User, b domain.Backend, expires *time.Time, status domain.GrantStatus, portalPW string) domain.Grant {
	return domain.Grant{
		ID:             domain.NewID("g"),
		UserID:         u.ID,
		BackendID:      b.ID,
		Role:           domain.RoleApp,
		Database:       "orders",
		Status:         status,
		ExpiresAt:      expires,
		PortalPassword: portalPW,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
}

func TestResolve_Success(t *testing.T) {
	m, u, b := seed(t)
	ctx := context.Background()
	expires := time.Now().Add(time.Hour)
	if err := m.CreateGrant(ctx, grant(u, b, &expires, domain.GrantApproved, "portal-pw")); err != nil {
		t.Fatal(err)
	}

	resp, err := New(m).Resolve(ctx, auth.LookupRequest{
		Username: "alice", SourceIP: "10.0.0.1", ProxyType: "mongo", BackendServer: "127.0.0.1:27017",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Password != "portal-pw" || resp.BackendUser != "app_user" || resp.BackendPass != "app_pw" {
		t.Errorf("bad mapping: %+v", resp)
	}
	if resp.GrantID == "" || resp.Role != "app" {
		t.Errorf("missing metadata: %+v", resp)
	}
	if len(resp.AllowedDBs) != 1 || resp.AllowedDBs[0] != "orders" {
		t.Errorf("allowed_dbs = %v", resp.AllowedDBs)
	}
}

func TestResolve_NoUser(t *testing.T) {
	m := store.NewMemory()
	_, err := New(m).Resolve(context.Background(), auth.LookupRequest{
		Username: "ghost", ProxyType: "mongo", BackendServer: "127.0.0.1:27017",
	})
	if !errors.Is(err, ErrNoActiveGrant) {
		t.Fatalf("want ErrNoActiveGrant, got %v", err)
	}
}

func TestResolve_ProxyTypeMismatch(t *testing.T) {
	m, u, b := seed(t)
	ctx := context.Background()
	expires := time.Now().Add(time.Hour)
	_ = m.CreateGrant(ctx, grant(u, b, &expires, domain.GrantApproved, "pw"))

	_, err := New(m).Resolve(ctx, auth.LookupRequest{
		Username: u.Username, ProxyType: "mysql", BackendServer: b.Address(),
	})
	if err == nil {
		t.Fatal("expected proxy-type mismatch error")
	}
}

func TestResolve_Expired(t *testing.T) {
	m, u, b := seed(t)
	ctx := context.Background()
	past := time.Now().Add(-time.Minute)
	_ = m.CreateGrant(ctx, grant(u, b, &past, domain.GrantApproved, "pw"))

	_, err := New(m).Resolve(ctx, auth.LookupRequest{
		Username: u.Username, ProxyType: "mongo", BackendServer: b.Address(),
	})
	if !errors.Is(err, ErrGrantExpired) {
		t.Fatalf("want ErrGrantExpired, got %v", err)
	}
}

func TestResolve_Revoked(t *testing.T) {
	m, u, b := seed(t)
	ctx := context.Background()
	expires := time.Now().Add(time.Hour)
	now := time.Now()
	g := grant(u, b, &expires, domain.GrantApproved, "pw")
	g.RevokedAt = &now
	g.Status = domain.GrantRevoked
	_ = m.CreateGrant(ctx, g)

	_, err := New(m).Resolve(ctx, auth.LookupRequest{
		Username: u.Username, ProxyType: "mongo", BackendServer: b.Address(),
	})
	if !errors.Is(err, ErrGrantExpired) {
		t.Fatalf("want ErrGrantExpired for revoked, got %v", err)
	}
}

func TestResolve_PasswordRef_Resolved(t *testing.T) {
	m, u, b := seed(t)
	ctx := context.Background()
	// Replace the account with one that carries a PasswordRef instead of a
	// cleartext Password to exercise the Phase 1.4 resolver branch.
	acct := domain.BackendAccount{ID: "ba-1", BackendID: "b-1", Role: domain.RoleApp, Username: "app_user", PasswordRef: "env://UNIT_TEST_REF_PW"}
	if err := m.UpsertBackendAccount(ctx, acct); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour)
	if err := m.CreateGrant(ctx, grant(u, b, &expires, domain.GrantApproved, "pw")); err != nil {
		t.Fatal(err)
	}

	eng := New(m).WithSecretsResolver(func(ref string) (string, error) {
		if ref != "env://UNIT_TEST_REF_PW" {
			t.Fatalf("unexpected ref %q", ref)
		}
		return "from-resolver", nil
	})
	resp, err := eng.Resolve(ctx, auth.LookupRequest{
		Username: u.Username, ProxyType: "mongo", BackendServer: b.Address(),
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp.BackendPass != "from-resolver" {
		t.Fatalf("backend pass = %q, want from-resolver", resp.BackendPass)
	}
}

func TestResolve_PasswordRef_FailClosed(t *testing.T) {
	m, u, b := seed(t)
	ctx := context.Background()
	acct := domain.BackendAccount{ID: "ba-1", BackendID: "b-1", Role: domain.RoleApp, Username: "app_user", PasswordRef: "env://MISSING", Password: "legacy-should-not-leak"}
	if err := m.UpsertBackendAccount(ctx, acct); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour)
	_ = m.CreateGrant(ctx, grant(u, b, &expires, domain.GrantApproved, "pw"))

	eng := New(m).WithSecretsResolver(func(ref string) (string, error) {
		return "", errors.New("not found")
	})
	_, err := eng.Resolve(ctx, auth.LookupRequest{
		Username: u.Username, ProxyType: "mongo", BackendServer: b.Address(),
	})
	if !errors.Is(err, ErrGrantExpired) {
		t.Fatalf("want generic denial (ErrGrantExpired), got %v", err)
	}
}

func TestResolve_DisabledUser(t *testing.T) {
	m, u, b := seed(t)
	ctx := context.Background()
	u.Status = "disabled"
	_ = m.CreateUser(ctx, u) // no-op for duplicate; set via update path in real impl
	_ = b

	_, err := New(m).Resolve(ctx, auth.LookupRequest{
		Username: u.Username, ProxyType: "mongo", BackendServer: b.Address(),
	})
	if err == nil {
		t.Fatal("expected denial for disabled user")
	}
}
