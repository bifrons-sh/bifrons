package ephemeral

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/store"
)

func TestOrphanSweepHook_RevokesAndClears(t *testing.T) {
	s := store.NewMemory()
	ctx := context.Background()

	// Seed backend + orphan grant.
	b := domain.Backend{ID: "b-1", Name: "pg", Type: domain.ProxyPostgres, Host: "h", Port: 5432}
	if err := s.CreateBackend(ctx, b); err != nil {
		t.Fatal(err)
	}
	u := domain.User{ID: "u-1", Username: "alice", Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(-time.Hour) // already expired, terminal state
	g := domain.Grant{
		ID: "g-orphan", UserID: u.ID, BackendID: b.ID, Role: domain.RoleApp,
		Status: domain.GrantRevoked, EphemeralUsername: "portal_grant_x",
		EphemeralPassword: "pw", RequestedAt: time.Now(),
		ExpiresAt: &exp, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateGrant(ctx, g); err != nil {
		t.Fatal(err)
	}

	fake := &fakeProv{}
	mgr := NewManager(map[BackendType]Provisioner{BackendPostgres: fake}, NewMetrics(), nil)

	hook := OrphanSweepHook(mgr, slog.New(slog.NewTextHandler(io.Discard, nil)))
	hook(ctx, s)

	got, _ := s.GetGrant(ctx, "g-orphan")
	if got.EphemeralUsername != "" {
		t.Errorf("expected EphemeralUsername cleared, got %q", got.EphemeralUsername)
	}
	_, rev, _, _ := mgr.Metrics().Snapshot()
	if rev != 1 {
		t.Errorf("expected 1 revoke, got %d", rev)
	}
}

func TestOrphanSweepHook_SkipsNonTerminal(t *testing.T) {
	s := store.NewMemory()
	ctx := context.Background()
	b := domain.Backend{ID: "b-1", Name: "pg", Type: domain.ProxyPostgres, Host: "h", Port: 5432}
	_ = s.CreateBackend(ctx, b)
	u := domain.User{ID: "u-1", Username: "alice", Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	_ = s.CreateUser(ctx, u)
	exp := time.Now().Add(time.Hour)
	// APPROVED + ephemeral user = still active, must not be swept.
	g := domain.Grant{
		ID: "g-live", UserID: u.ID, BackendID: b.ID, Role: domain.RoleApp,
		Status: domain.GrantApproved, EphemeralUsername: "portal_grant_x",
		EphemeralPassword: "pw", RequestedAt: time.Now(),
		ExpiresAt: &exp, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	_ = s.CreateGrant(ctx, g)

	fake := &fakeProv{}
	mgr := NewManager(map[BackendType]Provisioner{BackendPostgres: fake}, NewMetrics(), nil)
	hook := OrphanSweepHook(mgr, slog.New(slog.NewTextHandler(io.Discard, nil)))
	hook(ctx, s)

	got, _ := s.GetGrant(ctx, "g-live")
	if got.EphemeralUsername == "" {
		t.Error("APPROVED grant's ephemeral creds were cleared by sweep")
	}
	_, rev, _, _ := mgr.Metrics().Snapshot()
	if rev != 0 {
		t.Errorf("APPROVED grant should not trigger revoke, got %d", rev)
	}
}
