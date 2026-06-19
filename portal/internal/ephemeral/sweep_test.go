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

// fakeEmitter records the grants the orphan sweeper asks to revoke. Stands in
// for *provisioning.Client so the ephemeral package test stays dependency-free.
type fakeEmitter struct {
	revoked []string
	err     error
}

func (f *fakeEmitter) EmitRevoke(_ context.Context, g domain.Grant) (domain.Intent, error) {
	if f.err != nil {
		return domain.Intent{}, f.err
	}
	f.revoked = append(f.revoked, g.ID)
	return domain.Intent{ID: "ip-" + g.ID, GrantID: g.ID, Kind: domain.IntentRevoke}, nil
}

func TestOrphanSweepHook_EmitsRevokeIntent(t *testing.T) {
	s := store.NewMemory()
	ctx := context.Background()

	// Seed backend + orphan grant (terminal state, still carries an ephemeral user).
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

	emitter := &fakeEmitter{}
	hook := OrphanSweepHook(emitter, slog.New(slog.NewTextHandler(io.Discard, nil)))
	hook(ctx, s)

	if len(emitter.revoked) != 1 || emitter.revoked[0] != "g-orphan" {
		t.Fatalf("expected 1 revoke intent for g-orphan, got %v", emitter.revoked)
	}
	// The sweeper must NOT clear the ephemeral columns — the worker does that
	// once the DROP lands. Clearing here would hide a still-live account.
	got, _ := s.GetGrant(ctx, "g-orphan")
	if got.EphemeralUsername != "portal_grant_x" {
		t.Errorf("sweeper must not clear ephemeral username before the worker drops the user, got %q", got.EphemeralUsername)
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

	emitter := &fakeEmitter{}
	hook := OrphanSweepHook(emitter, slog.New(slog.NewTextHandler(io.Discard, nil)))
	hook(ctx, s)

	if len(emitter.revoked) != 0 {
		t.Errorf("APPROVED grant should not trigger a revoke intent, got %v", emitter.revoked)
	}
}
