package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/store"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSQLite_UsersCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	u := domain.User{ID: "u-1", Username: "alice", Status: "active", IsAdmin: true, CreatedAt: now, UpdatedAt: now}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, u); !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
	got, err := s.GetUserByUsername(ctx, "alice")
	if err != nil || got.ID != "u-1" || !got.IsAdmin {
		t.Fatalf("lookup: %+v %v", got, err)
	}
	if _, err := s.GetUser(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSQLite_BackendsAndAccounts(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	b := domain.Backend{ID: "b-1", Name: "mongo", Type: domain.ProxyMongo, Host: "127.0.0.1", Port: 27017, Databases: []string{"orders", "billing"}, CreatedAt: now, UpdatedAt: now}
	if err := s.CreateBackend(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateBackend(ctx, b); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected conflict on duplicate addr, got %v", err)
	}
	got, err := s.GetBackendByAddress(ctx, "127.0.0.1:27017")
	if err != nil || got.ID != "b-1" || len(got.Databases) != 2 {
		t.Fatalf("lookup: %+v %v", got, err)
	}

	a := domain.BackendAccount{ID: "ba-1", BackendID: "b-1", Role: domain.RoleApp, Username: "app", Password: "pw1", CreatedAt: now, UpdatedAt: now}
	if err := s.UpsertBackendAccount(ctx, a); err != nil {
		t.Fatal(err)
	}
	// Upsert on same (backend, role) — new ID but same slot.
	a2 := a
	a2.ID = "ba-2"
	a2.Password = "pw2"
	if err := s.UpsertBackendAccount(ctx, a2); err != nil {
		t.Fatal(err)
	}
	gotAcct, err := s.GetBackendAccount(ctx, "b-1", domain.RoleApp)
	if err != nil || gotAcct.Password != "pw2" {
		t.Fatalf("account upsert didn't overwrite password: %+v err=%v", gotAcct, err)
	}
}

func TestSQLite_GrantsLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Seed parent rows so FK constraints hold.
	_ = s.CreateUser(ctx, domain.User{ID: "u-1", Username: "alice", Status: "active", CreatedAt: now, UpdatedAt: now})
	_ = s.CreateBackend(ctx, domain.Backend{ID: "b-1", Name: "mongo", Type: domain.ProxyMongo, Host: "127.0.0.1", Port: 27017, CreatedAt: now, UpdatedAt: now})

	exp := now.Add(time.Hour)
	g := domain.Grant{
		ID: "g-1", UserID: "u-1", BackendID: "b-1", Role: domain.RoleApp,
		Database: "orders", Status: domain.GrantPending, ExpiresAt: &exp,
		RequestedAt: now, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.CreateGrant(ctx, g); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetGrant(ctx, "g-1")
	if err != nil || got.ExpiresAt == nil {
		t.Fatalf("get grant: %+v %v", got, err)
	}

	got.Status = domain.GrantApproved
	got.ApprovedBy = "admin"
	ap := now.Add(time.Minute)
	got.ApprovedAt = &ap
	if err := s.UpdateGrant(ctx, got); err != nil {
		t.Fatal(err)
	}
	approved, err := s.ListGrants(ctx, store.GrantFilter{Statuses: []domain.GrantStatus{domain.GrantApproved}})
	if err != nil || len(approved) != 1 {
		t.Fatalf("list approved: %d err=%v", len(approved), err)
	}

	pending, _ := s.ListGrants(ctx, store.GrantFilter{UserID: "u-1", Statuses: []domain.GrantStatus{domain.GrantPending}})
	if len(pending) != 0 {
		t.Fatalf("expected 0 pending, got %d", len(pending))
	}
}

func TestSQLite_AuditAppendAndPrune(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	var entries []domain.AuditEntry
	for i := 0; i < 10; i++ {
		entries = append(entries, domain.AuditEntry{
			Timestamp: now.Add(-time.Duration(10-i) * time.Hour),
			GrantID:   "g-1", Username: "alice", Query: "SELECT 1",
		})
	}
	if err := s.AppendAudit(ctx, entries); err != nil {
		t.Fatal(err)
	}
	got, _ := s.ListAudit(ctx, store.AuditFilter{GrantID: "g-1"})
	if len(got) != 10 {
		t.Fatalf("pre-prune got %d", len(got))
	}

	// Retention: keep last 5 hours → 5 rows survive.
	cutoff := now.Add(-5 * time.Hour)
	pruned, total, err := s.PruneAudit(ctx, cutoff, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 {
		t.Fatalf("expected 5 after age prune, got %d", total)
	}
	if pruned < 5 {
		t.Fatalf("expected pruned >= 5, got %d", pruned)
	}

	// Cap: drop to 3.
	_, total, err = s.PruneAudit(ctx, time.Time{}, 3)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Fatalf("expected 3 after cap prune, got %d", total)
	}
}

func TestSQLite_FileBacked_RoundTrip(t *testing.T) {
	// Verifies migrations are idempotent on a real file and data survives a
	// reopen — the critical acceptance criterion for 1.1.
	dir := t.TempDir()
	path := filepath.Join(dir, "portal.db")

	s1, err := Open("file:" + path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open1: %v", err)
	}
	now := time.Now().UTC()
	if err := s1.CreateUser(context.Background(), domain.User{ID: "u-1", Username: "alice", Status: "active", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	_ = s1.Close()

	s2, err := Open("file:" + path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open2: %v", err)
	}
	defer s2.Close()
	got, err := s2.GetUserByUsername(context.Background(), "alice")
	if err != nil || got.ID != "u-1" {
		t.Fatalf("restart lookup: %+v err=%v", got, err)
	}
}
