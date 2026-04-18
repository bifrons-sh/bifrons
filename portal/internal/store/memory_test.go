package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
)

func TestMemory_Users(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	now := time.Now()

	u := domain.User{ID: "u-1", Username: "alice", Status: "active", CreatedAt: now, UpdatedAt: now}
	if err := m.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateUser(ctx, u); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate username should return ErrConflict, got %v", err)
	}

	got, err := m.GetUserByUsername(ctx, "alice")
	if err != nil || got.ID != "u-1" {
		t.Fatalf("username lookup: %v got %+v", err, got)
	}
	got, err = m.GetUser(ctx, "u-1")
	if err != nil || got.Username != "alice" {
		t.Fatalf("id lookup: %v got %+v", err, got)
	}
	if _, err := m.GetUser(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id should be ErrNotFound, got %v", err)
	}
}

func TestMemory_Backends(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	b := domain.Backend{ID: "b-1", Name: "mongo-a", Type: domain.ProxyMongo, Host: "127.0.0.1", Port: 27017}
	if err := m.CreateBackend(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateBackend(ctx, b); !errors.Is(err, ErrConflict) {
		t.Fatal("duplicate addr should conflict")
	}
	got, err := m.GetBackendByAddress(ctx, "127.0.0.1:27017")
	if err != nil || got.ID != "b-1" {
		t.Fatalf("lookup failed: %v got %+v", err, got)
	}

	bs, err := m.ListBackends(ctx)
	if err != nil || len(bs) != 1 {
		t.Fatalf("list: %v len=%d", err, len(bs))
	}
}

func TestMemory_BackendAccounts_Upsert(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	a := domain.BackendAccount{ID: "ba-1", BackendID: "b-1", Role: domain.RoleApp, Username: "app", Password: "pw1"}
	if err := m.UpsertBackendAccount(ctx, a); err != nil {
		t.Fatal(err)
	}
	// Upsert with new password, same (backend, role) — must overwrite not duplicate.
	a2 := a
	a2.ID = "ba-2"
	a2.Password = "pw2"
	if err := m.UpsertBackendAccount(ctx, a2); err != nil {
		t.Fatal(err)
	}
	got, err := m.GetBackendAccount(ctx, "b-1", domain.RoleApp)
	if err != nil {
		t.Fatal(err)
	}
	if got.Password != "pw2" {
		t.Fatalf("upsert didn't overwrite password: %q", got.Password)
	}
}

func TestMemory_GrantsFilter(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	now := time.Now()
	for i, st := range []domain.GrantStatus{domain.GrantPending, domain.GrantApproved, domain.GrantRevoked} {
		g := domain.Grant{
			ID:        domain.NewID("g"),
			UserID:    "u-1",
			BackendID: "b-1",
			Status:    st,
			CreatedAt: now.Add(time.Duration(i) * time.Second),
			UpdatedAt: now,
		}
		if err := m.CreateGrant(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	approved, err := m.ListGrants(ctx, GrantFilter{Statuses: []domain.GrantStatus{domain.GrantApproved}})
	if err != nil || len(approved) != 1 {
		t.Fatalf("expected 1 approved, got %d err=%v", len(approved), err)
	}
	all, _ := m.ListGrants(ctx, GrantFilter{UserID: "u-1"})
	if len(all) != 3 {
		t.Fatalf("expected 3 for user, got %d", len(all))
	}
}

func TestMemory_Audit(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	entries := []domain.AuditEntry{
		{GrantID: "g-1", Username: "alice", Query: "SELECT 1", Timestamp: time.Now()},
		{GrantID: "g-1", Username: "alice", Query: "INSERT ...", Timestamp: time.Now().Add(time.Second)},
		{GrantID: "g-2", Username: "bob", Query: "UPDATE ...", Timestamp: time.Now().Add(2 * time.Second)},
	}
	if err := m.AppendAudit(ctx, entries); err != nil {
		t.Fatal(err)
	}
	got, _ := m.ListAudit(ctx, AuditFilter{GrantID: "g-1"})
	if len(got) != 2 {
		t.Fatalf("expected 2 for g-1, got %d", len(got))
	}
	got, _ = m.ListAudit(ctx, AuditFilter{Username: "bob"})
	if len(got) != 1 {
		t.Fatalf("expected 1 for bob, got %d", len(got))
	}
}
