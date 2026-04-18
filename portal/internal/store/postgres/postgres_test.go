package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/store"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

// newTestContainer spins up a disposable Postgres 17 container and returns a
// live Store. t.Skip's when docker isn't reachable so CI without a docker
// socket still passes the unit suite.
func newTestContainer(t *testing.T) *Store {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	c, err := tcpostgres.Run(ctx,
		"postgres:17-alpine",
		tcpostgres.WithDatabase("portal"),
		tcpostgres.WithUsername("portal"),
		tcpostgres.WithPassword("portal"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Skipf("postgres testcontainer unavailable: %v", err)
	}
	t.Cleanup(func() {
		cctx, cc := context.WithTimeout(context.Background(), 30*time.Second)
		defer cc()
		_ = testcontainers.TerminateContainer(c, testcontainers.StopContext(cctx))
	})

	dsn, err := c.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	s, err := Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestPostgres_UsersCRUD(t *testing.T) {
	s := newTestContainer(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	u := domain.User{ID: "u-1", Username: "alice", Status: "active", IsAdmin: true, CreatedAt: now, UpdatedAt: now}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, u); !errors.Is(err, store.ErrConflict) {
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

func TestPostgres_BackendsAndAccounts(t *testing.T) {
	s := newTestContainer(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

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

	acct := domain.BackendAccount{ID: "a-1", BackendID: "b-1", Role: domain.RoleApp, Username: "app", Password: "pw", CreatedAt: now, UpdatedAt: now}
	if err := s.UpsertBackendAccount(ctx, acct); err != nil {
		t.Fatal(err)
	}
	acct.Password = "pw2"
	acct.UpdatedAt = now.Add(time.Second)
	if err := s.UpsertBackendAccount(ctx, acct); err != nil {
		t.Fatal(err)
	}
	gotAcct, err := s.GetBackendAccount(ctx, "b-1", domain.RoleApp)
	if err != nil || gotAcct.Password != "pw2" {
		t.Fatalf("lookup acct: %+v %v", gotAcct, err)
	}
	if _, err := s.GetBackendAccount(ctx, "b-1", domain.RoleDBA); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestPostgres_GrantsLifecycle(t *testing.T) {
	s := newTestContainer(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	// FK prerequisites.
	_ = s.CreateUser(ctx, domain.User{ID: "u-1", Username: "alice", Status: "active", CreatedAt: now, UpdatedAt: now})
	_ = s.CreateBackend(ctx, domain.Backend{ID: "b-1", Name: "pg", Type: domain.ProxyPostgres, Host: "127.0.0.1", Port: 5432, CreatedAt: now, UpdatedAt: now})

	g := domain.Grant{
		ID: "g-1", UserID: "u-1", BackendID: "b-1", Database: "orders",
		Role: domain.RoleApp, Status: domain.GrantPending, Reason: "rotation",
		PortalPassword: "ppw", RequestedAt: now, CreatedAt: now, UpdatedAt: now,
		ConnectionTTLSec: 3600,
	}
	if err := s.CreateGrant(ctx, g); err != nil {
		t.Fatal(err)
	}

	// Approve + set ApprovedAt + ExpiresAt.
	approved := now.Add(time.Minute)
	expires := now.Add(time.Hour)
	g.Status = domain.GrantApproved
	g.ApprovedBy = "admin"
	g.ApprovedAt = &approved
	g.ExpiresAt = &expires
	g.UpdatedAt = approved
	if err := s.UpdateGrant(ctx, g); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetGrant(ctx, "g-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != domain.GrantApproved || got.ApprovedBy != "admin" {
		t.Fatalf("unexpected grant: %+v", got)
	}
	if got.ApprovedAt == nil || !got.ApprovedAt.Equal(approved) {
		t.Fatalf("ApprovedAt = %v, want %v", got.ApprovedAt, approved)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(expires) {
		t.Fatalf("ExpiresAt = %v, want %v", got.ExpiresAt, expires)
	}

	list, err := s.ListGrants(ctx, store.GrantFilter{UserID: "u-1", Statuses: []domain.GrantStatus{domain.GrantApproved}})
	if err != nil || len(list) != 1 || list[0].ID != "g-1" {
		t.Fatalf("list: %+v %v", list, err)
	}
}

func TestPostgres_AuditAppendPrune(t *testing.T) {
	s := newTestContainer(t)
	ctx := context.Background()
	base := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Millisecond)

	// Append 10 entries with increasing timestamps.
	entries := make([]domain.AuditEntry, 10)
	for i := range entries {
		entries[i] = domain.AuditEntry{
			Timestamp: base.Add(time.Duration(i) * time.Hour),
			GrantID:   "g-1", Username: "alice", ProxyType: domain.ProxyPostgres,
			BackendServer: "db:5432", Database: "orders", Query: "SELECT 1",
			DurationMs: int64(i * 10),
		}
	}
	if err := s.AppendAudit(ctx, entries); err != nil {
		t.Fatal(err)
	}

	// Age cutoff: keep only the newest 3 (older than base+7h drops 7).
	cutoff := base.Add(7 * time.Hour)
	pruned, remaining, err := s.PruneAudit(ctx, cutoff, 0)
	if err != nil {
		t.Fatal(err)
	}
	if pruned != 7 || remaining != 3 {
		t.Fatalf("age prune: pruned=%d remaining=%d, want 7/3", pruned, remaining)
	}

	// Cap enforcement: keep only the 2 newest.
	pruned2, remaining2, err := s.PruneAudit(ctx, base.Add(-time.Hour), 2)
	if err != nil {
		t.Fatal(err)
	}
	if remaining2 != 2 || pruned2 != 1 {
		t.Fatalf("cap prune: pruned=%d remaining=%d, want 1/2", pruned2, remaining2)
	}
}

func TestPostgres_MigrationsIdempotent(t *testing.T) {
	s := newTestContainer(t)
	// Second migrate pass must be a no-op.
	if err := s.migrate(context.Background()); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}
