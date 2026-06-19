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

	u := domain.User{ID: "u-1", Username: "alice", Status: "active", IsOperator: true, CreatedAt: now, UpdatedAt: now}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, u); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
	got, err := s.GetUserByUsername(ctx, "alice")
	if err != nil || got.ID != "u-1" || !got.IsOperator {
		t.Fatalf("lookup: %+v %v", got, err)
	}
	if _, err := s.GetUser(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// TestPostgres_UpdateUserDemote_LastAdminGuard mirrors the in-package contract
// suite (which only runs against memory + sqlite) so the postgres impl is
// pinned for the atomic last-admin guard too.
func TestPostgres_UpdateUserDemote_LastAdminGuard(t *testing.T) {
	s := newTestContainer(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	alice := domain.User{ID: "u-a", Username: "alice", Status: "active", IsOperator: true, CreatedAt: now, UpdatedAt: now}
	bob := domain.User{ID: "u-b", Username: "bob", Status: "active", IsOperator: false, CreatedAt: now, UpdatedAt: now}
	if err := s.CreateUser(ctx, alice); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, bob); err != nil {
		t.Fatal(err)
	}
	cur, _ := s.GetUser(ctx, "u-a")
	cur.IsOperator = false
	if err := s.UpdateUserDemote(ctx, cur); !errors.Is(err, store.ErrLastAdmin) {
		t.Fatalf("sole admin demote: want ErrLastAdmin, got %v", err)
	}
	b, _ := s.GetUser(ctx, "u-b")
	b.IsOperator = true
	if err := s.UpdateUser(ctx, b); err != nil {
		t.Fatalf("promote bob: %v", err)
	}
	cur2, _ := s.GetUser(ctx, "u-a")
	cur2.IsOperator = false
	if err := s.UpdateUserDemote(ctx, cur2); err != nil {
		t.Fatalf("demote with two admins: %v", err)
	}
	n, _ := s.CountAdmins(ctx)
	if n != 1 {
		t.Fatalf("post-demote admin count: want 1, got %d", n)
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
	g.T2ApprovedBy = "admin"
	g.T2ApprovedAt = &approved
	g.ExpiresAt = &expires
	g.UpdatedAt = approved
	if err := s.UpdateGrant(ctx, g); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetGrant(ctx, "g-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != domain.GrantApproved || got.T2ApprovedBy != "admin" {
		t.Fatalf("unexpected grant: %+v", got)
	}
	if got.T2ApprovedAt == nil || !got.T2ApprovedAt.Equal(approved) {
		t.Fatalf("ApprovedAt = %v, want %v", got.T2ApprovedAt, approved)
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

// mkIntentGrant sets up the user + backend + grant FK chain a provision_intents
// row needs (the pg migration keeps the FK to grants(id)).
func mkIntentGrant(t *testing.T, s *Store, grantID, backendID string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	_ = s.CreateUser(ctx, domain.User{ID: "u-1", Username: "alice", Status: "active", CreatedAt: now, UpdatedAt: now})
	if _, err := s.GetBackend(ctx, backendID); errors.Is(err, store.ErrNotFound) {
		_ = s.CreateBackend(ctx, domain.Backend{ID: backendID, Name: backendID, Type: domain.ProxyPostgres, Host: backendID, Port: 5432, CreatedAt: now, UpdatedAt: now})
	}
	if err := s.CreateGrant(ctx, domain.Grant{
		ID: grantID, UserID: "u-1", BackendID: backendID, Role: domain.RoleApp,
		Status: domain.GrantApproved, RequestedAt: now, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("create grant %s: %v", grantID, err)
	}
}

// TestPostgres_IntentOutbox mirrors the in-package contract suite (memory +
// sqlite) so the postgres outbox impl is pinned for the same behaviours:
// idempotent insert, claim → in_flight, revoke-before-provision ordering,
// instance whitelist, stale-lease reclaim, owner-only mutations, latest lookup.
func TestPostgres_IntentOutbox(t *testing.T) {
	s := newTestContainer(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	// Two backends so the whitelist branch is exercised.
	mkIntentGrant(t, s, "g-prov", "b-1")
	mkIntentGrant(t, s, "g-rev", "b-1")
	if err := s.CreateGrant(ctx, domain.Grant{
		ID: "g-other", UserID: "u-1", BackendID: "b-2", Role: domain.RoleApp,
		Status: domain.GrantApproved, RequestedAt: now, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		// b-2 doesn't exist yet — create it then the grant.
		_ = s.CreateBackend(ctx, domain.Backend{ID: "b-2", Name: "b-2", Type: domain.ProxyPostgres, Host: "b-2", Port: 5432, CreatedAt: now, UpdatedAt: now})
		if err := s.CreateGrant(ctx, domain.Grant{
			ID: "g-other", UserID: "u-1", BackendID: "b-2", Role: domain.RoleApp,
			Status: domain.GrantApproved, RequestedAt: now, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	provID := domain.IntentID("g-prov", domain.IntentProvision)
	revID := domain.IntentID("g-rev", domain.IntentRevoke)
	otherID := domain.IntentID("g-other", domain.IntentProvision)

	mk := func(id, grantID string, kind domain.IntentKind, backend string, createdAt time.Time) {
		if err := s.InsertIntent(ctx, domain.Intent{
			ID: id, GrantID: grantID, Kind: kind, BackendID: backend, Role: domain.RoleApp,
			Status: domain.IntentPending, CreatedAt: createdAt, UpdatedAt: createdAt,
		}); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}
	// provision OLDER than revoke; revoke must still sort first.
	mk(provID, "g-prov", domain.IntentProvision, "b-1", now)
	mk(revID, "g-rev", domain.IntentRevoke, "b-1", now.Add(time.Second))
	mk(otherID, "g-other", domain.IntentProvision, "b-2", now)

	// Idempotent re-insert.
	if err := s.InsertIntent(ctx, domain.Intent{
		ID: provID, GrantID: "g-prov", Kind: domain.IntentProvision, BackendID: "b-1",
		Role: domain.RoleApp, Status: domain.IntentPending, Database: "clobber",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("idempotent re-insert: %v", err)
	}
	if g, _ := s.GetIntent(ctx, provID); g.Database != "" {
		t.Fatalf("dup insert clobbered row: %+v", g)
	}

	// Whitelist b-1 → b-2 excluded; revoke before provision.
	claimed, err := s.ClaimPendingIntents(ctx, "worker-A", []string{"b-1"}, time.Minute, 10)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed) != 2 {
		t.Fatalf("claimed %d, want 2", len(claimed))
	}
	if claimed[0].ID != revID || claimed[1].ID != provID {
		t.Fatalf("ordering: got %s,%s want revoke,provision", claimed[0].ID, claimed[1].ID)
	}
	for _, c := range claimed {
		if c.Status != domain.IntentInFlight || c.WorkerID != "worker-A" || c.LeaseExpiresAt == nil {
			t.Fatalf("not leased: %+v", c)
		}
	}

	// Owner-only heartbeat / complete / fail.
	if err := s.HeartbeatIntentLease(ctx, provID, "worker-B", time.Minute); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("foreign heartbeat: want ErrNotFound got %v", err)
	}
	if err := s.HeartbeatIntentLease(ctx, provID, "worker-A", 2*time.Minute); err != nil {
		t.Fatalf("owner heartbeat: %v", err)
	}
	if err := s.CompleteIntent(ctx, provID, "worker-A", "ap_user", "pw"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if g, _ := s.GetIntent(ctx, provID); g.Status != domain.IntentDone || g.CompletedAt == nil || g.ResultUsername != "ap_user" {
		t.Fatalf("complete not persisted: %+v", g)
	}
	if err := s.FailIntent(ctx, revID, "worker-A", "transient_network", "i/o timeout", 2); err != nil {
		t.Fatalf("fail: %v", err)
	}
	if g, _ := s.GetIntent(ctx, revID); g.Status != domain.IntentFailed || g.RetryCount != 2 || g.ErrorClass != "transient_network" {
		t.Fatalf("fail not persisted: %+v", g)
	}

	// Latest lookup.
	gotRev, err := s.GetLatestIntentForGrant(ctx, "g-rev", domain.IntentRevoke)
	if err != nil || gotRev.ID != revID {
		t.Fatalf("latest revoke: %+v %v", gotRev, err)
	}
	if _, err := s.GetLatestIntentForGrant(ctx, "g-rev", domain.IntentProvision); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing kind: want ErrNotFound got %v", err)
	}
}

// TestPostgres_ResetIntentForRetry mirrors the contract suite (HIGH-2) on the
// real backend: a failed row re-arms to pending; any non-failed row is a no-op.
func TestPostgres_ResetIntentForRetry(t *testing.T) {
	s := newTestContainer(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	mkIntentGrant(t, s, "g-1", "b-1")
	id := domain.IntentID("g-1", domain.IntentProvision)
	if err := s.InsertIntent(ctx, domain.Intent{
		ID: id, GrantID: "g-1", Kind: domain.IntentProvision, BackendID: "b-1",
		Role: domain.RoleApp, Status: domain.IntentPending, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	// Pending → not failed → ErrNotFound.
	if err := s.ResetIntentForRetry(ctx, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("reset on pending: want ErrNotFound got %v", err)
	}
	if _, err := s.ClaimPendingIntents(ctx, "worker-A", nil, time.Minute, 10); err != nil {
		t.Fatal(err)
	}
	if err := s.FailIntent(ctx, id, "worker-A", "transient_exhausted", "blip", 3); err != nil {
		t.Fatal(err)
	}
	if err := s.ResetIntentForRetry(ctx, id); err != nil {
		t.Fatalf("reset on failed: %v", err)
	}
	got, _ := s.GetIntent(ctx, id)
	if got.Status != domain.IntentPending || got.WorkerID != "" || got.LeaseExpiresAt != nil ||
		got.ErrorClass != "" || got.ErrorDetail != "" || got.RetryCount != 0 {
		t.Fatalf("reset did not fully re-arm row: %+v", got)
	}
	reclaimed, err := s.ClaimPendingIntents(ctx, "worker-B", nil, time.Minute, 10)
	if err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	if len(reclaimed) != 1 || reclaimed[0].ID != id {
		t.Fatalf("re-armed row not reclaimable: %+v", reclaimed)
	}
}

// TestPostgres_IntentStaleLeaseReclaim: an in_flight row past its lease becomes
// claimable by a different worker (the FOR UPDATE SKIP LOCKED reclaim path).
func TestPostgres_IntentStaleLeaseReclaim(t *testing.T) {
	s := newTestContainer(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	mkIntentGrant(t, s, "g-1", "b-1")
	id := domain.IntentID("g-1", domain.IntentProvision)
	if err := s.InsertIntent(ctx, domain.Intent{
		ID: id, GrantID: "g-1", Kind: domain.IntentProvision, BackendID: "b-1",
		Role: domain.RoleApp, Status: domain.IntentPending, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	// worker-A claims with an already-expired lease, then "dies".
	if _, err := s.ClaimPendingIntents(ctx, "worker-A", nil, -time.Second, 10); err != nil {
		t.Fatal(err)
	}
	reclaimed, err := s.ClaimPendingIntents(ctx, "worker-B", nil, time.Minute, 10)
	if err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	if len(reclaimed) != 1 || reclaimed[0].WorkerID != "worker-B" {
		t.Fatalf("stale reclaim failed: %+v", reclaimed)
	}
	if err := s.HeartbeatIntentLease(ctx, id, "worker-A", time.Minute); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("stale owner heartbeat: want ErrNotFound got %v", err)
	}
}

func TestPostgres_MigrationsIdempotent(t *testing.T) {
	s := newTestContainer(t)
	// Second migrate pass must be a no-op.
	if err := s.migrate(context.Background()); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

// TestPostgres_WorkerHeartbeat mirrors the in-package contract suite on the
// real backend: upsert→list round-trip, started_at preserved across beats,
// JSON round-trip of Instances + Health (LastOKAt pointer + ErrorClass), and
// PruneStaleWorkers deleting only rows older than the cutoff.
func TestPostgres_WorkerHeartbeat(t *testing.T) {
	s := newTestContainer(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	okAt := now.Add(30 * time.Second)

	hb := domain.WorkerHeartbeat{
		WorkerID:  "worker-A",
		Instances: []string{"b-1", "b-2"},
		Health: []domain.InstanceHealth{
			{BackendID: "b-1", OK: true, LastOKAt: &okAt},
			{BackendID: "b-2", OK: false, ErrorClass: "dial_timeout"},
		},
		Version:    "v1.2.3",
		StartedAt:  now,
		LastSeenAt: now,
	}
	if err := s.UpsertWorkerHeartbeat(ctx, hb); err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	list, err := s.ListWorkerHeartbeats(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("list len = %d, want 1", len(list))
	}
	got := list[0]
	if got.Version != "v1.2.3" || len(got.Instances) != 2 || got.Instances[1] != "b-2" {
		t.Fatalf("scalar/instances round-trip: %+v", got)
	}
	if len(got.Health) != 2 {
		t.Fatalf("health len = %d, want 2", len(got.Health))
	}
	if h := got.Health[0]; h.BackendID != "b-1" || !h.OK || h.LastOKAt == nil || !h.LastOKAt.Equal(okAt) {
		t.Fatalf("health[0]: %+v", h)
	}
	if h := got.Health[1]; h.BackendID != "b-2" || h.OK || h.ErrorClass != "dial_timeout" || h.LastOKAt != nil {
		t.Fatalf("health[1]: %+v", h)
	}

	// Second beat: started_at preserved even though a later one is supplied.
	later := now.Add(5 * time.Minute)
	hb2 := hb
	hb2.StartedAt = later
	hb2.LastSeenAt = later
	if err := s.UpsertWorkerHeartbeat(ctx, hb2); err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	list, _ = s.ListWorkerHeartbeats(ctx)
	if len(list) != 1 || !list[0].StartedAt.Equal(now) || !list[0].LastSeenAt.Equal(later) {
		t.Fatalf("started_at must be preserved, last_seen advanced: %+v", list)
	}

	// Add a stale second worker; prune at cutoff = now keeps only worker-A.
	if err := s.UpsertWorkerHeartbeat(ctx, domain.WorkerHeartbeat{
		WorkerID: "worker-stale", StartedAt: now.Add(-time.Hour), LastSeenAt: now.Add(-10 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	n, err := s.PruneStaleWorkers(ctx, now.Add(-time.Minute))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("pruned %d, want 1", n)
	}
	list, _ = s.ListWorkerHeartbeats(ctx)
	if len(list) != 1 || list[0].WorkerID != "worker-A" {
		t.Fatalf("after prune: %+v, want only worker-A", list)
	}
}

// TestPostgres_ExpireUnclaimedGrants: PENDING past RequestExpiresAt and
// APPROVED past ClaimExpiresAt both flip to EXPIRED; live grants untouched.
func TestPostgres_ExpireUnclaimedGrants(t *testing.T) {
	s := newTestContainer(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	_ = s.CreateUser(ctx, domain.User{ID: "u-1", Username: "alice", Status: "active", CreatedAt: now, UpdatedAt: now})
	_ = s.CreateBackend(ctx, domain.Backend{ID: "b-1", Name: "pg", Type: domain.ProxyPostgres, Host: "127.0.0.1", Port: 5432, CreatedAt: now, UpdatedAt: now})

	mkGrant := func(id string, status domain.GrantStatus, reqExp, claimExp *time.Time) {
		g := domain.Grant{
			ID: id, UserID: "u-1", BackendID: "b-1",
			Role: domain.RoleApp, Status: status,
			RequestedAt: now, CreatedAt: now, UpdatedAt: now,
			RequestExpiresAt: reqExp,
			ClaimExpiresAt:   claimExp,
		}
		if err := s.CreateGrant(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	mkGrant("g-stale-pending", domain.GrantPending, &past, nil)
	mkGrant("g-live-pending", domain.GrantPending, &future, nil)
	mkGrant("g-stale-claim", domain.GrantApproved, nil, &past)
	mkGrant("g-live-claim", domain.GrantApproved, nil, &future)
	mkGrant("g-stale-validator", domain.GrantValidatorApproved, &past, nil)

	n, err := s.ExpireUnclaimedGrants(ctx, now)
	if err != nil {
		t.Fatalf("ExpireUnclaimedGrants: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 expired, got %d", n)
	}
	for _, tc := range []struct {
		id   string
		want domain.GrantStatus
	}{
		{"g-stale-pending", domain.GrantExpired},
		{"g-stale-validator", domain.GrantExpired},
		{"g-stale-claim", domain.GrantExpired},
		{"g-live-pending", domain.GrantPending},
		{"g-live-claim", domain.GrantApproved},
	} {
		got, err := s.GetGrant(ctx, tc.id)
		if err != nil {
			t.Errorf("GetGrant(%s): %v", tc.id, err)
			continue
		}
		if got.Status != tc.want {
			t.Errorf("%s status = %s, want %s", tc.id, got.Status, tc.want)
		}
	}
}
