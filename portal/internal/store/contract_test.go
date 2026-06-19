package store_test

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/lifecycle"
	"github.com/babs/poc-proxies/portal/internal/store"

	// Register sqlite so NewFromURL("sqlite::memory:") resolves.
	_ "github.com/babs/poc-proxies/portal/internal/store/sqlite"
)

// factories drives the same behavioural tests against every Store impl so the
// sqlite backend matches the memory backend tick-for-tick (the API tests only
// exercise the memory impl, so a dedicated contract suite catches impl drift).
//
// Postgres is intentionally NOT in this list: spinning up a testcontainer for
// each subtest multiplies suite runtime by ~3s per test. Postgres coverage
// lives in portal/internal/store/postgres/postgres_test.go, which exercises
// the same contract against a single shared container per test. New Store
// interface methods must be tested there as well — the interface satisfaction
// check catches *compile-time* regressions on postgres automatically, but
// behavioural parity is a human/test responsibility.
func factories() []struct {
	name string
	make func(t *testing.T) store.Store
} {
	return []struct {
		name string
		make func(t *testing.T) store.Store
	}{
		{"memory", func(_ *testing.T) store.Store { return store.NewMemory() }},
		{"sqlite::memory:", func(t *testing.T) store.Store {
			s, err := store.NewFromURL("sqlite::memory:")
			if err != nil {
				t.Fatalf("open sqlite: %v", err)
			}
			t.Cleanup(func() { _ = s.Close() })
			return s
		}},
	}
}

func TestContract_UserLifecycle(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			s := f.make(t)
			ctx := context.Background()
			now := time.Now().UTC()
			u := domain.User{ID: "u-1", Username: "alice", Status: "active", CreatedAt: now, UpdatedAt: now}
			if err := s.CreateUser(ctx, u); err != nil {
				t.Fatal(err)
			}
			if err := s.CreateUser(ctx, u); !errors.Is(err, store.ErrConflict) {
				t.Fatalf("expected ErrConflict, got %v", err)
			}
			if _, err := s.GetUserByUsername(ctx, "alice"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestContract_UpdateUserDemote_LastAdminGuard pins the atomic guard: every
// store impl must (a) refuse to demote the only remaining admin with
// ErrLastAdmin and (b) once a second admin exists, allow the demote to
// succeed via UpdateUserDemote with the same CAS shape as UpdateUser.
func TestContract_UpdateUserDemote_LastAdminGuard(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			s := f.make(t)
			ctx := context.Background()
			now := time.Now().UTC()
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
		})
	}
}

// TestMemory_UpdateUserDemote_ConcurrentRace runs the original H1 scenario
// against the memory store: two goroutines demote two different admins from a
// 2-admin baseline. With the atomic guard in place exactly one demote must
// succeed and the other must return ErrLastAdmin — never both succeed.
// Memory-only because pg/sqlite need their own concurrency tests with real
// connections; the lock semantics differ enough that one test can't cover
// all three.
func TestMemory_UpdateUserDemote_ConcurrentRace(t *testing.T) {
	for i := 0; i < 50; i++ {
		s := store.NewMemory()
		ctx := context.Background()
		now := time.Now().UTC()
		_ = s.CreateUser(ctx, domain.User{ID: "u-a", Username: "alice", Status: "active", IsOperator: true, CreatedAt: now, UpdatedAt: now})
		_ = s.CreateUser(ctx, domain.User{ID: "u-b", Username: "bob", Status: "active", IsOperator: true, CreatedAt: now, UpdatedAt: now})

		a, _ := s.GetUser(ctx, "u-a")
		a.IsOperator = false
		b, _ := s.GetUser(ctx, "u-b")
		b.IsOperator = false

		var successes, lastAdmin atomic.Int32
		errs := make(chan error, 2)
		ready := make(chan struct{})
		go func() {
			<-ready
			err := s.UpdateUserDemote(ctx, a)
			errs <- err
		}()
		go func() {
			<-ready
			err := s.UpdateUserDemote(ctx, b)
			errs <- err
		}()
		close(ready)
		for j := 0; j < 2; j++ {
			err := <-errs
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, store.ErrLastAdmin):
				lastAdmin.Add(1)
			default:
				t.Fatalf("unexpected err: %v", err)
			}
		}
		if successes.Load() != 1 || lastAdmin.Load() != 1 {
			t.Fatalf("iter %d: want 1 success + 1 ErrLastAdmin, got %d / %d", i, successes.Load(), lastAdmin.Load())
		}
		n, _ := s.CountAdmins(ctx)
		if n != 1 {
			t.Fatalf("iter %d: post-race admin count must be 1, got %d", i, n)
		}
	}
}

func TestContract_AuditPrune(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			s := f.make(t)
			ctx := context.Background()
			now := time.Now().UTC()

			var entries []domain.AuditEntry
			for i := 0; i < 20; i++ {
				entries = append(entries, domain.AuditEntry{
					Timestamp: now.Add(-time.Duration(20-i) * time.Minute),
					GrantID:   "g-1", Username: "alice", Query: "SELECT 1",
				})
			}
			if err := s.AppendAudit(ctx, entries); err != nil {
				t.Fatal(err)
			}
			pruned, total, err := s.PruneAudit(ctx, now.Add(-10*time.Minute), 0)
			if err != nil {
				t.Fatal(err)
			}
			if pruned < 10 || total > 11 {
				t.Fatalf("age prune: pruned=%d total=%d", pruned, total)
			}
			pruned2, total2, err := s.PruneAudit(ctx, time.Time{}, 5)
			if err != nil {
				t.Fatal(err)
			}
			if total2 != 5 {
				t.Fatalf("cap prune should leave 5, got %d (pruned=%d)", total2, pruned2)
			}
		})
	}
}

func TestContract_GrantFilter(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			s := f.make(t)
			ctx := context.Background()
			now := time.Now().UTC()

			_ = s.CreateUser(ctx, domain.User{ID: "u-1", Username: "alice", Status: "active", CreatedAt: now, UpdatedAt: now})
			_ = s.CreateBackend(ctx, domain.Backend{ID: "b-1", Name: "m", Type: domain.ProxyMongo, Host: "h", Port: 1, CreatedAt: now, UpdatedAt: now})
			for i, st := range []domain.GrantStatus{domain.GrantPending, domain.GrantApproved, domain.GrantRevoked} {
				g := domain.Grant{
					ID: domain.NewID("g"), UserID: "u-1", BackendID: "b-1",
					Role: domain.RoleApp, Status: st,
					RequestedAt: now, CreatedAt: now.Add(time.Duration(i) * time.Second), UpdatedAt: now,
				}
				if err := s.CreateGrant(ctx, g); err != nil {
					t.Fatal(err)
				}
			}
			got, err := s.ListGrants(ctx, store.GrantFilter{UserID: "u-1", Statuses: []domain.GrantStatus{domain.GrantApproved}})
			if err != nil || len(got) != 1 {
				t.Fatalf("list: %d err=%v", len(got), err)
			}
			all, _ := s.ListGrants(ctx, store.GrantFilter{UserID: "u-1"})
			if len(all) != 3 {
				t.Fatalf("expected 3, got %d", len(all))
			}
		})
	}
}

// TestContract_UpdateGrantIfStatus_CAS verifies the compare-and-swap:
// first writer wins, second writer gets ErrConflict (no silent clobber).
func TestContract_UpdateGrantIfStatus_CAS(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			s := f.make(t)
			ctx := context.Background()
			now := time.Now().UTC()
			_ = s.CreateUser(ctx, domain.User{ID: "u-1", Username: "alice", Status: "active", CreatedAt: now, UpdatedAt: now})
			_ = s.CreateBackend(ctx, domain.Backend{ID: "b-1", Name: "m", Type: domain.ProxyMongo, Host: "h", Port: 1, CreatedAt: now, UpdatedAt: now})
			g := domain.Grant{
				ID: "g-1", UserID: "u-1", BackendID: "b-1",
				Role: domain.RoleApp, Status: domain.GrantPending,
				RequestedAt: now, CreatedAt: now, UpdatedAt: now,
			}
			if err := s.CreateGrant(ctx, g); err != nil {
				t.Fatal(err)
			}

			// First actor approves — expects PENDING.
			approved := g
			approved.Status = domain.GrantApproved
			approved.UpdatedAt = now.Add(time.Second)
			if err := s.UpdateGrantIfStatus(ctx, approved, domain.GrantPending); err != nil {
				t.Fatalf("first CAS: %v", err)
			}

			// Second actor, also expecting PENDING, now hits ErrConflict.
			denied := g
			denied.Status = domain.GrantDenied
			denied.UpdatedAt = now.Add(2 * time.Second)
			err := s.UpdateGrantIfStatus(ctx, denied, domain.GrantPending)
			if !errors.Is(err, store.ErrConflict) {
				t.Fatalf("want ErrConflict, got %v", err)
			}

			// Missing row returns ErrNotFound, not ErrConflict.
			ghost := g
			ghost.ID = "g-ghost"
			ghost.Status = domain.GrantApproved
			err = s.UpdateGrantIfStatus(ctx, ghost, domain.GrantPending)
			if !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("want ErrNotFound, got %v", err)
			}
		})
	}
}

// TestContract_ExpireStaleGrants verifies the background reconciliation
// flips APPROVED grants past ExpiresAt to EXPIRED — and leaves non-APPROVED
// or still-live grants alone.
func TestContract_ExpireStaleGrants(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			s := f.make(t)
			ctx := context.Background()
			now := time.Now().UTC()
			_ = s.CreateUser(ctx, domain.User{ID: "u-1", Username: "alice", Status: "active", CreatedAt: now, UpdatedAt: now})
			_ = s.CreateBackend(ctx, domain.Backend{ID: "b-1", Name: "m", Type: domain.ProxyMongo, Host: "h", Port: 1, CreatedAt: now, UpdatedAt: now})

			mkGrant := func(id string, status domain.GrantStatus, expires *time.Time) {
				g := domain.Grant{
					ID: id, UserID: "u-1", BackendID: "b-1",
					Role: domain.RoleApp, Status: status, ExpiresAt: expires,
					RequestedAt: now, CreatedAt: now, UpdatedAt: now,
				}
				if err := s.CreateGrant(ctx, g); err != nil {
					t.Fatal(err)
				}
			}
			past := now.Add(-time.Hour)
			future := now.Add(time.Hour)
			mkGrant("g-stale", domain.GrantActive, &past)
			mkGrant("g-live", domain.GrantActive, &future)
			mkGrant("g-pending", domain.GrantPending, &past) // not ACTIVE, leave it
			mkGrant("g-open", domain.GrantActive, nil)       // no expiry, leave it

			n, err := s.ExpireStaleGrants(ctx, now)
			if err != nil {
				t.Fatalf("ExpireStaleGrants: %v", err)
			}
			if n != 1 {
				t.Fatalf("expected 1 expired, got %d", n)
			}
			g, _ := s.GetGrant(ctx, "g-stale")
			if g.Status != domain.GrantExpired {
				t.Errorf("g-stale status = %s, want EXPIRED", g.Status)
			}
			for _, id := range []string{"g-live", "g-pending", "g-open"} {
				g, _ := s.GetGrant(ctx, id)
				if g.Status == domain.GrantExpired {
					t.Errorf("%s wrongly expired", id)
				}
			}
		})
	}
}

// TestContract_ExpireUnclaimedGrants: PENDING/VALIDATOR_APPROVED past
// RequestExpiresAt and APPROVED past ClaimExpiresAt all transition to EXPIRED.
func TestContract_ExpireUnclaimedGrants(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			s := f.make(t)
			ctx := context.Background()
			now := time.Now().UTC()
			_ = s.CreateUser(ctx, domain.User{ID: "u-1", Username: "alice", Status: "active", CreatedAt: now, UpdatedAt: now})
			_ = s.CreateBackend(ctx, domain.Backend{ID: "b-1", Name: "m", Type: domain.ProxyMongo, Host: "h", Port: 1, CreatedAt: now, UpdatedAt: now})

			past := now.Add(-time.Hour)
			future := now.Add(time.Hour)
			mk := func(id string, status domain.GrantStatus, reqExp, claimExp *time.Time) {
				g := domain.Grant{
					ID: id, UserID: "u-1", BackendID: "b-1",
					Role: domain.RoleApp, Status: status,
					RequestExpiresAt: reqExp,
					ClaimExpiresAt:   claimExp,
					RequestedAt:      now, CreatedAt: now, UpdatedAt: now,
				}
				if err := s.CreateGrant(ctx, g); err != nil {
					t.Fatal(err)
				}
			}
			mk("g-pending-stale", domain.GrantPending, &past, nil)         // EXPIRED
			mk("g-mgrap-stale", domain.GrantValidatorApproved, &past, nil) // EXPIRED
			mk("g-approved-stale", domain.GrantApproved, nil, &past)       // EXPIRED
			mk("g-pending-live", domain.GrantPending, &future, nil)        // skip
			mk("g-approved-live", domain.GrantApproved, nil, &future)      // skip
			mk("g-pending-noexp", domain.GrantPending, nil, nil)           // skip (no deadline)

			n, err := s.ExpireUnclaimedGrants(ctx, now)
			if err != nil {
				t.Fatalf("ExpireUnclaimedGrants: %v", err)
			}
			if n != 3 {
				t.Errorf("expected 3 expired, got %d", n)
			}
			for _, id := range []string{"g-pending-stale", "g-mgrap-stale", "g-approved-stale"} {
				g, _ := s.GetGrant(ctx, id)
				if g.Status != domain.GrantExpired {
					t.Errorf("%s status=%s want EXPIRED", id, g.Status)
				}
			}
			for _, id := range []string{"g-pending-live", "g-approved-live", "g-pending-noexp"} {
				g, _ := s.GetGrant(ctx, id)
				if g.Status == domain.GrantExpired {
					t.Errorf("%s wrongly expired", id)
				}
			}
		})
	}
}

func TestContract_GetBackendByName(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			s := f.make(t)
			ctx := context.Background()
			now := time.Now().UTC()
			_ = s.CreateBackend(ctx, domain.Backend{ID: "b-1", Name: "prod-pg", Type: domain.ProxyPostgres, Host: "h", Port: 5432, CreatedAt: now, UpdatedAt: now})
			got, err := s.GetBackendByName(ctx, "prod-pg")
			if err != nil {
				t.Fatalf("GetBackendByName: %v", err)
			}
			if got.ID != "b-1" {
				t.Errorf("ID=%s", got.ID)
			}
			if _, err := s.GetBackendByName(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("missing: want ErrNotFound got %v", err)
			}
		})
	}
}

func TestContract_SessionCRUD(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			s := f.make(t)
			ctx := context.Background()
			now := time.Now().UTC()
			rec := store.SessionRecord{
				ID: "sid-1", Subject: "sub-1", Email: "a@b", Name: "Alice",
				IsOperator: true, ExpiresAt: now.Add(time.Hour),
			}
			if err := s.CreateSession(ctx, rec); err != nil {
				t.Fatalf("create: %v", err)
			}
			if err := s.CreateSession(ctx, rec); !errors.Is(err, store.ErrConflict) {
				t.Fatalf("duplicate: want ErrConflict got %v", err)
			}
			got, err := s.GetSession(ctx, "sid-1")
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if got.Subject != "sub-1" || !got.IsOperator {
				t.Fatalf("bad record: %+v", got)
			}
			if _, err := s.GetSession(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("missing: want ErrNotFound got %v", err)
			}
			if err := s.DeleteSession(ctx, "sid-1"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.GetSession(ctx, "sid-1"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("after delete: want ErrNotFound got %v", err)
			}
		})
	}
}

func TestContract_SessionPrune(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			s := f.make(t)
			ctx := context.Background()
			now := time.Now().UTC()
			mk := func(id string, exp time.Time) {
				if err := s.CreateSession(ctx, store.SessionRecord{
					ID: id, Subject: id, ExpiresAt: exp,
				}); err != nil {
					t.Fatalf("create %s: %v", id, err)
				}
			}
			mk("alive", now.Add(time.Hour))
			mk("dead-1", now.Add(-time.Minute))
			mk("dead-2", now.Add(-time.Hour))

			n, err := s.PruneExpiredSessions(ctx, now)
			if err != nil {
				t.Fatalf("prune: %v", err)
			}
			if n != 2 {
				t.Fatalf("pruned=%d want 2", n)
			}
			if _, err := s.GetSession(ctx, "alive"); err != nil {
				t.Fatalf("alive missing: %v", err)
			}
			if _, err := s.GetSession(ctx, "dead-1"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("dead-1 still present: %v", err)
			}
		})
	}
}

// mkIntentGrant creates the user + backend + grant FK prerequisites a
// provision_intents row needs (the sqlite migration drops the FK but the pg
// one keeps it, so the contract suite must satisfy it to stay portable).
func mkIntentGrant(t *testing.T, s store.Store, grantID string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	_ = s.CreateUser(ctx, domain.User{ID: "u-1", Username: "alice", Status: "active", CreatedAt: now, UpdatedAt: now})
	_ = s.CreateBackend(ctx, domain.Backend{ID: "b-1", Name: "pg", Type: domain.ProxyPostgres, Host: "h", Port: 5432, CreatedAt: now, UpdatedAt: now})
	g := domain.Grant{
		ID: grantID, UserID: "u-1", BackendID: "b-1",
		Role: domain.RoleApp, Status: domain.GrantApproved,
		RequestedAt: now, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.CreateGrant(ctx, g); err != nil {
		t.Fatalf("create grant %s: %v", grantID, err)
	}
}

func TestContract_IntentInsertGetIdempotent(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			s := f.make(t)
			ctx := context.Background()
			now := time.Now().UTC()
			mkIntentGrant(t, s, "g-1")

			id := domain.IntentID("g-1", domain.IntentProvision)
			in := domain.Intent{
				ID: id, GrantID: "g-1", Kind: domain.IntentProvision,
				BackendID: "b-1", Database: "orders", Role: domain.RoleApp,
				Status: domain.IntentPending, CreatedAt: now, UpdatedAt: now,
			}
			if err := s.InsertIntent(ctx, in); err != nil {
				t.Fatalf("insert: %v", err)
			}
			// Re-insert with the same id is a no-op SUCCESS, not ErrConflict.
			dup := in
			dup.Database = "other" // different payload must NOT clobber the row
			if err := s.InsertIntent(ctx, dup); err != nil {
				t.Fatalf("idempotent re-insert: %v", err)
			}
			got, err := s.GetIntent(ctx, id)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if got.Database != "orders" || got.Status != domain.IntentPending || got.Kind != domain.IntentProvision {
				t.Fatalf("row mutated by dup insert: %+v", got)
			}
			if _, err := s.GetIntent(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("missing: want ErrNotFound got %v", err)
			}
		})
	}
}

func TestContract_IntentClaimAndLease(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			s := f.make(t)
			ctx := context.Background()
			now := time.Now().UTC()
			mkIntentGrant(t, s, "g-1")

			id := domain.IntentID("g-1", domain.IntentProvision)
			if err := s.InsertIntent(ctx, domain.Intent{
				ID: id, GrantID: "g-1", Kind: domain.IntentProvision,
				BackendID: "b-1", Role: domain.RoleApp,
				Status: domain.IntentPending, CreatedAt: now, UpdatedAt: now,
			}); err != nil {
				t.Fatal(err)
			}

			claimed, err := s.ClaimPendingIntents(ctx, "worker-A", nil, time.Minute, 10)
			if err != nil {
				t.Fatalf("claim: %v", err)
			}
			if len(claimed) != 1 {
				t.Fatalf("claimed %d, want 1", len(claimed))
			}
			c := claimed[0]
			if c.Status != domain.IntentInFlight || c.WorkerID != "worker-A" || c.LeaseExpiresAt == nil {
				t.Fatalf("not leased: %+v", c)
			}

			// A second claim finds nothing — the row is leased and fresh.
			again, err := s.ClaimPendingIntents(ctx, "worker-B", nil, time.Minute, 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(again) != 0 {
				t.Fatalf("second claim got %d, want 0", len(again))
			}

			// Heartbeat / complete / fail only the owner.
			if err := s.HeartbeatIntentLease(ctx, id, "worker-B", time.Minute); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("foreign heartbeat: want ErrNotFound got %v", err)
			}
			if err := s.HeartbeatIntentLease(ctx, id, "worker-A", 2*time.Minute); err != nil {
				t.Fatalf("owner heartbeat: %v", err)
			}
			if err := s.CompleteIntent(ctx, id, "worker-B", "u", "p"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("foreign complete: want ErrNotFound got %v", err)
			}
			if err := s.FailIntent(ctx, id, "worker-B", "x", "y", 1); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("foreign fail: want ErrNotFound got %v", err)
			}
			if err := s.CompleteIntent(ctx, id, "worker-A", "ap_user", "secret"); err != nil {
				t.Fatalf("owner complete: %v", err)
			}
			done, _ := s.GetIntent(ctx, id)
			if done.Status != domain.IntentDone || done.CompletedAt == nil {
				t.Fatalf("not done: %+v", done)
			}
			// Completing an already-done row fails (no longer in_flight).
			if err := s.CompleteIntent(ctx, id, "worker-A", "u", "p"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("re-complete: want ErrNotFound got %v", err)
			}
		})
	}
}

// TestContract_ResetIntentForRetry covers HIGH-2: a failed intent can be re-armed
// to pending so a re-claim re-drives it, while a non-failed row is left untouched.
func TestContract_ResetIntentForRetry(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			s := f.make(t)
			ctx := context.Background()
			now := time.Now().UTC()
			mkIntentGrant(t, s, "g-1")

			id := domain.IntentID("g-1", domain.IntentProvision)
			if err := s.InsertIntent(ctx, domain.Intent{
				ID: id, GrantID: "g-1", Kind: domain.IntentProvision,
				BackendID: "b-1", Role: domain.RoleApp,
				Status: domain.IntentPending, CreatedAt: now, UpdatedAt: now,
			}); err != nil {
				t.Fatal(err)
			}

			// A pending row is not failed → ErrNotFound (race-safe no-op).
			if err := s.ResetIntentForRetry(ctx, id); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("reset on pending: want ErrNotFound, got %v", err)
			}

			// Drive it to failed via claim + fail.
			if _, err := s.ClaimPendingIntents(ctx, "worker-A", nil, time.Minute, 10); err != nil {
				t.Fatalf("claim: %v", err)
			}
			if err := s.FailIntent(ctx, id, "worker-A", "transient_network", "blip", 3); err != nil {
				t.Fatalf("fail: %v", err)
			}

			// Reset clears the bookkeeping and flips back to pending.
			if err := s.ResetIntentForRetry(ctx, id); err != nil {
				t.Fatalf("reset on failed: %v", err)
			}
			got, err := s.GetIntent(ctx, id)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if got.Status != domain.IntentPending {
				t.Errorf("status = %q, want pending", got.Status)
			}
			if got.WorkerID != "" || got.LeaseExpiresAt != nil || got.ErrorClass != "" || got.ErrorDetail != "" || got.RetryCount != 0 {
				t.Errorf("reset did not clear bookkeeping: %+v", got)
			}

			// A re-claim now finds the re-armed row — proves it re-enters the queue.
			reclaimed, err := s.ClaimPendingIntents(ctx, "worker-B", nil, time.Minute, 10)
			if err != nil {
				t.Fatalf("reclaim: %v", err)
			}
			if len(reclaimed) != 1 || reclaimed[0].ID != id {
				t.Fatalf("reclaim got %d rows, want the reset intent back in the queue", len(reclaimed))
			}

			// Resetting a now-in_flight row is a no-op (don't yank an active retry).
			if err := s.ResetIntentForRetry(ctx, id); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("reset on in_flight: want ErrNotFound, got %v", err)
			}

			// Absent row → ErrNotFound.
			if err := s.ResetIntentForRetry(ctx, "ip-does-not-exist"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("reset on missing: want ErrNotFound, got %v", err)
			}
		})
	}
}

func TestContract_IntentClaimOrderingAndWhitelist(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			s := f.make(t)
			ctx := context.Background()
			now := time.Now().UTC()
			// Two backends, two grants so the pg FK is satisfied per backend.
			_ = s.CreateUser(ctx, domain.User{ID: "u-1", Username: "alice", Status: "active", CreatedAt: now, UpdatedAt: now})
			_ = s.CreateBackend(ctx, domain.Backend{ID: "b-1", Name: "pg1", Type: domain.ProxyPostgres, Host: "h1", Port: 5432, CreatedAt: now, UpdatedAt: now})
			_ = s.CreateBackend(ctx, domain.Backend{ID: "b-2", Name: "pg2", Type: domain.ProxyPostgres, Host: "h2", Port: 5432, CreatedAt: now, UpdatedAt: now})
			mkGrant := func(id, backend string) {
				if err := s.CreateGrant(ctx, domain.Grant{
					ID: id, UserID: "u-1", BackendID: backend, Role: domain.RoleApp,
					Status: domain.GrantApproved, RequestedAt: now, CreatedAt: now, UpdatedAt: now,
				}); err != nil {
					t.Fatal(err)
				}
			}
			mkGrant("g-1", "b-1")
			mkGrant("g-2", "b-1")
			mkGrant("g-3", "b-2")

			mkIntent := func(grantID string, kind domain.IntentKind, backend string, createdAt time.Time) string {
				id := domain.IntentID(grantID, kind)
				if err := s.InsertIntent(ctx, domain.Intent{
					ID: id, GrantID: grantID, Kind: kind, BackendID: backend,
					Role: domain.RoleApp, Status: domain.IntentPending,
					CreatedAt: createdAt, UpdatedAt: createdAt,
				}); err != nil {
					t.Fatal(err)
				}
				return id
			}
			// provision is OLDER than revoke, yet revoke must sort first.
			provID := mkIntent("g-1", domain.IntentProvision, "b-1", now)
			revID := mkIntent("g-2", domain.IntentRevoke, "b-1", now.Add(time.Second))
			_ = mkIntent("g-3", domain.IntentProvision, "b-2", now)

			// Whitelist b-1 only → b-2 intent excluded; revoke before provision.
			claimed, err := s.ClaimPendingIntents(ctx, "w", []string{"b-1"}, time.Minute, 10)
			if err != nil {
				t.Fatalf("claim: %v", err)
			}
			if len(claimed) != 2 {
				t.Fatalf("claimed %d, want 2 (b-2 excluded)", len(claimed))
			}
			if claimed[0].ID != revID || claimed[1].ID != provID {
				t.Fatalf("ordering: got %s,%s want revoke(%s),provision(%s)",
					claimed[0].ID, claimed[1].ID, revID, provID)
			}
			for _, c := range claimed {
				if c.BackendID != "b-1" {
					t.Fatalf("whitelist leak: %+v", c)
				}
			}
		})
	}
}

func TestContract_IntentStaleLeaseReclaim(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			s := f.make(t)
			ctx := context.Background()
			now := time.Now().UTC()
			mkIntentGrant(t, s, "g-1")
			id := domain.IntentID("g-1", domain.IntentProvision)
			if err := s.InsertIntent(ctx, domain.Intent{
				ID: id, GrantID: "g-1", Kind: domain.IntentProvision,
				BackendID: "b-1", Role: domain.RoleApp,
				Status: domain.IntentPending, CreatedAt: now, UpdatedAt: now,
			}); err != nil {
				t.Fatal(err)
			}
			// worker-A claims with a lease that expires immediately, then dies.
			if _, err := s.ClaimPendingIntents(ctx, "worker-A", nil, -time.Second, 10); err != nil {
				t.Fatal(err)
			}
			// worker-B reclaims the now-stale in_flight row.
			reclaimed, err := s.ClaimPendingIntents(ctx, "worker-B", nil, time.Minute, 10)
			if err != nil {
				t.Fatalf("reclaim: %v", err)
			}
			if len(reclaimed) != 1 || reclaimed[0].WorkerID != "worker-B" {
				t.Fatalf("stale reclaim failed: %+v", reclaimed)
			}
			// worker-A can no longer heartbeat — it lost the lease.
			if err := s.HeartbeatIntentLease(ctx, id, "worker-A", time.Minute); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("stale owner heartbeat: want ErrNotFound got %v", err)
			}
		})
	}
}

func TestContract_GetLatestIntentForGrant(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			s := f.make(t)
			ctx := context.Background()
			now := time.Now().UTC()
			mkIntentGrant(t, s, "g-1")

			// One provision + one revoke for the same grant; query each kind.
			provID := domain.IntentID("g-1", domain.IntentProvision)
			revID := domain.IntentID("g-1", domain.IntentRevoke)
			if err := s.InsertIntent(ctx, domain.Intent{
				ID: provID, GrantID: "g-1", Kind: domain.IntentProvision, BackendID: "b-1",
				Role: domain.RoleApp, Status: domain.IntentPending, CreatedAt: now, UpdatedAt: now,
			}); err != nil {
				t.Fatal(err)
			}
			if err := s.InsertIntent(ctx, domain.Intent{
				ID: revID, GrantID: "g-1", Kind: domain.IntentRevoke, BackendID: "b-1",
				Role: domain.RoleApp, Status: domain.IntentPending, CreatedAt: now.Add(time.Hour), UpdatedAt: now.Add(time.Hour),
			}); err != nil {
				t.Fatal(err)
			}
			gotProv, err := s.GetLatestIntentForGrant(ctx, "g-1", domain.IntentProvision)
			if err != nil || gotProv.ID != provID {
				t.Fatalf("latest provision: %+v %v", gotProv, err)
			}
			gotRev, err := s.GetLatestIntentForGrant(ctx, "g-1", domain.IntentRevoke)
			if err != nil || gotRev.ID != revID {
				t.Fatalf("latest revoke: %+v %v", gotRev, err)
			}
			if _, err := s.GetLatestIntentForGrant(ctx, "g-nope", domain.IntentProvision); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("missing: want ErrNotFound got %v", err)
			}
		})
	}
}

// TestContract_IntentResultEncryptionRoundTrip pins the at-rest encryption of
// the result columns through the Encrypting wrapper: a credential written via
// CompleteIntent comes back decrypted on read, and the raw row underneath the
// wrapper is NOT the plaintext.
func TestContract_IntentResultEncryptionRoundTrip(t *testing.T) {
	cipher := newTestCipher(t)
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			inner := f.make(t)
			enc := store.NewEncrypting(inner, cipher, slog.New(slog.NewTextHandler(writerDiscard{}, nil)))
			ctx := context.Background()
			now := time.Now().UTC()
			mkIntentGrant(t, enc, "g-1")

			id := domain.IntentID("g-1", domain.IntentProvision)
			if err := enc.InsertIntent(ctx, domain.Intent{
				ID: id, GrantID: "g-1", Kind: domain.IntentProvision, BackendID: "b-1",
				Role: domain.RoleApp, Status: domain.IntentPending, CreatedAt: now, UpdatedAt: now,
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := enc.ClaimPendingIntents(ctx, "w", nil, time.Minute, 10); err != nil {
				t.Fatal(err)
			}
			if err := enc.CompleteIntent(ctx, id, "w", "ap_deadbeef", "s3cr3t-pw"); err != nil {
				t.Fatalf("complete: %v", err)
			}
			got, err := enc.GetIntent(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if got.ResultUsername != "ap_deadbeef" || got.ResultPassword != "s3cr3t-pw" {
				t.Fatalf("decrypted mismatch: %q / %q", got.ResultUsername, got.ResultPassword)
			}
			// The raw row (read straight from the inner store) must be ciphertext.
			raw, err := inner.GetIntent(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if raw.ResultUsername == "ap_deadbeef" || raw.ResultPassword == "s3cr3t-pw" {
				t.Fatalf("result columns stored as plaintext: %q / %q", raw.ResultUsername, raw.ResultPassword)
			}
		})
	}
}

// TestContract_WorkerHeartbeatUpsertList covers the upsert→list round-trip,
// started_at preservation across beats, and the JSON round-trip of Instances +
// Health (including a LastOKAt pointer and an ErrorClass on the unhealthy
// instance).
func TestContract_WorkerHeartbeatUpsertList(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			s := f.make(t)
			ctx := context.Background()
			started := time.Now().UTC().Truncate(time.Second)
			okAt := started.Add(30 * time.Second)

			hb := domain.WorkerHeartbeat{
				WorkerID:  "worker-A",
				Instances: []string{"b-1", "b-2"},
				Health: []domain.InstanceHealth{
					{BackendID: "b-1", OK: true, LastOKAt: &okAt},
					{BackendID: "b-2", OK: false, ErrorClass: "dial_timeout"},
				},
				Version:    "v1.2.3",
				StartedAt:  started,
				LastSeenAt: started,
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
			if got.WorkerID != "worker-A" || got.Version != "v1.2.3" {
				t.Fatalf("scalar mismatch: %+v", got)
			}
			if len(got.Instances) != 2 || got.Instances[0] != "b-1" || got.Instances[1] != "b-2" {
				t.Fatalf("instances round-trip: %+v", got.Instances)
			}
			if len(got.Health) != 2 {
				t.Fatalf("health len = %d, want 2", len(got.Health))
			}
			h0, h1 := got.Health[0], got.Health[1]
			if h0.BackendID != "b-1" || !h0.OK || h0.LastOKAt == nil || !h0.LastOKAt.Equal(okAt) {
				t.Fatalf("health[0] round-trip: %+v", h0)
			}
			if h1.BackendID != "b-2" || h1.OK || h1.ErrorClass != "dial_timeout" || h1.LastOKAt != nil {
				t.Fatalf("health[1] round-trip: %+v", h1)
			}

			// Second beat: started_at must be preserved; last_seen_at + health
			// must advance.
			later := started.Add(5 * time.Minute)
			hb2 := hb
			hb2.StartedAt = later // a later StartedAt MUST be ignored on update
			hb2.LastSeenAt = later
			hb2.Health = []domain.InstanceHealth{{BackendID: "b-1", OK: true, LastOKAt: &later}}
			if err := s.UpsertWorkerHeartbeat(ctx, hb2); err != nil {
				t.Fatalf("second upsert: %v", err)
			}
			list, err = s.ListWorkerHeartbeats(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(list) != 1 {
				t.Fatalf("after re-upsert list len = %d, want 1", len(list))
			}
			got = list[0]
			if !got.StartedAt.Equal(started) {
				t.Fatalf("started_at not preserved: got %v want %v", got.StartedAt, started)
			}
			if !got.LastSeenAt.Equal(later) {
				t.Fatalf("last_seen_at not advanced: got %v want %v", got.LastSeenAt, later)
			}
			if len(got.Health) != 1 || !got.Health[0].OK {
				t.Fatalf("health not updated: %+v", got.Health)
			}
		})
	}
}

// TestContract_WorkerHeartbeatStaleAndPrune covers IsStale's boundary and
// PruneStaleWorkers deleting only rows older than the cutoff.
func TestContract_WorkerHeartbeatStaleAndPrune(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	within := time.Minute

	// IsStale boundary: exactly `within` old is NOT stale; one instant older is.
	atBoundary := domain.WorkerHeartbeat{LastSeenAt: now.Add(-within)}
	if atBoundary.IsStale(now, within) {
		t.Fatalf("worker exactly %v old should not be stale", within)
	}
	pastBoundary := domain.WorkerHeartbeat{LastSeenAt: now.Add(-within - time.Nanosecond)}
	if !pastBoundary.IsStale(now, within) {
		t.Fatalf("worker older than %v should be stale", within)
	}
	fresh := domain.WorkerHeartbeat{LastSeenAt: now}
	if fresh.IsStale(now, within) {
		t.Fatalf("just-seen worker should not be stale")
	}

	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			s := f.make(t)
			ctx := context.Background()

			// stale: last seen 10m ago; fresh: last seen now.
			stale := domain.WorkerHeartbeat{
				WorkerID: "worker-stale", StartedAt: now.Add(-time.Hour), LastSeenAt: now.Add(-10 * time.Minute),
			}
			freshHB := domain.WorkerHeartbeat{
				WorkerID: "worker-fresh", StartedAt: now.Add(-time.Hour), LastSeenAt: now,
			}
			if err := s.UpsertWorkerHeartbeat(ctx, stale); err != nil {
				t.Fatal(err)
			}
			if err := s.UpsertWorkerHeartbeat(ctx, freshHB); err != nil {
				t.Fatal(err)
			}

			cutoff := now.Add(-within)
			n, err := s.PruneStaleWorkers(ctx, cutoff)
			if err != nil {
				t.Fatalf("prune: %v", err)
			}
			if n != 1 {
				t.Fatalf("pruned %d, want 1 (only the stale worker)", n)
			}
			list, err := s.ListWorkerHeartbeats(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(list) != 1 || list[0].WorkerID != "worker-fresh" {
				t.Fatalf("after prune: %+v, want only worker-fresh", list)
			}
		})
	}
}

func TestFactory_UnknownURL(t *testing.T) {
	if _, err := store.NewFromURL("redis://x"); err == nil {
		t.Fatal("expected error for unknown URL scheme")
	}
}

func TestFactory_MemoryDefault(t *testing.T) {
	s, err := store.NewFromURL("")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.(*store.Memory); !ok {
		t.Fatalf("expected *Memory, got %T", s)
	}
}

func TestSweeper_TriggersAndCounts(t *testing.T) {
	s := store.NewMemory()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	now := time.Now().UTC()
	// 100 entries, half older than the retention window.
	var batch []domain.AuditEntry
	for i := 0; i < 100; i++ {
		batch = append(batch, domain.AuditEntry{
			Timestamp: now.Add(-time.Duration(i) * time.Hour),
			GrantID:   "g-1", Username: "alice", Query: "SELECT 1",
		})
	}
	if err := s.AppendAudit(ctx, batch); err != nil {
		t.Fatal(err)
	}
	m := lifecycle.NewAuditMetrics()
	logger := slog.New(slog.NewTextHandler(writerDiscard{}, nil))

	done := make(chan struct{})
	go func() {
		lifecycle.Run(ctx, s, lifecycle.SweeperConfig{
			RetentionDays: 1,
			MaxEntries:    10,
			Interval:      50 * time.Millisecond,
		}, m, logger)
		close(done)
	}()

	// Poll until metrics update (first sweep runs synchronously at start but
	// the metric write races; give it a grace window).
	deadline := time.Now().Add(2 * time.Second)
	var total, pruned uint64
	for time.Now().Before(deadline) {
		total, pruned = m.Snapshot()
		if total <= 10 && pruned > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if total > 10 {
		t.Fatalf("expected total<=10, got %d", total)
	}
	if pruned == 0 {
		t.Fatal("expected pruned > 0")
	}
	cancel()
	<-done
}

func TestSweeper_PrunesExpiredSessions(t *testing.T) {
	s := store.NewMemory()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	now := time.Now().UTC()
	if err := s.CreateSession(ctx, store.SessionRecord{ID: "live", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, store.SessionRecord{ID: "dead", ExpiresAt: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	m := lifecycle.NewAuditMetrics()
	logger := slog.New(slog.NewTextHandler(writerDiscard{}, nil))

	done := make(chan struct{})
	go func() {
		lifecycle.Run(ctx, s, lifecycle.SweeperConfig{
			Interval: 50 * time.Millisecond,
		}, m, logger)
		close(done)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if m.SessionsPruned() >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if m.SessionsPruned() < 1 {
		t.Fatalf("expected >=1 sessions pruned, got %d", m.SessionsPruned())
	}
	if _, err := s.GetSession(ctx, "dead"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("dead session survived sweep: %v", err)
	}
	if _, err := s.GetSession(ctx, "live"); err != nil {
		t.Fatalf("live session missing: %v", err)
	}
	cancel()
	<-done
}

func TestSweeper_IntervalZeroExits(t *testing.T) {
	s := store.NewMemory()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := atomic.Bool{}
	go func() {
		lifecycle.Run(ctx, s, lifecycle.SweeperConfig{Interval: 0}, nil, nil)
		done.Store(true)
	}()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if done.Load() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("sweeper with interval<=0 should exit immediately")
}

type writerDiscard struct{}

func (writerDiscard) Write(p []byte) (int, error) { return len(p), nil }
