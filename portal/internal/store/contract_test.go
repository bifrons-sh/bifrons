package store_test

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/store"

	// Register sqlite so NewFromURL("sqlite::memory:") resolves.
	_ "github.com/babs/poc-proxies/portal/internal/store/sqlite"
)

// factories drives the same behavioural tests against every Store impl so the
// sqlite backend matches the memory backend tick-for-tick (the API tests only
// exercise the memory impl, so a dedicated contract suite catches impl drift).
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
			mkGrant("g-stale", domain.GrantApproved, &past)
			mkGrant("g-live", domain.GrantApproved, &future)
			mkGrant("g-pending", domain.GrantPending, &past) // not APPROVED, leave it
			mkGrant("g-open", domain.GrantApproved, nil)     // no expiry, leave it

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
	m := store.NewAuditMetrics()
	logger := slog.New(slog.NewTextHandler(writerDiscard{}, nil))

	done := make(chan struct{})
	go func() {
		store.RunAuditSweeper(ctx, s, store.AuditSweeperConfig{
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

func TestSweeper_IntervalZeroExits(t *testing.T) {
	s := store.NewMemory()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := atomic.Bool{}
	go func() {
		store.RunAuditSweeper(ctx, s, store.AuditSweeperConfig{Interval: 0}, nil, nil)
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
