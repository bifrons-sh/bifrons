package lifecycle

import (
	"context"
	"testing"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// TestSweeper_PrunesStaleWorkers: a worker dead longer than PruneWorkerAge is
// reaped on a sweep; a fresh worker survives. Run does one immediate sweep on
// start, so a cancelled context still exercises the prune phase exactly once.
func TestSweeper_PrunesStaleWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := store.NewMemory()
	now := time.Now()

	fresh := domain.WorkerHeartbeat{WorkerID: "w-fresh", StartedAt: now.Add(-time.Hour), LastSeenAt: now}
	dead := domain.WorkerHeartbeat{WorkerID: "w-dead", StartedAt: now.Add(-3 * time.Hour), LastSeenAt: now.Add(-2 * time.Hour)}
	if err := s.UpsertWorkerHeartbeat(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertWorkerHeartbeat(ctx, dead); err != nil {
		t.Fatal(err)
	}

	// Cancel before Run so only the synchronous startup sweep executes, then
	// the ticker loop returns immediately on the done context.
	cancel()
	Run(ctx, s, SweeperConfig{
		Interval:       time.Minute,
		PruneWorkerAge: time.Hour,
	}, NewAuditMetrics(), quietLogger())

	hbs, err := s.ListWorkerHeartbeats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(hbs) != 1 || hbs[0].WorkerID != "w-fresh" {
		t.Fatalf("want only w-fresh to survive, got %+v", hbs)
	}
}

// TestSweeper_WorkerPruneDisabled: PruneWorkerAge<=0 leaves all rows intact.
func TestSweeper_WorkerPruneDisabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := store.NewMemory()
	now := time.Now()
	dead := domain.WorkerHeartbeat{WorkerID: "w-dead", StartedAt: now.Add(-3 * time.Hour), LastSeenAt: now.Add(-2 * time.Hour)}
	if err := s.UpsertWorkerHeartbeat(ctx, dead); err != nil {
		t.Fatal(err)
	}
	cancel()
	Run(ctx, s, SweeperConfig{Interval: time.Minute}, NewAuditMetrics(), quietLogger())

	hbs, err := s.ListWorkerHeartbeats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(hbs) != 1 {
		t.Fatalf("prune disabled: want row retained, got %d rows", len(hbs))
	}
}
