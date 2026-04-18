package store

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// AuditSweeperConfig controls the retention sweeper.
type AuditSweeperConfig struct {
	// RetentionDays drops audit entries older than now - RetentionDays.
	// 0 disables the age-based cutoff (cap-only mode).
	RetentionDays int
	// MaxEntries caps the total number of rows. 0 disables the cap.
	MaxEntries int
	// Interval between sweeps. Must be > 0 when the sweeper runs.
	Interval time.Duration
}

// AuditMetrics collects sweeper observability. Safe for concurrent use.
type AuditMetrics struct {
	// entriesTotal is the most recent post-sweep row count.
	entriesTotal atomic.Int64
	// entriesPrunedTotal is a monotonic counter of all rows ever pruned.
	entriesPrunedTotal atomic.Int64
}

// NewAuditMetrics returns a zeroed metrics holder.
func NewAuditMetrics() *AuditMetrics { return &AuditMetrics{} }

// Snapshot returns the current counters (total, pruned_total).
func (m *AuditMetrics) Snapshot() (total, prunedTotal uint64) {
	if m == nil {
		return 0, 0
	}
	return uint64(m.entriesTotal.Load()), uint64(m.entriesPrunedTotal.Load())
}

// SetTotal overrides the cached row count — called by the sweeper on each pass.
func (m *AuditMetrics) SetTotal(n int) {
	if m == nil {
		return
	}
	m.entriesTotal.Store(int64(n))
}

// AddPruned accumulates the pruned counter.
func (m *AuditMetrics) AddPruned(n int) {
	if m == nil || n <= 0 {
		return
	}
	m.entriesPrunedTotal.Add(int64(n))
}

// RunAuditSweeper blocks until ctx is done, periodically calling PruneAudit on
// the store according to cfg. Errors are logged but never fatal — the sweeper
// is a best-effort janitor. It runs one sweep immediately on start so freshly
// booted portals get caught up against backlogs from the previous run.
func RunAuditSweeper(ctx context.Context, s Store, cfg AuditSweeperConfig, m *AuditMetrics, logger *slog.Logger) {
	if cfg.Interval <= 0 {
		// Defensive: an operator setting interval=0 almost certainly meant
		// "disable" rather than "spin hot forever". Log and bail.
		if logger != nil {
			logger.Info("audit_sweeper_disabled", "reason", "interval<=0")
		}
		return
	}

	// Cap the sweep deadline so a configured interval of 24h doesn't turn a
	// runaway DELETE into a day-long lock. 30 min is generous even for
	// multi-million-row audit tables with typical pg write throughput.
	const maxSweepTimeout = 30 * time.Minute
	sweep := func() {
		timeout := min(cfg.Interval, maxSweepTimeout)
		sweepCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		var cutoff time.Time
		if cfg.RetentionDays > 0 {
			cutoff = time.Now().Add(-time.Duration(cfg.RetentionDays) * 24 * time.Hour)
		}
		pruned, total, err := s.PruneAudit(sweepCtx, cutoff, cfg.MaxEntries)
		if err != nil {
			if logger != nil {
				logger.Error("audit_sweep_failed", "err", err)
			}
			return
		}
		m.SetTotal(total)
		m.AddPruned(pruned)
		if logger != nil && pruned > 0 {
			logger.Info("audit_swept", "pruned", pruned, "total", total)
		}
	}

	sweep()
	t := time.NewTicker(cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweep()
		}
	}
}
