// Package lifecycle owns the out-of-band reconciliation that keeps grant and
// session state consistent with wall-clock deadlines. Hoisting it out of
// store/ keeps the store package as pure persistence; orchestration lives
// here.
package lifecycle

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/babs/poc-proxies/portal/internal/store"
)

// SweeperConfig controls the retention sweeper.
type SweeperConfig struct {
	// RetentionDays drops audit entries older than now - RetentionDays.
	// 0 disables the age-based cutoff (cap-only mode).
	RetentionDays int
	// MaxEntries caps the total number of rows. 0 disables the cap.
	MaxEntries int
	// Interval between sweeps. Must be > 0 when the sweeper runs.
	Interval time.Duration
	// OrphanEphemeralSweep is invoked on each sweep, after audit pruning, if
	// set. The sweeper passes the store handle so the hook can emit revoke
	// intents for orphan ephemeral accounts without importing the store package.
	// Decoupled this way so store/ stays zero-aware of the provisioning client.
	OrphanEphemeralSweep func(ctx context.Context, s store.Store)
	// ReconcileProvisioned, when true, runs the provisioned-grant reconciler on
	// each sweep: APPROVED grants whose latest provision intent is done get
	// their credential propagated and flip to ACTIVE. Covers the sad path where
	// a /claim returned 202 and the requester never polled (spec §8.5.1).
	ReconcileProvisioned bool
	// CredentialTTL is the phase-3 deadline the reconciler stamps onto a grant
	// it flips to ACTIVE. Non-positive falls back to the package default.
	CredentialTTL time.Duration
	// PruneWorkerAge deletes worker-heartbeat rows last seen before
	// now-PruneWorkerAge, so a genuinely-dead worker eventually drops out of
	// the liveness view. Deliberately much longer than the obs stale-threshold
	// (which only flags a row, not deletes it): a brief blip should surface as
	// stale=true but keep the row, while only a worker gone for the long cutoff
	// is reaped. Non-positive disables the phase.
	PruneWorkerAge time.Duration
}

// AuditMetrics collects sweeper observability. Safe for concurrent use.
type AuditMetrics struct {
	// entriesTotal is the most recent post-sweep row count.
	entriesTotal atomic.Int64
	// entriesPrunedTotal is a monotonic counter of all rows ever pruned.
	entriesPrunedTotal atomic.Int64
	// grantsExpiredTotal counts grants reconciled from APPROVED->EXPIRED.
	grantsExpiredTotal atomic.Int64
	// sessionsPrunedTotal counts OIDC sessions reaped by the sweeper.
	sessionsPrunedTotal atomic.Int64
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

// GrantsExpired returns the monotonic count of grants flipped to EXPIRED.
func (m *AuditMetrics) GrantsExpired() uint64 {
	if m == nil {
		return 0
	}
	return uint64(m.grantsExpiredTotal.Load())
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

// AddGrantsExpired accumulates the grants-expired counter.
func (m *AuditMetrics) AddGrantsExpired(n int) {
	if m == nil || n <= 0 {
		return
	}
	m.grantsExpiredTotal.Add(int64(n))
}

// SessionsPruned returns the monotonic count of OIDC sessions reaped.
func (m *AuditMetrics) SessionsPruned() uint64 {
	if m == nil {
		return 0
	}
	return uint64(m.sessionsPrunedTotal.Load())
}

// AddSessionsPruned accumulates the sessions-pruned counter.
func (m *AuditMetrics) AddSessionsPruned(n int) {
	if m == nil || n <= 0 {
		return
	}
	m.sessionsPrunedTotal.Add(int64(n))
}

// RunAuditSweeper blocks until ctx is done, periodically calling PruneAudit on
// the store according to cfg. Errors are logged but never fatal — the sweeper
// is a best-effort janitor. It runs one sweep immediately on start so freshly
// booted portals get caught up against backlogs from the previous run.
func Run(ctx context.Context, s store.Store, cfg SweeperConfig, m *AuditMetrics, logger *slog.Logger) {
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

		// Grant expiry reconciliation. Runs first so a just-expired grant
		// doesn't keep showing up as ACTIVE between audit-prune and the
		// next sweep. Failures here are logged but don't skip audit prune.
		if expired, err := s.ExpireStaleGrants(sweepCtx, time.Now()); err != nil {
			if logger != nil {
				logger.Error("grant_expiry_sweep_failed", "err", err)
			}
		} else {
			m.AddGrantsExpired(expired)
			if logger != nil && expired > 0 {
				logger.Info("grants_expired", "count", expired)
			}
		}
		// Pre-credential expiry passes: PENDING|VALIDATOR_APPROVED past the
		// validation window AND APPROVED past the claim window both transition
		// to EXPIRED. No creds were ever issued so no provisioner work needed.
		if expired, err := s.ExpireUnclaimedGrants(sweepCtx, time.Now()); err != nil {
			if logger != nil {
				logger.Error("grant_unclaimed_sweep_failed", "err", err)
			}
		} else {
			m.AddGrantsExpired(expired)
			if logger != nil && expired > 0 {
				logger.Info("grants_unclaimed_expired", "count", expired)
			}
		}

		// OIDC session reaping — persisted sessions outlive the node that
		// minted them, so a dedicated sweep is required to avoid unbounded
		// table growth. Best-effort: failures are logged, never fatal.
		if reaped, err := s.PruneExpiredSessions(sweepCtx, time.Now()); err != nil {
			if logger != nil {
				logger.Error("session_sweep_failed", "err", err)
			}
		} else {
			m.AddSessionsPruned(reaped)
			if logger != nil && reaped > 0 {
				logger.Info("sessions_pruned", "count", reaped)
			}
		}

		// Worker-heartbeat reaping — drop rows for workers gone longer than the
		// long prune cutoff so the liveness table doesn't accrete dead workers
		// across restarts/renames. Best-effort: failures are logged, never fatal.
		if cfg.PruneWorkerAge > 0 {
			workerCutoff := time.Now().Add(-cfg.PruneWorkerAge)
			if pruned, err := s.PruneStaleWorkers(sweepCtx, workerCutoff); err != nil {
				if logger != nil {
					logger.Error("worker_prune_failed", "err", err)
				}
			} else if logger != nil && pruned > 0 {
				logger.Info("workers_pruned", "count", pruned)
			}
		}

		var cutoff time.Time
		if cfg.RetentionDays > 0 {
			cutoff = time.Now().Add(-time.Duration(cfg.RetentionDays) * 24 * time.Hour)
		}
		// Reconcile done provision intents whose grant is still APPROVED before
		// the orphan sweep, so a freshly-reconciled ACTIVE grant isn't a moving
		// target for orphan detection in the same pass.
		if cfg.ReconcileProvisioned {
			if n := ReconcileProvisionedGrants(sweepCtx, s, cfg.CredentialTTL, logger); n > 0 && logger != nil {
				logger.Info("grants_reconciled_active", "count", n)
			}
			// Close the revoke loop (H2) BEFORE the orphan sweep: clearing the
			// ephemeral columns of terminal grants whose revoke is done drops
			// them out of ListEphemeralOrphans, so the orphan sweep below doesn't
			// re-emit a revoke for an already-gone user this same pass.
			if n := ReconcileRevokedEphemeral(sweepCtx, s, logger); n > 0 && logger != nil {
				logger.Info("grants_ephemeral_cleared", "count", n)
			}
		}
		if cfg.OrphanEphemeralSweep != nil {
			cfg.OrphanEphemeralSweep(sweepCtx, s)
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
