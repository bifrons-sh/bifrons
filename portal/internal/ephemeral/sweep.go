package ephemeral

import (
	"context"
	"log/slog"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// maxOrphansPerSweep bounds how many orphans one sweep tackles so a large
// backlog can't monopolise the sweep window. The remainder is picked up on the
// next tick; truncation is logged, never silent.
const maxOrphansPerSweep = 100

// RevokeEmitter is the producer half of the provisioning outbox the orphan
// sweeper needs: it emits a revoke intent for a grant. Satisfied by
// *provisioning.Client. Declared here (rather than importing provisioning) so
// the ephemeral package stays free of an import cycle and holds no DBA creds.
type RevokeEmitter interface {
	EmitRevoke(ctx context.Context, g domain.Grant) (domain.Intent, error)
}

// OrphanSweepHook returns a closure suitable for
// lifecycle.SweeperConfig.OrphanEphemeralSweep. It lists terminal-state grants
// that still carry an ephemeral username and emits a revoke intent for each —
// the worker drops the backend user and clears the grant's ephemeral columns
// once it's gone. The portal no longer runs DDL (spec §8.2), so the sweeper is
// purely the durable safety net for a crash between status-flip and the
// handler's own revoke-intent emit; re-emission is idempotent.
//
// Designed to be cheap when idle (single SELECT returning zero rows).
func OrphanSweepHook(emitter RevokeEmitter, logger *slog.Logger) func(context.Context, store.Store) {
	if logger == nil {
		logger = slog.Default()
	}
	return func(ctx context.Context, s store.Store) {
		if emitter == nil {
			return
		}
		orphans, err := s.ListEphemeralOrphans(ctx)
		if err != nil {
			logger.Warn("ephemeral_orphan_list_failed", "err", err)
			return
		}
		if len(orphans) > maxOrphansPerSweep {
			logger.Warn("ephemeral_orphan_sweep_truncated",
				"total", len(orphans), "processing", maxOrphansPerSweep)
			orphans = orphans[:maxOrphansPerSweep]
		}
		for _, g := range orphans {
			if _, err := emitter.EmitRevoke(ctx, g); err != nil {
				logger.Warn("ephemeral_orphan_revoke_emit_failed",
					"grant_id", g.ID, "err", err)
				continue
			}
			// Do NOT clear the grant's ephemeral columns here — the worker drops
			// the user and clears them once the DROP actually lands. Clearing
			// now would hide a still-live backend account from the next sweep if
			// the worker never executes the intent.
			logger.Info("ephemeral_orphan_revoke_emitted",
				"grant_id", g.ID, "username", g.EphemeralUsername)
		}
	}
}
