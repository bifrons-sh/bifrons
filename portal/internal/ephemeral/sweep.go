package ephemeral

import (
	"context"
	"log/slog"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// OrphanSweepHook returns a closure suitable for
// lifecycle.SweeperConfig.OrphanEphemeralSweep. It lists terminal-state
// grants that still carry an ephemeral username and drops the backend user
// before clearing the grant's ephemeral fields.
//
// Designed to be cheap when idle (single SELECT returning zero rows). Under a
// sustained flow of revoked grants it still completes in O(orphans) with one
// Revoke per grant — the handler's own Revoke path normally catches these
// first; the sweeper exists for crash-between-status-flip-and-revoke.
func OrphanSweepHook(mgr *Manager, logger *slog.Logger) func(context.Context, store.Store) {
	if logger == nil {
		logger = slog.Default()
	}
	return func(ctx context.Context, s store.Store) {
		if mgr == nil {
			return
		}
		orphans, err := s.ListEphemeralOrphans(ctx)
		if err != nil {
			logger.Warn("ephemeral_orphan_list_failed", "err", err)
			return
		}
		for _, g := range orphans {
			if err := revokeOrphan(ctx, mgr, s, g); err != nil {
				logger.Warn("ephemeral_orphan_revoke_failed",
					"grant_id", g.ID, "err", err)
				continue
			}
			if cerr := s.SetGrantEphemeral(ctx, g.ID, "", ""); cerr != nil {
				logger.Warn("ephemeral_orphan_clear_failed",
					"grant_id", g.ID, "err", cerr)
				continue
			}
			logger.Info("ephemeral_orphan_revoked",
				"grant_id", g.ID, "username", g.EphemeralUsername)
		}
	}
}

// revokeOrphan resolves the backend coords from the store and fires Revoke.
// Split out for test injection: the orphan grant already has enough data to
// rebuild a ProvisionedAccount, but we still need the backend row for its
// Host/Port/Type.
func revokeOrphan(ctx context.Context, mgr *Manager, s store.Store, g domain.Grant) error {
	backend, err := backendByID(ctx, s, g.BackendID)
	if err != nil {
		return err
	}
	bt := MapBackendType(backend.Type)
	if bt == "" {
		return nil // nothing we can do — no provisioner for this type
	}
	acct := ProvisionedAccount{
		Username:    g.EphemeralUsername,
		Password:    g.EphemeralPassword,
		BackendID:   backend.ID,
		BackendType: bt,
		Host:        backend.Host,
		Port:        backend.Port,
		Database:    g.Database,
		GrantID:     g.ID,
	}
	return mgr.Revoke(ctx, bt, acct)
}

// backendByID iterates Backends to find one matching id. Store doesn't expose
// a GetBackend-by-id method today; scanning the short list is fine given the
// sweeper runs at the audit-sweep cadence (hourly by default).
func backendByID(ctx context.Context, s store.Store, id string) (domain.Backend, error) {
	backends, err := s.ListBackends(ctx)
	if err != nil {
		return domain.Backend{}, err
	}
	for _, b := range backends {
		if b.ID == id {
			return b, nil
		}
	}
	return domain.Backend{}, store.ErrNotFound
}
