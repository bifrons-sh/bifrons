package lifecycle

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/babs/poc-proxies/portal/internal/api"
	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// maxReconcilePerSweep bounds how many APPROVED grants one reconcile pass
// inspects so a large backlog can't monopolise the sweep window. The remainder
// is picked up on the next tick.
const maxReconcilePerSweep = 200

// ReconcileProvisionedGrants covers the sad path of the async claim handshake
// (spec §8.5.1): a requester POSTed /claim, got a 202 (provisioning still in
// flight), and never polled …/claim/status. The done provision intent then sits
// unconsumed with the grant stuck APPROVED. This pass finds those grants and
// propagates the worker's credential — SetGrantEphemeral + APPROVED→ACTIVE —
// using exactly the same store calls the /claim path uses, so the outcome is
// identical regardless of who consumes the intent.
//
// Bounded (maxReconcilePerSweep) and best-effort: per-grant errors are logged
// and skipped, never fatal. Returns the number of grants flipped to ACTIVE.
func ReconcileProvisionedGrants(ctx context.Context, s store.Store, credentialTTL time.Duration, logger *slog.Logger) int {
	if logger == nil {
		logger = slog.Default()
	}
	approved, err := s.ListGrants(ctx, store.GrantFilter{
		Statuses: []domain.GrantStatus{domain.GrantApproved},
		Limit:    maxReconcilePerSweep,
	})
	if err != nil {
		logger.Warn("provision_reconcile_list_failed", "err", err)
		return 0
	}
	ttl := credentialTTL
	if ttl <= 0 {
		// M1: same fallback source as the /claim handler, so a reconciled grant
		// and an inline-claimed grant carry an identical TTL.
		ttl = api.DefaultCredentialTTL
	}
	flipped := 0
	for _, g := range approved {
		in, err := s.GetLatestIntentForGrant(ctx, g.ID, domain.IntentProvision)
		if err != nil {
			// No intent (never claimed) is the common case — not worth a log.
			if !errors.Is(err, store.ErrNotFound) {
				logger.Warn("provision_reconcile_intent_lookup_failed", "grant_id", g.ID, "err", err)
			}
			continue
		}
		if in.Status != domain.IntentDone {
			continue
		}
		if err := propagate(ctx, s, g, in, ttl); err != nil {
			logger.Warn("provision_reconcile_propagate_failed", "grant_id", g.ID, "err", err)
			continue
		}
		flipped++
		logger.Info("grant_reconciled_active", "grant_id", g.ID, "intent_id", in.ID)
	}
	return flipped
}

// ReconcileRevokedEphemeral closes the revoke loop (H2). When a grant reaches a
// terminal state (DENIED/EXPIRED/REVOKED) the handler / orphan sweep emit a
// revoke intent, but nothing consumes the *done* result: the grant keeps its
// ephemeral_username, so ListEphemeralOrphans re-lists it every sweep and the
// orphan sweep re-emits a revoke intent forever — saturating the orphan cap and
// starving genuinely-new orphans. This pass finds those terminal grants whose
// latest REVOKE intent is done (the backend user is actually gone) and clears
// the ephemeral columns via SetGrantEphemeral(id, "", ""), so the grant drops
// out of the orphan list.
//
// Bounded (maxReconcilePerSweep) and best-effort, mirroring
// ReconcileProvisionedGrants: per-grant errors are logged and skipped, never
// fatal. Returns the number of grants whose ephemeral columns were cleared.
func ReconcileRevokedEphemeral(ctx context.Context, s store.Store, logger *slog.Logger) int {
	if logger == nil {
		logger = slog.Default()
	}
	// ListEphemeralOrphans already scopes to terminal-state grants carrying a
	// non-empty ephemeral_username — exactly the candidate set here.
	orphans, err := s.ListEphemeralOrphans(ctx)
	if err != nil {
		logger.Warn("revoke_reconcile_list_failed", "err", err)
		return 0
	}
	if len(orphans) > maxReconcilePerSweep {
		orphans = orphans[:maxReconcilePerSweep]
	}
	cleared := 0
	for _, g := range orphans {
		in, err := s.GetLatestIntentForGrant(ctx, g.ID, domain.IntentRevoke)
		if err != nil {
			// No revoke intent yet (the orphan sweep emits it on a later pass) is
			// the common case — not worth a log.
			if !errors.Is(err, store.ErrNotFound) {
				logger.Warn("revoke_reconcile_intent_lookup_failed", "grant_id", g.ID, "err", err)
			}
			continue
		}
		// Only a DONE revoke means the backend user is actually gone. A pending /
		// in_flight / failed revoke must keep the columns so the orphan sweep
		// keeps the grant in its re-emit set until the DROP lands.
		if in.Status != domain.IntentDone {
			continue
		}
		if err := s.SetGrantEphemeral(ctx, g.ID, "", ""); err != nil {
			logger.Warn("revoke_reconcile_clear_failed", "grant_id", g.ID, "err", err)
			continue
		}
		cleared++
		logger.Info("grant_ephemeral_cleared", "grant_id", g.ID, "intent_id", in.ID)
	}
	return cleared
}

// propagate persists the worker's credential onto the grant and CAS-transitions
// APPROVED→ACTIVE. The intent's result fields arrive already decrypted (shared
// SECRETBOX_KEY via the portal's encrypting store). A status drift between the
// list and the CAS (a concurrent /claim won) surfaces as ErrConflict and is
// treated as a benign no-op by the caller's skip-on-error path.
func propagate(ctx context.Context, s store.Store, g domain.Grant, in domain.Intent, ttl time.Duration) error {
	if err := s.SetGrantEphemeral(ctx, g.ID, in.ResultUsername, in.ResultPassword); err != nil {
		return err
	}
	now := time.Now().UTC()
	exp := now.Add(ttl)
	g.EphemeralUsername = in.ResultUsername
	g.EphemeralPassword = in.ResultPassword
	g.Status = domain.GrantActive
	g.ExpiresAt = &exp
	g.UpdatedAt = now
	return s.UpdateGrantIfStatus(ctx, g, domain.GrantApproved)
}
