// Package provisioning is the portal (producer) side of the provisioning
// outbox described in specs/phase-8-provisioning-worker.md §8.3/§8.5. It turns
// grants into durable provision/revoke intents, wakes idle workers over a
// store-aware notification channel, and waits (bounded) for the worker's
// result so /claim can return credentials or fall back to 202.
//
// This package owns NO DB-privilege code and never computes ephemeral
// credentials — that is exclusively the worker's job. It only emits intents
// and reads back what the worker durably wrote.
package provisioning

import (
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
)

// buildIntent freezes the routing context a worker needs onto a fresh intent.
//
// Why freeze here and not let the worker re-read the grant: a concurrent grant
// edit (re-approval, role change, revoke) must not shift the ground under an
// in-flight worker. The intent is the immutable contract — see the type doc on
// domain.Intent. The id is deterministic (domain.IntentID) so producer retries
// hit INSERT ... ON CONFLICT DO NOTHING and never spawn a duplicate row.
//
// Pure and side-effect free: takes a grant, returns the intent value. The
// Client layer is responsible for persistence and notification.
func buildIntent(g domain.Grant, kind domain.IntentKind) domain.Intent {
	return domain.Intent{
		ID:        domain.IntentID(g.ID, kind),
		GrantID:   g.ID,
		Kind:      kind,
		BackendID: g.BackendID,
		Database:  g.Database,
		Role:      g.Role,
		Status:    domain.IntentPending,
	}
}

// ProvisionIntent builds the intent that asks the worker to CREATE USER + GRANT
// for the grant's role. The worker derives the username deterministically, so
// TargetUsername is intentionally left empty here.
//
// ttl is the effective credential lifetime the worker should honour, passed
// explicitly because at /claim time the grant's ExpiresAt is still nil — it is
// only stamped once the claim succeeds. Deriving the duration from the grant
// here would therefore always yield 0. A non-positive ttl freezes
// RequestedDurationSec at 0, meaning "no explicit expiry" — backends that don't
// support time-boxed users just ignore it.
func ProvisionIntent(g domain.Grant, ttl time.Duration) domain.Intent {
	in := buildIntent(g, domain.IntentProvision)
	if ttl > 0 {
		in.RequestedDurationSec = int(ttl.Seconds())
	}
	return in
}

// RevokeIntent builds the intent that asks the worker to DROP the ephemeral
// user previously provisioned for the grant. TargetUsername carries the exact
// account name to drop, taken from the grant — teardown must target the user
// that was actually created, not a freshly recomputed name. Revoke needs no
// TTL: it is tearing an account down, not minting a time-boxed one.
func RevokeIntent(g domain.Grant) domain.Intent {
	in := buildIntent(g, domain.IntentRevoke)
	in.TargetUsername = g.EphemeralUsername
	return in
}
