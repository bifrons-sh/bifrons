// Package authz is the single source of truth for "can this caller take
// this action on this grant?".
//
// Before this package existed, every handler in portal/internal/api re-derived
// admin / owner / validator checks inline, which made the rules hard to audit
// and easy to drift. Now handlers build a Principal once and call Authorize;
// the rulebook lives here.
package authz

import (
	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/entra"
	"github.com/babs/poc-proxies/portal/internal/oidc"
)

// Principal is the authenticated caller: either an OIDC session or the
// static-bearer operator credential (sess == nil). EntraWired reflects whether
// the portal is running with an Entra integration — it affects the dual-gate
// demotion rule for the static bearer.
//
// IsOperator and T2 eligibility are deliberately orthogonal (see
// specs/phase-7-validation-ui.md §7.8.1 / §7.8.7):
//
//   - IsOperator is portal config authority — mutates org/users/backends,
//     patches/revokes grants, acts on-behalf-of on /claim. Derived from
//     users.is_operator via the OIDC session (or implied by static-bearer).
//   - T2Subjects is the per-request snapshot of OIDC subjects eligible to
//     clear gate2 — populated from the backend's t2_group_slug's members. An
//     operator is NOT automatically T2-eligible unless their subject is
//     in that group; likewise, a T2-eligible user is NOT automatically an
//     operator. Static-bearer keeps the bootstrap automation bypass on
//     T2 because it's the privileged CLI credential — audit-loud but
//     unavoidable until a dedicated break-glass path lands (§7.8.9 TBD).
type Principal struct {
	Session    *oidc.Session
	EntraWired bool
	// T2Subjects is the set of OIDC subjects authorised to clear gate2
	// on this request. nil or empty ⇒ no T2 group configured / resolvable
	// — only static-bearer can still act in the T2 slot. Populated by the
	// handler from store.ListGroupMembers(backend's t2_group_slug).
	T2Subjects map[string]struct{}
}

// NewPrincipal builds a Principal from the current request context. T2
// eligibility defaults to empty; callers that exercise the approval flow
// must call WithT2Subjects to attach the resolved set.
func NewPrincipal(sess *oidc.Session, entraClient entra.Client) Principal {
	return Principal{Session: sess, EntraWired: entraClient != nil}
}

// WithT2Subjects returns a copy of p with the T2-eligibility set replaced.
// Pass the set resolved from store.ListGroupMembers(backend's t2_group_slug) so
// gate2 authz + the IsValidatorFor collapse-path both know who can act.
func (p Principal) WithT2Subjects(t2 map[string]struct{}) Principal {
	p.T2Subjects = t2
	return p
}

// IsStaticBearer reports whether the caller authenticated with the static
// bearer (no OIDC session attached).
func (p Principal) IsStaticBearer() bool { return p.Session == nil }

// IsOperator reports whether the caller has portal config authority. Static-
// bearer always counts — it's the privileged operator credential. OIDC
// sessions require the IsOperator claim (users.is_operator column).
//
// This is config authority only. Do NOT use for gate2 eligibility — use
// IsT2Eligible instead. See package doc for the rationale.
func (p Principal) IsOperator() bool {
	if p.IsStaticBearer() {
		return true
	}
	return p.Session.IsOperator
}

// IsT2Eligible reports whether the caller may clear the gate2 / admin-tier
// validator slot. Membership is decided by T2Subjects (resolved from the
// backend's t2_group_slug). Static-bearer retains bootstrap bypass.
//
// Returns false when T2Subjects is empty AND the caller isn't static-bearer
// — deployments that forget to populate the admin group see grants stranded
// at VALIDATOR_APPROVED with a clear authz decline, rather than silently
// falling through to the operator bundle.
func (p Principal) IsT2Eligible() bool {
	if p.IsStaticBearer() {
		return true
	}
	if p.Session == nil || p.Session.Subject == "" {
		return false
	}
	_, ok := p.T2Subjects[p.Session.Subject]
	return ok
}

// Subject returns the caller's OIDC subject, or empty for static-bearer.
func (p Principal) Subject() string {
	if p.Session == nil {
		return ""
	}
	return p.Session.Subject
}

// PortalUserID returns the caller's portal user binding, or empty for
// static-bearer / unprovisioned sessions.
func (p Principal) PortalUserID() string {
	if p.Session == nil {
		return ""
	}
	return p.Session.PortalUserID
}

// IsOwnerOf reports whether the caller owns the grant — either because their
// portal-user-id matches the grant's user-id, or because their OIDC subject
// was the one that originally requested it.
func (p Principal) IsOwnerOf(g domain.Grant) bool {
	if p.Session == nil {
		return false
	}
	if p.Session.PortalUserID != "" && p.Session.PortalUserID == g.UserID {
		return true
	}
	if p.Session.Subject != "" && p.Session.Subject == g.RequestedBy {
		return true
	}
	return false
}

// IsValidatorFor reports whether the caller can satisfy the T1 / validator
// half of the dual gate.
//
// Rules:
//   - Static bearer: satisfies when Entra isn't wired OR the grant has no
//     T1Subject recorded. Keeps bootstrap automation working.
//   - OIDC session whose `sub` equals `g.T1Subject`: natural T1 — always yes.
//   - OIDC session with no T1Subject recorded on the grant: collapses to
//     the T2 set, so any T2-eligible caller can clear the gate instead of
//     the grant stranding. The bundled "is_operator == T2" behaviour that
//     used to live here is gone — operators who are not in the admin
//     group cannot collapse their way into a validator slot.
//   - Everything else: no.
func (p Principal) IsValidatorFor(g domain.Grant) bool {
	if p.IsStaticBearer() {
		return !p.EntraWired || g.T1Subject == ""
	}
	if g.T1Subject == "" {
		return p.IsT2Eligible()
	}
	return p.Session.Subject == g.T1Subject
}

// Action names a user-initiated action on a grant. Kept as a closed enum so
// every policy rule lands in the Authorize switch.
type Action string

const (
	ActionView           Action = "view"            // GET /grants/:id
	ActionCreate         Action = "create"          // POST /grants
	ActionPatch          Action = "patch"           // PATCH /grants/:id
	ActionApproveT1 Action = "approve_t1" // POST /grants/:id/approve (T1 / validator half)
	ActionApproveT2 Action = "approve_t2" // POST /grants/:id/approve (T2 / admin half)
	ActionDeny           Action = "deny"           // POST /grants/:id/deny
	ActionClaim          Action = "claim"          // POST /grants/:id/claim
	ActionRevoke         Action = "revoke"         // DELETE /grants/:id
)

// Decision is the result of an authorization check. NotFoundErr is returned
// when we want the caller to see a 404 instead of a 403 — probe-resistance
// for ownership checks so a stranger can't confirm a grant id exists.
type Decision struct {
	Allow       bool
	Reason      string
	NotFoundErr bool
}

// Allowed returns a decision allowing the action. Sugar for readability.
func Allowed() Decision { return Decision{Allow: true} }

// Denied returns a decision denying the action with a user-facing reason.
func Denied(reason string) Decision { return Decision{Reason: reason} }

// DeniedAsNotFound denies the action and signals the caller should return 404
// (not 403) — used when revealing grant existence to a non-owner is itself a leak.
func DeniedAsNotFound() Decision { return Decision{NotFoundErr: true} }

// Authorize is the single rulebook. g is optional: Create doesn't need one,
// every other action does.
func Authorize(a Action, g domain.Grant, p Principal) Decision {
	switch a {
	case ActionView:
		if p.IsOperator() || p.IsOwnerOf(g) {
			return Allowed()
		}
		return DeniedAsNotFound()

	case ActionCreate:
		// Admins / static-bearer bypass; non-admins are scoped to self by the
		// handler before we get here (the handler rewrites req.UserID →
		// sess.PortalUserID). This entry exists so /grants POST can still go
		// through Authorize for symmetry.
		if p.IsOperator() {
			return Allowed()
		}
		if p.Session == nil || p.Session.PortalUserID == "" {
			return Denied("session has no portal user binding")
		}
		return Allowed()

	case ActionPatch, ActionRevoke:
		if p.IsOperator() {
			return Allowed()
		}
		return Denied("admin privileges required")

	case ActionApproveT1:
		if p.IsValidatorFor(g) {
			return Allowed()
		}
		return Denied("validator approval required first")

	case ActionApproveT2:
		if p.IsT2Eligible() {
			return Allowed()
		}
		return Denied("gate2 requires a T2-eligible approver (member of the admin group)")

	case ActionDeny:
		// Deny is a safety decision — either gate's eligible set can exercise
		// it. Operators cannot deny unless they also happen to be T1 or T2.
		if p.IsT2Eligible() || p.IsValidatorFor(g) {
			return Allowed()
		}
		return Denied("deny requires a T1 or T2 approver")

	case ActionClaim:
		if p.IsOperator() || p.IsOwnerOf(g) {
			return Allowed()
		}
		return Denied("claim requires the requester or an admin")
	}
	return Denied("unknown action")
}
