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
type Principal struct {
	Session     *oidc.Session
	EntraWired  bool
}

// NewPrincipal builds a Principal from the current request context.
func NewPrincipal(sess *oidc.Session, entraClient entra.Client) Principal {
	return Principal{Session: sess, EntraWired: entraClient != nil}
}

// IsStaticBearer reports whether the caller authenticated with the static
// bearer (no OIDC session attached).
func (p Principal) IsStaticBearer() bool { return p.Session == nil }

// IsAdmin reports whether the caller has admin privileges. Static-bearer
// always counts as admin — it's the privileged operator credential. OIDC
// sessions require the IsAdmin claim.
func (p Principal) IsAdmin() bool {
	if p.IsStaticBearer() {
		return true
	}
	return p.Session.IsAdmin
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

// IsValidatorFor reports whether the caller can satisfy the validator half of the
// dual gate.
//
// Rules:
//   - Static bearer: satisfies when Entra isn't wired OR the grant has no
//     ValidatorSubject recorded. Keeps bootstrap automation working.
//   - OIDC session whose `sub` equals `g.ValidatorSubject`: always yes — the
//     four-eyes guarantee under Entra.
//   - OIDC admin session with no ValidatorSubject recorded on the grant:
//     collapses to admin-only because there is no validator identity to
//     represent; prevents non-Entra grants from stranding forever.
//   - Everything else: no.
func (p Principal) IsValidatorFor(g domain.Grant) bool {
	if p.IsStaticBearer() {
		return !p.EntraWired || g.ValidatorSubject == ""
	}
	if g.ValidatorSubject == "" {
		return p.IsAdmin()
	}
	return p.Session.Subject == g.ValidatorSubject
}

// Action names a user-initiated action on a grant. Kept as a closed enum so
// every policy rule lands in the Authorize switch.
type Action string

const (
	ActionView           Action = "view"            // GET /grants/:id
	ActionCreate         Action = "create"          // POST /grants
	ActionPatch          Action = "patch"           // PATCH /grants/:id
	ActionApproveValidator Action = "approve_validator" // POST /grants/:id/approve (validator half)
	ActionApproveAdmin   Action = "approve_admin"  // POST /grants/:id/approve (admin half)
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
		if p.IsAdmin() || p.IsOwnerOf(g) {
			return Allowed()
		}
		return DeniedAsNotFound()

	case ActionCreate:
		// Admins / static-bearer bypass; non-admins are scoped to self by the
		// handler before we get here (the handler rewrites req.UserID →
		// sess.PortalUserID). This entry exists so /grants POST can still go
		// through Authorize for symmetry.
		if p.IsAdmin() {
			return Allowed()
		}
		if p.Session == nil || p.Session.PortalUserID == "" {
			return Denied("session has no portal user binding")
		}
		return Allowed()

	case ActionPatch, ActionRevoke:
		if p.IsAdmin() {
			return Allowed()
		}
		return Denied("admin privileges required")

	case ActionApproveValidator:
		if p.IsValidatorFor(g) {
			return Allowed()
		}
		return Denied("validator approval required first")

	case ActionApproveAdmin:
		if p.IsAdmin() {
			return Allowed()
		}
		return Denied("admin approval required")

	case ActionDeny:
		if p.IsAdmin() || p.IsValidatorFor(g) {
			return Allowed()
		}
		return Denied("deny requires validator or admin")

	case ActionClaim:
		if p.IsAdmin() || p.IsOwnerOf(g) {
			return Allowed()
		}
		return Denied("claim requires the requester or an admin")
	}
	return Denied("unknown action")
}
