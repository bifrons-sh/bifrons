package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/babs/poc-proxies/portal/internal/authz"
	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/entra"
	"github.com/babs/poc-proxies/portal/internal/ephemeral"
	"github.com/babs/poc-proxies/portal/internal/notify"
	"github.com/babs/poc-proxies/portal/internal/policy"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// grantsHandler serves the /api/v1/grants collection + /api/v1/grants/:id item routes.
type grantsHandler struct {
	store       store.Store
	logger      *slog.Logger
	autoApprove bool

	// ephemeral is the per-grant backend provisioner. nil = feature disabled;
	// handler falls back to shared BackendAccount path.
	ephemeral *ephemeral.Manager

	// Entra integration for policy + validator resolution. All notification
	// delivery (mail + webhook) goes through `notifier` — `entra` here is
	// only consulted for policy.Authorize groups lookup + Validator resolution
	// at create time. nil ⇒ policy check and validator resolution skipped.
	entra        entra.Client
	requestPol   *policy.RequestPolicy
	entraMetrics *notify.EntraMetrics

	// notifier is the single fan-out seam for grant-lifecycle events. Always
	// non-nil (defaults to notify.Noop in the router when no channels are
	// configured) — handlers call it without guarding.
	notifier notify.Notifier

	// Tri-phase lifecycle defaults — used at /create and /approve when the
	// request body doesn't override them. Zero means "feature off" (no
	// deadline), matching the previous single-window behaviour.
	validationWindow time.Duration
	claimWindow      time.Duration
	credentialTTL    time.Duration
}

// principalForGrant builds the authz Principal for a grant-handler request
// that operates on a specific grant, including the per-request T2-
// eligibility snapshot resolved from THIS backend's admin group. Each
// backend has its own t2_group_slug (see specs/phase-7-validation-ui.md
// §7.8.1 — T2 eligibility is per-backend, not global). Cheap (two store
// lookups, indexed by slug + group id) — acceptable for every /approve call.
func (h *grantsHandler) principalForGrant(r *http.Request, backend domain.Backend) authz.Principal {
	p := authz.NewPrincipal(SessionFromContext(r.Context()), h.entra)
	slug := backend.T2GroupSlug
	if slug == "" {
		return p
	}
	grp, err := h.store.GetGroupBySlug(r.Context(), slug)
	if err != nil {
		h.logger.Warn("backend_t2_group_lookup_failed",
			"backend_id", backend.ID, "slug", slug, "err_class", errClass(err))
		return p
	}
	members, err := h.store.ListGroupMembers(r.Context(), grp.ID)
	if err != nil {
		h.logger.Warn("backend_t2_group_members_lookup_failed",
			"backend_id", backend.ID, "slug", slug, "err_class", errClass(err))
		return p
	}
	set := make(map[string]struct{}, len(members))
	for _, u := range members {
		if u.ExternalID != "" {
			set[u.ExternalID] = struct{}{}
		}
	}
	return p.WithT2Subjects(set)
}


// grantStatusHandler serves GET /api/v1/grants/status/:id — a slim, proxy-facing
// view of a grant used by the mid-session revoke watcher. Mounted on the
// proxy-guarded mux (X-Portal-Token), NOT the user mux, because proxies poll
// it every few seconds per active connection.
type grantStatusHandler struct {
	store  store.Store
	logger *slog.Logger
}

// grantStatusResponse is the minimal payload the proxy watcher consumes.
// Keep this surface small — the watcher polls frequently and we don't want
// to leak unnecessary grant metadata to the proxy.
type grantStatusResponse struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ServeHTTP reads {id} from the Go 1.22 path-value binding set on the route
// pattern the router registers.
func (h *grantStatusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "grant id required")
		return
	}
	g, err := h.store.GetGrant(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "grant not found")
			return
		}
		// Don't leak driver-level detail (pgx/sqlite strings) to the proxy.
		h.logger.Error("grant_status_store_error", "grant_id", id, "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	resp := grantStatusResponse{ID: g.ID, Status: string(g.Status)}
	if g.ExpiresAt != nil {
		resp.ExpiresAt = *g.ExpiresAt
	}
	writeJSON(w, http.StatusOK, resp)
}

// registerGrantRoutes wires every grant endpoint onto mux using Go 1.22
// method + pattern matching. Authorisation is per-endpoint — see HLD:
//   - GET  /api/v1/grants           non-operators see their own; operators see all
//   - POST /api/v1/grants           non-operators create for themselves
//                                   (policy-gated when Entra is wired)
//   - GET  /api/v1/grants/{id}      owner (non-operator) + operator
//   - PATCH/DELETE /api/v1/grants/{id} operator-only
//   - POST /api/v1/grants/{id}/approve|deny|claim  per-action gate
func registerGrantRoutes(mux *http.ServeMux, h *grantsHandler) {
	mux.HandleFunc("GET /api/v1/grants", h.list)
	mux.HandleFunc("POST /api/v1/grants", h.create)
	mux.HandleFunc("GET /api/v1/grants/{id}", func(w http.ResponseWriter, r *http.Request) {
		h.get(w, r, r.PathValue("id"))
	})
	mux.Handle("PATCH /api/v1/grants/{id}", operatorOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.patch(w, r, r.PathValue("id"))
	})))
	mux.Handle("DELETE /api/v1/grants/{id}", operatorOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.revoke(w, r, r.PathValue("id"))
	})))
	// Approval is dispatched inside handleApprove based on caller identity
	// (validator half vs admin half) — requireOperator would reject the validator
	// path, so we don't wrap this one.
	mux.HandleFunc("POST /api/v1/grants/{id}/approve", func(w http.ResponseWriter, r *http.Request) {
		h.handleApprove(w, r, r.PathValue("id"))
	})
	mux.HandleFunc("POST /api/v1/grants/{id}/deny", func(w http.ResponseWriter, r *http.Request) {
		h.deny(w, r, r.PathValue("id"))
	})
	mux.HandleFunc("POST /api/v1/grants/{id}/claim", func(w http.ResponseWriter, r *http.Request) {
		h.claim(w, r, r.PathValue("id"))
	})
}

type createGrantReq struct {
	UserID         string `json:"user_id"`
	BackendAddr    string `json:"backend_addr"` // host:port, resolved to backend
	Database       string `json:"database"`
	Role           string `json:"role"`
	Reason         string `json:"reason"`
	PortalPassword string `json:"portal_password,omitempty"` // optional; auto-generated if empty
	// Per-request overrides for the tri-phase windows. Each accepts a
	// time.ParseDuration string; empty falls back to the portal default.
	ValidationWindow string `json:"validation_window,omitempty"`
	ClaimWindow      string `json:"claim_window,omitempty"`
	CredentialTTL    string `json:"credential_ttl,omitempty"`
}

func (h *grantsHandler) create(w http.ResponseWriter, r *http.Request) {
	var req createGrantReq
	if err := decodeJSONBody(w, r, defaultBodyLimit, &req); err != nil {
		return
	}
	// Non-admin OIDC sessions can only create grants for themselves.
	// Empty user_id → derive from session; explicit user_id must match the
	// session's PortalUserID. Applies whether or not Entra policy is wired —
	// the trio policy gates (instance, database, level) on the *caller's*
	// groups, not on the target user, so without this check a non-operator
	// whose groups allow a trio could mint creds for any teammate.
	// Admins and static-bearer callers bypass via authz.Authorize.
	p := authz.NewPrincipal(SessionFromContext(r.Context()), h.entra)
	if !p.IsOperator() {
		if d := authz.Authorize(authz.ActionCreate, domain.Grant{}, p); !d.Allow {
			writeErr(w, http.StatusForbidden, d.Reason)
			return
		}
		if req.UserID == "" {
			req.UserID = p.PortalUserID()
		} else if req.UserID != p.PortalUserID() {
			writeErr(w, http.StatusForbidden, "non-operator may only create grants for self")
			return
		}
	}
	if req.UserID == "" || req.BackendAddr == "" || req.Role == "" {
		writeErr(w, http.StatusBadRequest, "user_id, backend_addr and role are required")
		return
	}
	// Tri-phase per-request overrides — empty string falls back to portal default.
	validationWindow := h.validationWindow
	if req.ValidationWindow != "" {
		d, err := time.ParseDuration(req.ValidationWindow)
		if err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("invalid validation_window: %v", err))
			return
		}
		validationWindow = d
	}

	user, err := h.store.GetUser(r.Context(), req.UserID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	backend, err := h.store.GetBackendByAddress(r.Context(), req.BackendAddr)
	if err != nil {
		writeErr(w, http.StatusNotFound, "backend not registered")
		return
	}

	// Authorization split:
	//   - OIDC session w/ IsOperator=true → bypass policy (existing scaffold contract).
	//   - Static-bearer callers → bypass policy (privileged operator credential).
	//   - OIDC session w/ IsOperator=false → must satisfy the Entra RequestPolicy;
	//     reject otherwise. No OIDC session + no bearer (open mode) also
	//     bypasses — matches the existing "local dev" semantic.
	sess := SessionFromContext(r.Context())
	isNonOperatorOIDC := sess != nil && !sess.IsOperator
	// Group-based authorisation reads from the portal's local group membership
	// (populated by the sync script). No live IdP call here — the hot path is
	// a single SQL join. requestPol keys on group slugs, so we pass those.
	// resolvedMode caches the verdict so /claim doesn't re-run the lookup;
	// the non-policy path defaults to permanent (shared BackendAccount).
	resolvedMode := policy.ModePermanent
	if isNonOperatorOIDC && h.requestPol != nil {
		groups, gerr := h.store.ListUserGroups(r.Context(), user.ID)
		if gerr != nil {
			h.logger.Warn("user_groups_lookup_failed", "user", user.ID, "err_class", gerr.Error())
			writeErr(w, http.StatusForbidden, "could not resolve user groups")
			return
		}
		slugs := make([]string, 0, len(groups))
		for _, g := range groups {
			slugs = append(slugs, g.Slug)
		}
		mode, err := h.requestPol.Authorize(slugs, backend.Name, req.Database, req.Role)
		if err != nil {
			h.entraMetrics.IncPolicyRejected()
			h.logger.Info("policy_rejected",
				"user", user.ID, "instance", backend.Name, "database", req.Database, "level", req.Role,
			)
			writeErr(w, http.StatusForbidden, policy.ErrRequestNotAllowed.Error())
			return
		}
		resolvedMode = mode
	}

	now := time.Now().UTC()
	requester := principalFrom(r)

	g := domain.Grant{
		ID:             domain.NewID("g"),
		UserID:         user.ID,
		BackendID:      backend.ID,
		Database:       req.Database,
		Role:           domain.Role(req.Role),
		Status:         domain.GrantPending,
		Reason:         req.Reason,
		PortalPassword: firstNonEmpty(req.PortalPassword, domain.NewSecret()),
		RequestedBy:    requester,
		RequestedAt:    now,
		PolicyMode:     resolvedMode,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	// Phase-1 validation window: deadline by which the dual-gate approval
	// must complete. Zero means the operator opted out of the validation
	// deadline — grants then sit indefinitely until someone approves / denies.
	if validationWindow > 0 {
		exp := now.Add(validationWindow)
		g.RequestExpiresAt = &exp
	}
	// Auto-approve escape hatch — bootstrap / demo only, documented as unsafe
	// for prod. Collapses the dual-gate AND the claim phase so the grant lands
	// directly in ACTIVE with ExpiresAt stamped from credentialTTL.
	if h.autoApprove {
		approvedAt := now
		g.Status = domain.GrantActive
		g.T1ApprovedBy = "auto-approve"
		g.T1ApprovedAt = &approvedAt
		g.T2ApprovedAt = &approvedAt
		g.T2ApprovedBy = "auto-approve"
		ttl := h.credentialTTL
		if ttl <= 0 {
			ttl = 4 * time.Hour
		}
		exp := now.Add(ttl)
		g.ExpiresAt = &exp
	}

	// Resolve the validator from the local store (populated by the org-hier
	// sync script — see cmd/entra-sync). No live IdP round-trip on the hot
	// path. When the user has a ValidatorUserID on file, we stamp the grant's
	// T1Subject with the validator's ExternalID (OIDC sub) so the
	// dual-gate dispatch can match the approver's session. A missing validator
	// is logged but never blocks: the T2 gate still promotes it (or the
	// backend's approval_mode collapses the workflow — §7.8.1).
	if g.Status == domain.GrantPending && user.ValidatorUserID != "" {
		mgr, mErr := h.store.GetUser(r.Context(), user.ValidatorUserID)
		if mErr != nil {
			h.entraMetrics.IncValidatorLookupFailed()
			h.logger.Info("validator_lookup_failed", "user", user.ID, "validator_user_id", user.ValidatorUserID, "err_class", errClass(mErr))
		} else {
			g.T1Subject = mgr.ExternalID
			g.ApproverHint = firstNonEmpty(mgr.Email, mgr.Username)
		}
	}

	if err := h.store.CreateGrant(r.Context(), g); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.logger.Info("grant_created",
		"grant_id", g.ID,
		"user", user.Username,
		"backend", backend.Address(),
		"role", g.Role,
		"status", g.Status,
		"requested_by", g.RequestedBy,
		"approver_hint", g.ApproverHint,
		"expires_at", g.ExpiresAt,
	)
	// Fire lifecycle notification — skip when auto-approved because the
	// four-eyes notification would be meaningless. Delivery is async and
	// best-effort inside the notifier; we don't block here.
	if g.Status == domain.GrantPending {
		_ = h.notifier.OnGrantCreated(r.Context(), notify.Event{Grant: g, User: user, Backend: backend})
	}
	writeJSON(w, http.StatusCreated, g)
}

func (h *grantsHandler) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := store.GrantFilter{
		UserID:    q.Get("user_id"),
		BackendID: q.Get("backend_id"),
	}
	if s := q.Get("status"); s != "" {
		filter.Statuses = []domain.GrantStatus{domain.GrantStatus(s)}
	}
	// Scope resolution (phase-7 §7.4 bridge):
	//   - scope=mine     → own grants. Default for non-operators; operators
	//                      who pass it explicitly get the same self-view
	//                      (the SPA "My requests" tab depends on this).
	//   - scope=validator→ grants awaiting caller's validator approval.
	//   - scope=all      → operator-only; every grant. Operator default
	//                      when no scope param is sent.
	// Non-operator sessions are clamped to mine/validator; attempts to
	// forge scope=all or user_id silently self-scope so a curious user
	// can't probe another user's history.
	p := authz.NewPrincipal(SessionFromContext(r.Context()), h.entra)
	scope := q.Get("scope")
	if !p.IsOperator() {
		if p.PortalUserID() == "" {
			writeErr(w, http.StatusForbidden, "session has no portal user binding")
			return
		}
		switch scope {
		case "validator":
			filter.UserID = ""
			filter.ValidatorUserID = p.PortalUserID()
		default: // "", "mine", anything else → self-scope
			filter.UserID = p.PortalUserID()
			filter.ValidatorUserID = ""
		}
	} else {
		switch scope {
		case "validator":
			filter.UserID = ""
			filter.ValidatorUserID = p.PortalUserID()
		case "mine":
			if p.PortalUserID() != "" {
				filter.UserID = p.PortalUserID()
			}
			filter.ValidatorUserID = ""
		}
		// scope unset / "all" / unknown → leave filter alone (unrestricted).
	}
	grants, err := h.store.ListGrants(r.Context(), filter)
	if err != nil {
		h.logger.Error("list_grants_failed", "scope", scope, "err_class", errClass(err))
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, grants)
}

func (h *grantsHandler) get(w http.ResponseWriter, r *http.Request, id string) {
	g, err := h.store.GetGrant(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "grant not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	p := authz.NewPrincipal(SessionFromContext(r.Context()), h.entra)
	if d := authz.Authorize(authz.ActionView, g, p); !d.Allow {
		// 404 rather than 403 so a non-operator can't probe for grant
		// existence by id — only the owner confirms it exists.
		writeErr(w, http.StatusNotFound, "grant not found")
		return
	}
	writeJSON(w, http.StatusOK, g)
}

type patchGrantReq struct {
	Reason string `json:"reason,omitempty"`
}

// patch updates mutable, non-lifecycle fields on a grant. Status transitions
// are NOT accepted here — routing them through PATCH would bypass the
// approve/deny/revoke handlers' gates (dual-gate dispatch, ephemeral-DBA
// precondition, claim-window stamping, outcome emails, on-behalf audit).
// Callers that need to change status must POST to /approve, /deny, /claim,
// or DELETE the grant.
func (h *grantsHandler) patch(w http.ResponseWriter, r *http.Request, id string) {
	// Two-pass decode: first into a raw map so we can reject smuggled `status`
	// keys with a clear 400, then into the typed struct for the actual fields.
	r.Body = http.MaxBytesReader(w, r.Body, defaultBodyLimit)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeErr(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if _, ok := keys["status"]; ok {
		writeErr(w, http.StatusBadRequest, "status changes require /approve, /deny, /claim, or DELETE")
		return
	}
	var body patchGrantReq
	if err := json.Unmarshal(raw, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	g, err := h.store.GetGrant(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "grant not found")
		return
	}
	if body.Reason == "" {
		writeErr(w, http.StatusBadRequest, "nothing to update")
		return
	}
	prev := g.Status
	g.Reason = body.Reason
	g.UpdatedAt = time.Now().UTC()
	if err := h.transitionGrant(r.Context(), g, prev, w); err != nil {
		return
	}
	h.logger.Info("grant_updated", "grant_id", g.ID, "field", "reason")
	writeJSON(w, http.StatusOK, g)
}

// approveBody is the optional POST body accepted by /approve. Carries the
// on-behalf-of-T1 override declaration — used in dual_strict when a T2
// (operator) is stepping in for an absent natural T1 validator. The
// declaration is justified once at gate1; gate2 by the same actor is then
// allowed without tripping the four-eyes guard (§7.8.7).
type approveBody struct {
	OnBehalfOfT1 bool   `json:"on_behalf_of_t1,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

// onBehalfReasonMinLen is the minimum non-whitespace reason length for a
// T2-acts-as-T1 override. 20 chars forces operators to say something
// meaningful ("INC-1234 outage, Bob on PTO") instead of "x" / "asap".
const onBehalfReasonMinLen = 20

// handleApprove dispatches /approve based on caller identity AND the
// backend's approval_mode (see specs/phase-7-validation-ui.md §7.8.1):
//
//   - dual_strict:    PENDING → VALIDATOR_APPROVED → APPROVED. Two calls
//                     required, with a four-eyes guard that rejects the
//                     second call from the same actor (§7.8.7). Operators
//                     not in the natural T1 set may step in via the
//                     on_behalf_of_t1 body override (reason >=20 chars);
//                     the override is recorded on the grant row and lets
//                     the same actor clear gate2 afterward since the
//                     exception was justified at gate1.
//   - dual_or:        PENDING → APPROVED on the first call from any
//                     eligible approver (T1 ∪ T2). Single approval suffices.
//   - validator_only: PENDING → APPROVED on the first call. T2 may act as
//                     fallback for an absent T1; gate2 doesn't exist.
//
// Static-bearer callers count as T2 (privileged operator credential).
// Backend lookup failure falls back to dual_strict (the safest default).
func (h *grantsHandler) handleApprove(w http.ResponseWriter, r *http.Request, id string) {
	g, err := h.store.GetGrant(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "grant not found")
		return
	}
	// Resolve the backend once so principal + mode + permissive-eligibility
	// all share the same snapshot of T2GroupSlug + ApprovalMode. Backend
	// lookup miss falls through to safest defaults (dual_strict, empty T2
	// set) rather than failing the call — preserves approve-on-orphaned-
	// backend as a recoverable state.
	backend, _ := h.store.GetBackend(r.Context(), g.BackendID)
	mode := backend.ApprovalMode
	if !mode.Valid() {
		mode = domain.ApprovalDualStrict
	}
	p := h.principalForGrant(r, backend)
	switch g.Status {
	case domain.GrantPending:
		// Eligibility split (§7.8.1 + §7.8.7):
		//   1. Authorize pass → natural T1 (or bootstrap collapse). Proceed.
		//   2. Authorize fail + dual_or / validator_only + T2-eligible
		//      → permissive modes let {T1 ∪ T2} act at gate1, no ceremony.
		//   3. Authorize fail + dual_strict + T2-eligible
		//      → require an on_behalf_of_t1 body override with reason
		//        (>=20 chars). Recorded on the grant row so the same actor
		//        can later clear gate2.
		//   4. Anything else → 403 with the authz reason.
		onBehalf := false
		onBehalfReason := ""
		if d := authz.Authorize(authz.ActionApproveT1, g, p); !d.Allow {
			if !p.IsT2Eligible() {
				writeErr(w, http.StatusForbidden, d.Reason)
				return
			}
			if mode == domain.ApprovalDualStrict {
				body, berr := decodeOptionalApproveBody(w, r)
				if berr != nil {
					return // response already written
				}
				if !body.OnBehalfOfT1 {
					writeErr(w, http.StatusForbidden,
						"not in T1 set; to step in for an absent T1, pass {\"on_behalf_of_t1\": true, \"reason\": \"<>=20 chars\"}")
					return
				}
				onBehalfReason = strings.TrimSpace(body.Reason)
				if len(onBehalfReason) < onBehalfReasonMinLen {
					writeErr(w, http.StatusBadRequest,
						fmt.Sprintf("on_behalf_of_t1 requires a reason of at least %d characters", onBehalfReasonMinLen))
					return
				}
				onBehalf = true
			}
			// dual_or / validator_only: T2 is implicitly eligible as part
			// of {T1 ∪ T2}; no override ceremony needed.
		}
		g.T1ApprovedOnBehalf = onBehalf
		g.T1OnBehalfReason = onBehalfReason
		if onBehalf {
			h.logger.Warn("grant_t1_override",
				"grant_id", g.ID, "actor", principalFrom(r),
				"reason_len", len(onBehalfReason))
		}
		// Modes that collapse to single-call APPROVED skip the
		// VALIDATOR_APPROVED stop entirely. Audit row still records who
		// cleared which slot via the t1_approved_by + t2_approved_by pair
		// (same subject in the collapse path).
		if mode == domain.ApprovalDualOr || mode == domain.ApprovalValidatorOnly {
			h.validatorApproveCollapse(w, r, g)
			return
		}
		h.validatorApprove(w, r, g)
	case domain.GrantValidatorApproved:
		if d := authz.Authorize(authz.ActionApproveT2, g, p); !d.Allow {
			writeErr(w, http.StatusForbidden, d.Reason)
			return
		}
		// Four-eyes guard for dual_strict (§7.8.7): the second-gate
		// approver must be a different actor than the first, unless
		// gate1 was explicitly cleared on-behalf-of-T1 by this actor
		// (in which case the override already captured the justification).
		// dual_or / validator_only never reach this branch — they collapse
		// at gate1.
		if mode == domain.ApprovalDualStrict && g.T1ApprovedBy == principalFrom(r) && !g.T1ApprovedOnBehalf {
			writeErr(w, http.StatusConflict, "four-eyes: validator gate already cleared by you; need a different approver for the admin gate")
			return
		}
		h.adminApprove(w, r, g)
	default:
		writeErr(w, http.StatusConflict, fmt.Sprintf("cannot approve: status is %s", g.Status))
	}
}

// decodeOptionalApproveBody parses /approve's optional JSON body. Empty
// body / missing Content-Length → zero-value struct, no error. Malformed
// JSON → 400 written to w, returned error signals the handler to stop.
func decodeOptionalApproveBody(w http.ResponseWriter, r *http.Request) (approveBody, error) {
	var body approveBody
	if r.Body == nil || r.ContentLength == 0 {
		return body, nil
	}
	r.Body = http.MaxBytesReader(w, r.Body, defaultBodyLimit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		// EOF on an empty body is common when clients send Content-Length:0
		// without a payload — tolerate it silently.
		if errors.Is(err, io.EOF) {
			return approveBody{}, nil
		}
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return body, err
	}
	return body, nil
}

// approvalModeFor resolves the workflow mode for the grant's backend.
// On lookup miss returns dual_strict — preserving today's safest default
// rather than silently downgrading the workflow.
func (h *grantsHandler) approvalModeFor(ctx context.Context, backendID string) domain.ApprovalMode {
	b, err := h.store.GetBackend(ctx, backendID)
	if err != nil || !b.ApprovalMode.Valid() {
		return domain.ApprovalDualStrict
	}
	return b.ApprovalMode
}

// validatorApproveCollapse handles the dual_or / validator_only short-circuit:
// the first eligible approver clears straight to APPROVED, populating both
// the validator_approved_by and approved_by columns with the same subject.
// Mirrors the auto-approve path (claim window, OnApproved notify) so the
// caller experience and downstream audit shape are identical to the
// dual_strict end-state — only the number of HTTP calls differs.
func (h *grantsHandler) validatorApproveCollapse(w http.ResponseWriter, r *http.Request, g domain.Grant) {
	prev := g.Status
	now := time.Now().UTC()
	subject := principalFrom(r)
	g.Status = domain.GrantApproved
	g.T1ApprovedBy = subject
	g.T1ApprovedAt = &now
	g.T2ApprovedAt = &now
	g.T2ApprovedBy = subject
	if h.claimWindow > 0 {
		ce := now.Add(h.claimWindow)
		g.ClaimExpiresAt = &ce
	}
	// Same fail-closed check as adminApprove: ephemeral mode without a
	// DBA account on the backend → 422 before we transition.
	if g.IsEphemeral() && h.ephemeral != nil {
		if backend, berr := h.resolveBackendForGrant(r.Context(), g); berr == nil {
			if _, lerr := h.store.GetBackendAccount(r.Context(), backend.ID, domain.RoleDBA); lerr != nil {
				writeErr(w, http.StatusUnprocessableEntity, "ephemeral mode requires a DBA backend account on this backend")
				return
			}
		}
	}
	g.UpdatedAt = now
	if err := h.transitionGrant(r.Context(), g, prev, w); err != nil {
		return
	}
	h.logger.Info("grant_approved_collapsed",
		"grant_id", g.ID, "approved_by", subject,
		"claim_expires_at", g.ClaimExpiresAt)
	_ = h.notifier.OnApproved(r.Context(), notify.Event{Grant: g})
	writeJSON(w, http.StatusOK, g)
}

// validatorApprove records the validator half of the dual gate. Does not provision
// ephemeral creds — that happens at /claim after the admin gate.
func (h *grantsHandler) validatorApprove(w http.ResponseWriter, r *http.Request, g domain.Grant) {
	prev := g.Status
	now := time.Now().UTC()
	g.Status = domain.GrantValidatorApproved
	g.T1ApprovedBy = principalFrom(r)
	g.T1ApprovedAt = &now
	g.UpdatedAt = now
	if err := h.transitionGrant(r.Context(), g, prev, w); err != nil {
		return
	}
	h.logger.Info("grant_t1_approved",
		"grant_id", g.ID, "t1_approved_by", g.T1ApprovedBy,
		"on_behalf", g.T1ApprovedOnBehalf)
	// Notify the admin reachability target so the second gate can fire.
	// Look up the backend so the notifier can render the friendly name
	// instead of the opaque id; lookup failure falls through to the
	// id-in-template fallback inside the notifier.
	backend, _ := h.store.GetBackend(r.Context(), g.BackendID)
	_ = h.notifier.OnValidatorApproved(r.Context(), notify.Event{Grant: g, Backend: backend})
	writeJSON(w, http.StatusOK, g)
}

// adminApprove is the second gate. After it fires, the grant is APPROVED and
// the requester can /claim within the claim window. Ephemeral provisioning
// is deferred to /claim — see spec §5.
func (h *grantsHandler) adminApprove(w http.ResponseWriter, r *http.Request, g domain.Grant) {
	prev := g.Status
	now := time.Now().UTC()
	g.Status = domain.GrantApproved
	g.T2ApprovedAt = &now
	g.T2ApprovedBy = principalFrom(r)
	// Phase-2 claim window: when the requester must collect their creds.
	if h.claimWindow > 0 {
		ce := now.Add(h.claimWindow)
		g.ClaimExpiresAt = &ce
	}
	// Fail-closed: if the policy resolved this trio as ephemeral but the
	// backend has no DBA BackendAccount configured, we cannot honour the
	// request. Surface 422 so the admin sees a precondition failure and the
	// grant stays at VALIDATOR_APPROVED.
	if g.IsEphemeral() && h.ephemeral != nil {
		backend, berr := h.resolveBackendForGrant(r.Context(), g)
		if berr == nil {
			if _, lerr := h.store.GetBackendAccount(r.Context(), backend.ID, domain.RoleDBA); lerr != nil {
				writeErr(w, http.StatusUnprocessableEntity, "ephemeral mode requires a DBA backend account on this backend")
				return
			}
		}
	}
	g.UpdatedAt = now
	if err := h.transitionGrant(r.Context(), g, prev, w); err != nil {
		return
	}
	h.logger.Info("grant_t2_approved",
		"grant_id", g.ID, "t2_approved_by", g.T2ApprovedBy,
		"claim_expires_at", g.ClaimExpiresAt)
	// Email the requester so they know the gate is open.
	_ = h.notifier.OnApproved(r.Context(), notify.Event{Grant: g})
	writeJSON(w, http.StatusOK, g)
}

// provisionEphemeral calls the Provisioner and persists the returned creds
// onto the grant. Mutates g in place so the caller can return the final row.
// On DBA-not-configured, logs a warning and falls back to the shared-account
// path (returns nil without touching g).
func (h *grantsHandler) provisionEphemeral(ctx context.Context, g *domain.Grant) error {
	backend, err := h.resolveBackendForGrant(ctx, *g)
	if err != nil {
		return fmt.Errorf("resolve backend: %w", err)
	}
	bt := ephemeral.MapBackendType(backend.Type)
	if bt == "" {
		return fmt.Errorf("no provisioner for backend type %q", backend.Type)
	}
	req := ephemeral.ProvisionRequest{
		BackendType: bt,
		BackendID:   backend.ID,
		Host:        backend.Host,
		Port:        backend.Port,
		Database:    g.Database,
		Role:        g.Role,
		GrantID:     g.ID,
	}
	if g.ExpiresAt != nil {
		req.TTL = time.Until(*g.ExpiresAt)
	}
	acct, perr := h.ephemeral.Provision(ctx, req)
	if errors.Is(perr, ephemeral.ErrNoDBACredential) {
		// Opt-in feature: missing DBA creds is a warn, not an error. Fall
		// back to the shared BackendAccount path.
		h.logger.Warn("grant_ephemeral_skipped_no_dba",
			"grant_id", g.ID, "backend_id", backend.ID)
		return nil
	}
	if perr != nil {
		return perr
	}
	if err := h.store.SetGrantEphemeral(ctx, g.ID, acct.Username, acct.Password); err != nil {
		// Persistence failed — best-effort revoke the freshly-created backend
		// user so we don't leak it.
		_ = h.ephemeral.Revoke(ctx, bt, acct)
		return fmt.Errorf("persist ephemeral: %w", err)
	}
	g.EphemeralUsername = acct.Username
	g.EphemeralPassword = acct.Password
	return nil
}

// resolveBackendForGrant fetches the Backend row for g. Pulled out so the
// approve / revoke paths share a single lookup; returns ErrNotFound cleanly.
func (h *grantsHandler) resolveBackendForGrant(ctx context.Context, g domain.Grant) (domain.Backend, error) {
	return h.store.GetBackend(ctx, g.BackendID)
}

// maybeRevokeEphemeral fires provisioner.Revoke + clears the stored creds.
// Never blocks the status change on revoke failure — logs + bumps the metric
// counter and moves on. Terminal-state grants with leftover creds get
// reconciled by the orphan sweeper anyway.
func (h *grantsHandler) maybeRevokeEphemeral(ctx context.Context, g domain.Grant) {
	if h.ephemeral == nil || g.EphemeralUsername == "" {
		return
	}
	backend, err := h.resolveBackendForGrant(ctx, g)
	if err != nil {
		h.logger.Warn("grant_ephemeral_revoke_backend_lookup_failed",
			"grant_id", g.ID, "err", err)
		return
	}
	bt := ephemeral.MapBackendType(backend.Type)
	if bt == "" {
		return
	}
	acct := ephemeral.ProvisionedAccount{
		Username:    g.EphemeralUsername,
		Password:    g.EphemeralPassword,
		BackendID:   backend.ID,
		BackendType: bt,
		Host:        backend.Host,
		Port:        backend.Port,
		Database:    g.Database,
		GrantID:     g.ID,
	}
	if err := h.ephemeral.Revoke(ctx, bt, acct); err != nil {
		h.logger.Warn("grant_ephemeral_revoke_failed",
			"grant_id", g.ID, "backend_id", backend.ID, "err", err)
		return
	}
	if err := h.store.SetGrantEphemeral(ctx, g.ID, "", ""); err != nil {
		h.logger.Warn("grant_ephemeral_clear_failed",
			"grant_id", g.ID, "err", err)
	}
}

// transitionGrant persists a state-transition via CAS on prev status.
// On conflict writes 409 and returns the store error so the caller can bail
// without writing another response body.
func (h *grantsHandler) transitionGrant(ctx context.Context, g domain.Grant, prev domain.GrantStatus, w http.ResponseWriter) error {
	err := h.store.UpdateGrantIfStatus(ctx, g, prev)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrConflict):
		writeErr(w, http.StatusConflict, "grant status changed under us; retry")
		return err
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "grant not found")
		return err
	default:
		h.logger.Error("grant_update_failed", "grant_id", g.ID, "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return err
	}
}

func (h *grantsHandler) deny(w http.ResponseWriter, r *http.Request, id string) {
	g, err := h.store.GetGrant(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "grant not found")
		return
	}
	p := authz.NewPrincipal(SessionFromContext(r.Context()), h.entra)
	if d := authz.Authorize(authz.ActionDeny, g, p); !d.Allow {
		writeErr(w, http.StatusForbidden, d.Reason)
		return
	}
	prev := g.Status
	if !isValidTransition(prev, domain.GrantDenied) {
		writeErr(w, http.StatusConflict, fmt.Sprintf("cannot deny: status is %s", prev))
		return
	}
	now := time.Now().UTC()
	g.Status = domain.GrantDenied
	g.DeniedAt = &now
	g.DeniedBy = principalFrom(r)
	g.UpdatedAt = now
	if err := h.transitionGrant(r.Context(), g, prev, w); err != nil {
		return
	}
	h.logger.Info("grant_denied", "grant_id", g.ID, "denied_by", g.DeniedBy)
	h.maybeRevokeEphemeral(r.Context(), g)
	_ = h.notifier.OnDenied(r.Context(), notify.Event{Grant: g})
	writeJSON(w, http.StatusOK, g)
}

// claimResponse is the one-shot creds payload returned by POST /api/v1/grants/:id/claim.
// Re-claims within the ACTIVE window return the same payload idempotently;
// after ExpiresAt the endpoint returns 410.
type claimResponse struct {
	BackendUser    string    `json:"backend_user"`
	BackendPass    string    `json:"backend_pass"`
	PortalPassword string    `json:"portal_password"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// claim is the phase-2 → phase-3 transition: an APPROVED grant becomes ACTIVE,
// ExpiresAt is stamped now+credential_ttl, and (if ephemeral) the per-grant
// backend account is provisioned. Owner-only with admin override.
func (h *grantsHandler) claim(w http.ResponseWriter, r *http.Request, id string) {
	g, err := h.store.GetGrant(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "grant not found")
		return
	}
	p := authz.NewPrincipal(SessionFromContext(r.Context()), h.entra)
	if d := authz.Authorize(authz.ActionClaim, g, p); !d.Allow {
		writeErr(w, http.StatusForbidden, d.Reason)
		return
	}
	isOperator, isOwner := p.IsOperator(), p.IsOwnerOf(g)
	now := time.Now().UTC()

	// Idempotent re-claim: if already ACTIVE and within ExpiresAt, return the
	// same creds. Past ExpiresAt → 410 Gone. No audit row here — the initial
	// PENDING→ACTIVE claim already recorded who claimed it; subsequent polls
	// by the same or a different admin don't change state.
	if g.Status == domain.GrantActive {
		if g.IsPastCredentialTTL(now) {
			writeErr(w, http.StatusGone, "credentials expired")
			return
		}
		writeJSON(w, http.StatusOK, h.buildClaimResponse(g))
		return
	}

	if g.Status != domain.GrantApproved {
		writeErr(w, http.StatusConflict, fmt.Sprintf("cannot claim: status is %s", g.Status))
		return
	}
	// Phase-2 deadline: claim window must still be open.
	if g.IsPastClaimWindow(now) {
		writeErr(w, http.StatusGone, "claim window lapsed")
		return
	}

	prev := g.Status
	g.Status = domain.GrantActive
	if h.credentialTTL > 0 {
		exp := now.Add(h.credentialTTL)
		g.ExpiresAt = &exp
	}
	g.UpdatedAt = now

	// Provision ephemeral creds at /claim time when the policy mode requires
	// it. Failures roll back to APPROVED so the requester can retry.
	if h.ephemeral != nil && g.IsEphemeral() {
		if err := h.provisionEphemeral(r.Context(), &g); err != nil {
			h.logger.Warn("grant_ephemeral_provision_failed", "grant_id", g.ID, "err", err)
			writeErr(w, http.StatusInternalServerError, "ephemeral provisioning failed")
			return
		}
	}
	if err := h.transitionGrant(r.Context(), g, prev, w); err != nil {
		// Best-effort revoke if provision happened but persist failed.
		if g.EphemeralUsername != "" {
			h.maybeRevokeEphemeral(r.Context(), g)
		}
		return
	}
	// Admin-on-behalf: record the handoff ONLY after the PENDING→ACTIVE
	// transition has succeeded, so a 409/410/500 from validation or provisioning
	// doesn't leave a misleading "admin claimed this" audit row. Best-effort —
	// failing to persist the audit must not undo a successful claim.
	if isOperator && !isOwner {
		claimedBy := principalFrom(r)
		h.logger.Warn("grant_claimed_on_behalf",
			"grant_id", g.ID,
			"owner_user_id", g.UserID,
			"claimed_by", claimedBy,
		)
		entry := domain.AuditEntry{
			Timestamp: time.Now().UTC(),
			GrantID:   g.ID,
			Username:  claimedBy,
			ProxyType: "portal", // sentinel: portal lifecycle event, not a DB query
			Query:     fmt.Sprintf("admin_on_behalf_claim owner_user_id=%s", g.UserID),
			SourceIP:  ClientIPKey(r),
		}
		if err := h.store.AppendAudit(r.Context(), []domain.AuditEntry{entry}); err != nil {
			h.logger.Warn("claim_audit_append_failed", "grant_id", g.ID, "err", err)
		}
	}
	h.logger.Info("grant_claimed", "grant_id", g.ID, "expires_at", g.ExpiresAt)
	writeJSON(w, http.StatusOK, h.buildClaimResponse(g))
}

// buildClaimResponse hides the BackendUser/Pass selection — returns the
// ephemeral pair when present, otherwise the shared BackendAccount creds.
func (h *grantsHandler) buildClaimResponse(g domain.Grant) claimResponse {
	resp := claimResponse{PortalPassword: g.PortalPassword}
	if g.ExpiresAt != nil {
		resp.ExpiresAt = *g.ExpiresAt
	}
	if g.EphemeralUsername != "" {
		resp.BackendUser = g.EphemeralUsername
		resp.BackendPass = g.EphemeralPassword
		return resp
	}
	// Shared backend account. Best-effort: if lookup fails (operator never
	// seeded it) we still return the portal password so the requester can
	// see the grant succeeded — proxy /auth will surface the missing acct.
	acct, err := h.store.GetBackendAccount(context.Background(), g.BackendID, g.Role)
	if err == nil {
		resp.BackendUser = acct.Username
		resp.BackendPass = acct.Password
	}
	return resp
}

func (h *grantsHandler) revoke(w http.ResponseWriter, r *http.Request, id string) {
	g, err := h.store.GetGrant(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "grant not found")
		return
	}
	prev := g.Status
	if !isValidTransition(prev, domain.GrantRevoked) {
		writeErr(w, http.StatusConflict, fmt.Sprintf("cannot revoke: status is %s", prev))
		return
	}
	now := time.Now().UTC()
	g.Status = domain.GrantRevoked
	g.RevokedAt = &now
	g.UpdatedAt = now
	if err := h.transitionGrant(r.Context(), g, prev, w); err != nil {
		return
	}
	h.logger.Info("grant_revoked", "grant_id", g.ID)
	h.maybeRevokeEphemeral(r.Context(), g)
	w.WriteHeader(http.StatusNoContent)
}

// isValidTransition enforces the dual-gate / tri-phase lifecycle:
//
//	PENDING          -> VALIDATOR_APPROVED | DENIED | REVOKED
//	VALIDATOR_APPROVED -> APPROVED | DENIED | REVOKED
//	APPROVED         -> ACTIVE | EXPIRED | REVOKED   (ACTIVE only via /claim)
//	ACTIVE           -> EXPIRED | REVOKED
//	DENIED, EXPIRED, REVOKED are terminal.
//
// PENDING -> REVOKED is allowed so a requester can cancel before approval.
//
// Any illegal transition yields 409 Conflict at the HTTP layer.
func isValidTransition(from, to domain.GrantStatus) bool {
	switch from {
	case domain.GrantPending:
		return to == domain.GrantValidatorApproved || to == domain.GrantDenied || to == domain.GrantRevoked
	case domain.GrantValidatorApproved:
		return to == domain.GrantApproved || to == domain.GrantDenied || to == domain.GrantRevoked
	case domain.GrantApproved:
		return to == domain.GrantActive || to == domain.GrantExpired || to == domain.GrantRevoked
	case domain.GrantActive:
		return to == domain.GrantExpired || to == domain.GrantRevoked
	case domain.GrantDenied, domain.GrantExpired, domain.GrantRevoked:
		return false
	}
	return false
}

// principalFrom returns the approver/requester identity from the OIDC session
// when present, falling back to "api-bearer" when the request was authorised
// with the static bearer (no session context), and "anonymous" when neither
// guard is configured (local-dev).
func principalFrom(r *http.Request) string {
	if sess := SessionFromContext(r.Context()); sess != nil {
		if sess.Subject != "" {
			return sess.Subject
		}
	}
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return "api-bearer"
	}
	return "anonymous"
}

// requireOperator enforces operator-only access for admin endpoints. When an OIDC
// session is present it must carry IsOperator=true; static-bearer callers are
// accepted because the bearer is already a privileged operator credential.
// Writes 403 + false when denied.
func requireOperator(w http.ResponseWriter, r *http.Request) bool {
	if sess := SessionFromContext(r.Context()); sess != nil {
		if !sess.IsOperator {
			writeErr(w, http.StatusForbidden, "operator privileges required")
			return false
		}
	}
	return true
}

func firstNonEmpty(xs ...string) string {
	for _, s := range xs {
		if s != "" {
			return s
		}
	}
	return ""
}
