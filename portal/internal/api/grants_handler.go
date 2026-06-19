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
	"github.com/babs/poc-proxies/portal/internal/provisioning"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// grantsHandler serves the /api/v1/grants collection + /api/v1/grants/:id item routes.
type grantsHandler struct {
	store       store.Store
	logger      *slog.Logger
	autoApprove bool

	// provisioner emits provision/revoke intents to the outbox for the
	// dedicated provisioner-worker to execute. The portal holds NO master/DBA
	// credentials and never runs DDL itself (spec §8.2). nil = ephemeral
	// provisioning disabled; handler falls back to the shared BackendAccount
	// path.
	provisioner *provisioning.Client

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
//     (policy-gated when Entra is wired)
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
	// Async-claim poll endpoint: the SPA / CLI hits this after a 202 from
	// /claim to observe the worker's result (spec §8.5.1). Same ActionClaim
	// gate as /claim.
	mux.HandleFunc("GET /api/v1/grants/{id}/claim/status", func(w http.ResponseWriter, r *http.Request) {
		h.claimStatus(w, r, r.PathValue("id"))
	})
}

// DefaultCredentialTTL is the fallback applied wherever an effective
// credential TTL resolves to <=0 (auto-approve and /claim). Security: it
// guarantees every issued credential carries a finite expiry the sweeper can
// reap — a TTL of 0 would otherwise yield a never-expiring grant.
//
// Exported as the SINGLE credential-TTL source (M1): the lifecycle reconciler
// references this constant instead of keeping its own divergent copy, so a
// reconciled claim and an inline /claim stamp the same TTL on the same grant.
const DefaultCredentialTTL = 4 * time.Hour

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

// create handles POST /api/v1/grants. Reads top-to-bottom as a sequence of
// numbered phases; each helper writes its own HTTP error and returns ok=false
// so this body stays a flat happy-path. Behaviour is unchanged from the
// previous inline form — only the structure was factored out.
func (h *grantsHandler) create(w http.ResponseWriter, r *http.Request) {
	var req createGrantReq
	if err := decodeJSONBodyStrict(w, r, defaultBodyLimit, &req); err != nil {
		return
	}

	// 1. Caller scoping: non-operators may only create for themselves and must
	// pass the create authz gate. May mutate req.UserID (derive from session).
	p := authz.NewPrincipal(SessionFromContext(r.Context()), h.entra)
	if !h.authorizeCreate(w, r, p, &req) {
		return
	}

	// 2. Required fields + closed-enum role validation.
	if req.UserID == "" || req.BackendAddr == "" || req.Role == "" {
		writeErr(w, http.StatusBadRequest, "user_id, backend_addr and role are required")
		return
	}
	// Security: req.Role flows unmodified into the provisioning DDL as the
	// backend role the ephemeral user inherits. For operator / static-bearer
	// callers the trio policy is skipped below, so without this gate a caller
	// could bind an ephemeral user to ANY pre-existing backend role (e.g. a
	// superuser) — a privilege-escalation path. Validate against the closed
	// domain.Role enum REGARDLESS of caller privilege; reject anything else.
	if !isKnownRole(req.Role) {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("invalid role %q: must be one of ro, app, dba", req.Role))
		return
	}

	// 3. Resolve the per-request validation window (override or portal default).
	validationWindow, ok := h.resolveValidationWindow(w, req)
	if !ok {
		return
	}

	// 4. Resolve referenced rows.
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

	// 5. Resolve the credential lifecycle mode via the trio policy (non-operator
	// OIDC callers only); operator / bearer / open-mode default to permanent.
	resolvedMode, ok := h.resolvePolicyMode(w, r, user, backend, req)
	if !ok {
		return
	}

	// 6. Assemble the grant row, apply the validation-window deadline, then the
	// auto-approve collapse when the escape hatch is on.
	now := time.Now().UTC()
	g := domain.Grant{
		ID:             domain.NewID("g"),
		UserID:         user.ID,
		BackendID:      backend.ID,
		Database:       req.Database,
		Role:           domain.Role(req.Role),
		Status:         domain.GrantPending,
		Reason:         req.Reason,
		PortalPassword: firstNonEmpty(req.PortalPassword, domain.NewSecret()),
		RequestedBy:    principalFrom(r),
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
	if h.autoApprove {
		h.applyAutoApprove(&g, now)
	}

	// 7. Stamp the validator hint so the dual-gate dispatch can match the
	// approver's session (skipped once auto-approve collapsed the workflow).
	if g.Status == domain.GrantPending && user.ValidatorUserID != "" {
		h.stampValidator(r, &g, user)
	}

	// 8. Persist + emit the create notification (PENDING only).
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

// authorizeCreate enforces the non-operator create gate: the caller must pass
// the create authz check and may only target their own PortalUserID (empty
// user_id is derived from the session). Operators / static-bearer bypass.
// Applies whether or not Entra policy is wired — the trio policy gates on the
// *caller's* groups, not the target user, so without this a non-operator whose
// groups allow a trio could mint creds for any teammate. Writes the HTTP error
// and returns false on rejection; may mutate req.UserID.
func (h *grantsHandler) authorizeCreate(w http.ResponseWriter, r *http.Request, p authz.Principal, req *createGrantReq) bool {
	if p.IsOperator() {
		return true
	}
	if d := authz.Authorize(authz.ActionCreate, domain.Grant{}, p); !d.Allow {
		writeErr(w, http.StatusForbidden, d.Reason)
		return false
	}
	if req.UserID == "" {
		req.UserID = p.PortalUserID()
		return true
	}
	if req.UserID != p.PortalUserID() {
		writeErr(w, http.StatusForbidden, "non-operator may only create grants for self")
		return false
	}
	return true
}

// resolveValidationWindow returns the effective validation window: the parsed
// per-request override when present, else the portal default. Writes a 400 and
// returns ok=false on an unparseable override.
func (h *grantsHandler) resolveValidationWindow(w http.ResponseWriter, req createGrantReq) (time.Duration, bool) {
	if req.ValidationWindow == "" {
		return h.validationWindow, true
	}
	d, err := time.ParseDuration(req.ValidationWindow)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("invalid validation_window: %v", err))
		return 0, false
	}
	return d, true
}

// resolvePolicyMode runs the trio request policy for non-operator OIDC callers
// and returns the credential lifecycle mode it resolves. Operator / static-
// bearer / open-mode callers bypass the policy and default to permanent (the
// shared BackendAccount path). The verdict is persisted on the grant so /claim
// doesn't re-run the lookup. Writes the HTTP error and returns ok=false on a
// group-lookup failure or a policy rejection.
func (h *grantsHandler) resolvePolicyMode(w http.ResponseWriter, r *http.Request, user domain.User, backend domain.Backend, req createGrantReq) (policy.AccessMode, bool) {
	sess := SessionFromContext(r.Context())
	isNonOperatorOIDC := sess != nil && !sess.IsOperator
	if !isNonOperatorOIDC || h.requestPol == nil {
		return policy.ModePermanent, true
	}
	// Group-based authorisation reads from the portal's local group membership
	// (populated by the sync script). No live IdP call here — the hot path is
	// a single SQL join. requestPol keys on group slugs, so we pass those.
	groups, gerr := h.store.ListUserGroups(r.Context(), user.ID)
	if gerr != nil {
		h.logger.Warn("user_groups_lookup_failed", "user", user.ID, "err_class", gerr.Error())
		writeErr(w, http.StatusForbidden, "could not resolve user groups")
		return "", false
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
		return "", false
	}
	return mode, true
}

// applyAutoApprove collapses the dual-gate AND the claim phase so the grant
// lands directly in ACTIVE — bootstrap / demo only, documented as unsafe for
// prod. ExpiresAt is stamped from credentialTTL, falling back to the nonzero
// default so the grant always carries a finite expiry the sweeper can reap.
func (h *grantsHandler) applyAutoApprove(g *domain.Grant, now time.Time) {
	approvedAt := now
	g.Status = domain.GrantActive
	g.T1ApprovedBy = "auto-approve"
	g.T1ApprovedAt = &approvedAt
	g.T2ApprovedAt = &approvedAt
	g.T2ApprovedBy = "auto-approve"
	exp := now.Add(h.effectiveCredentialTTL())
	g.ExpiresAt = &exp
}

// effectiveCredentialTTL is the single resolver for the credential TTL a grant
// receives at APPROVED→ACTIVE: the configured value, or DefaultCredentialTTL
// when non-positive. Used by both the ExpiresAt stamp (claimExpiry /
// applyAutoApprove) AND the provision-intent emit (C1), so the worker's
// backend-side `VALID UNTIL` matches the portal-side expiry the sweeper reaps.
func (h *grantsHandler) effectiveCredentialTTL() time.Duration {
	if h.credentialTTL <= 0 {
		return DefaultCredentialTTL
	}
	return h.credentialTTL
}

// stampValidator resolves the requester's validator from the local store
// (populated by the org-hier sync script — see cmd/entra-sync; no live IdP
// round-trip) and stamps the grant's T1Subject + ApproverHint so the dual-gate
// dispatch can match the approver's session. A missing validator is logged but
// never blocks: the T2 gate still promotes it (or the backend's approval_mode
// collapses the workflow — §7.8.1).
func (h *grantsHandler) stampValidator(r *http.Request, g *domain.Grant, user domain.User) {
	mgr, mErr := h.store.GetUser(r.Context(), user.ValidatorUserID)
	if mErr != nil {
		h.entraMetrics.IncValidatorLookupFailed()
		h.logger.Info("validator_lookup_failed", "user", user.ID, "validator_user_id", user.ValidatorUserID, "err_class", errClass(mErr))
		return
	}
	g.T1Subject = mgr.ExternalID
	g.ApproverHint = firstNonEmpty(mgr.Email, mgr.Username)
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
//     required, with a four-eyes guard that rejects the
//     second call from the same actor (§7.8.7). Operators
//     not in the natural T1 set may step in via the
//     on_behalf_of_t1 body override (reason >=20 chars);
//     the override is recorded on the grant row and lets
//     the same actor clear gate2 afterward since the
//     exception was justified at gate1.
//   - dual_or:        PENDING → APPROVED on the first call from any
//     eligible approver (T1 ∪ T2). Single approval suffices.
//   - validator_only: PENDING → APPROVED on the first call. T2 may act as
//     fallback for an absent T1; gate2 doesn't exist.
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
		// Resolve gate1 eligibility (natural T1, permissive {T1∪T2}, or a
		// dual_strict on-behalf override). Helper writes its own error on
		// rejection.
		onBehalf, onBehalfReason, ok := h.resolveGate1OnBehalf(w, r, g, p, mode)
		if !ok {
			return
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
		actor := principalFrom(r)
		if mode == domain.ApprovalDualStrict && g.T1ApprovedBy == actor && !g.T1ApprovedOnBehalf {
			writeErr(w, http.StatusConflict, "four-eyes: validator gate already cleared by you; need a different approver for the admin gate")
			return
		}
		// Security: the static bearer is a shared automation credential — two
		// bearer-authenticated calls are indistinguishable (both resolve to
		// bearerPrincipal). It therefore cannot supply an independent second
		// approval, even under an on_behalf_of_t1 override, so it must never
		// satisfy BOTH halves of a dual gate. Block gate2 when both gates would
		// be cleared by the bearer. OIDC sessions are exempt: distinct subjects
		// are genuinely distinguishable and the guard above already covers them.
		if mode == domain.ApprovalDualStrict && actor == bearerPrincipal && g.T1ApprovedBy == bearerPrincipal {
			writeErr(w, http.StatusConflict, "four-eyes: the static bearer cannot satisfy both gates; the admin gate needs an independent approver")
			return
		}
		h.adminApprove(w, r, g)
	default:
		writeErr(w, http.StatusConflict, fmt.Sprintf("cannot approve: status is %s", g.Status))
	}
}

// resolveGate1OnBehalf decides whether a PENDING /approve caller may clear
// gate1, and whether they do so on-behalf-of-T1. Eligibility split
// (§7.8.1 + §7.8.7):
//  1. Authorize pass → natural T1 (or bootstrap collapse). Proceed, no override.
//  2. Authorize fail + dual_or / validator_only + T2-eligible
//     → permissive modes let {T1 ∪ T2} act at gate1, no ceremony.
//  3. Authorize fail + dual_strict + T2-eligible
//     → require an on_behalf_of_t1 body override with reason (>=20 chars).
//     Recorded on the grant row so the same actor can later clear gate2.
//  4. Anything else → 403 with the authz reason.
//
// Writes the HTTP error and returns ok=false on rejection.
func (h *grantsHandler) resolveGate1OnBehalf(w http.ResponseWriter, r *http.Request, g domain.Grant, p authz.Principal, mode domain.ApprovalMode) (onBehalf bool, reason string, ok bool) {
	if d := authz.Authorize(authz.ActionApproveT1, g, p); d.Allow {
		return false, "", true
	} else if !p.IsT2Eligible() {
		writeErr(w, http.StatusForbidden, d.Reason)
		return false, "", false
	}
	// dual_or / validator_only: T2 is implicitly eligible as part of
	// {T1 ∪ T2}; no override ceremony needed.
	if mode != domain.ApprovalDualStrict {
		return false, "", true
	}
	// dual_strict: a non-T1 T2 must justify stepping in for an absent T1.
	body, berr := decodeOptionalApproveBody(w, r)
	if berr != nil {
		return false, "", false // response already written
	}
	if !body.OnBehalfOfT1 {
		writeErr(w, http.StatusForbidden,
			"not in T1 set; to step in for an absent T1, pass {\"on_behalf_of_t1\": true, \"reason\": \"<>=20 chars\"}")
		return false, "", false
	}
	reason = strings.TrimSpace(body.Reason)
	if len(reason) < onBehalfReasonMinLen {
		writeErr(w, http.StatusBadRequest,
			fmt.Sprintf("on_behalf_of_t1 requires a reason of at least %d characters", onBehalfReasonMinLen))
		return false, "", false
	}
	return true, reason, true
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
	// Same fail-closed check as adminApprove: ephemeral mode on a backend that
	// has no provisioner → 422 before we transition. Fail closed on backend-
	// lookup error too: silently skipping the precondition would approve a grant
	// that is guaranteed to fail at /claim — surface it now instead.
	if g.IsEphemeral() && h.provisioner != nil {
		if !h.ephemeralProvisionablePreconditionMet(w, r, g) {
			return
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
	// backend isn't provisionable (unknown/unsupported type), we cannot honour
	// the request. Surface 422 so the admin sees a precondition failure and the
	// grant stays at VALIDATOR_APPROVED. The portal can no longer see DBA creds
	// (spec §8.2), so a missing master credential surfaces later as a terminal
	// error_class from the worker at /claim — not here.
	if g.IsEphemeral() && h.provisioner != nil {
		if !h.ephemeralProvisionablePreconditionMet(w, r, g) {
			return
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

// ephemeralProvisionablePreconditionMet reports whether g's backend is a
// provisionable type — the only non-secret precondition the portal can still
// check at approve time. Since the portal no longer holds DBA creds (spec
// §8.2), a missing master credential is no longer knowable here; it surfaces
// later as a terminal error_class from the worker at /claim.
//
// Returns false AND writes a 422 when the precondition can't be confirmed —
// including when the backend lookup itself fails. Fail-closed: a lookup error
// must NOT be treated as "precondition satisfied", which would approve a grant
// that is guaranteed to fail at claim time (M9).
func (h *grantsHandler) ephemeralProvisionablePreconditionMet(w http.ResponseWriter, r *http.Request, g domain.Grant) bool {
	backend, berr := h.resolveBackendForGrant(r.Context(), g)
	if berr != nil {
		h.logger.Warn("ephemeral_precondition_backend_lookup_failed",
			"grant_id", g.ID, "err_class", errClass(berr))
		writeErr(w, http.StatusUnprocessableEntity, "ephemeral mode requires a resolvable backend")
		return false
	}
	if ephemeral.MapBackendType(backend.Type) == "" {
		writeErr(w, http.StatusUnprocessableEntity,
			fmt.Sprintf("ephemeral mode is not supported for backend type %q", backend.Type))
		return false
	}
	return true
}

// resolveBackendForGrant fetches the Backend row for g. Pulled out so the
// approve / revoke paths share a single lookup; returns ErrNotFound cleanly.
func (h *grantsHandler) resolveBackendForGrant(ctx context.Context, g domain.Grant) (domain.Backend, error) {
	return h.store.GetBackend(ctx, g.BackendID)
}

// maybeRevokeEphemeral emits a revoke intent to the outbox for the worker to
// drop the per-grant backend user. Async + best-effort: the status transition
// is never blocked on the worker, and a failed emit is logged — the orphan
// sweeper re-emits a revoke intent as the durable safety net. The grant's
// ephemeral creds are NOT cleared here: the worker drops the user and the
// orphan sweeper clears the columns once the user is actually gone, so a lost
// emit doesn't strand a still-live backend account with no record of it.
//
// We emit for ANY ephemeral grant, even when EphemeralUsername is still empty
// (HIGH-1): a grant revoked/denied while its provision intent is pending/in_flight
// has no creds recorded yet, but the worker may still run the frozen provision
// intent and create ap_<hmac> on the backend. The deterministic revoke intent
// carries TargetUsername="" and the worker derives the sibling provision intent's
// username to drop — idempotent if the user was never actually created. Without
// this, the sweeper's ListEphemeralOrphans (non-empty username only) never sees
// the user and Mongo has no backend TTL → permanent orphan.
func (h *grantsHandler) maybeRevokeEphemeral(ctx context.Context, g domain.Grant) {
	if h.provisioner == nil || !g.IsEphemeral() {
		return
	}
	if _, err := h.provisioner.EmitRevoke(ctx, g); err != nil {
		h.logger.Warn("grant_ephemeral_revoke_emit_failed",
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

// claimPendingResponse is the 202 body returned when an ephemeral provision
// intent is still pending/in_flight after the short-circuit wait. The caller
// polls GET …/claim/status (see the Location header) until it flips terminal.
type claimPendingResponse struct {
	IntentID string `json:"intent_id"`
	State    string `json:"state"`
}

// claimFailedResponse is the 422 body returned when the worker reported a
// terminal failure on the provision intent. error_class is the closed-enum
// classification (spec §8.4.2); error_detail is a sanitised one-liner.
type claimFailedResponse struct {
	State       string `json:"state"`
	ErrorClass  string `json:"error_class,omitempty"`
	ErrorDetail string `json:"error_detail,omitempty"`
}

// claimProgressResponse is the 200 body returned by the status endpoint while
// the worker is still working the intent.
type claimProgressResponse struct {
	State     string `json:"state"`
	ElapsedMs int64  `json:"elapsed_ms,omitempty"`
}

// claimShortCircuitWait bounds how long /claim parks on the worker's result
// before degrading to the 202 + poll handshake (spec §8.5.1). Short enough to
// keep the request snappy, long enough that a healthy worker fills the happy
// path inline.
const claimShortCircuitWait = 2 * time.Second

// claim is the phase-2 → phase-3 transition. For ephemeral grants the portal
// no longer provisions inline (spec §8.2): it emits a provision intent to the
// outbox, waits briefly for the worker's result, and either propagates it
// (200 + creds) or returns 202 so the caller polls …/claim/status. Owner-only
// with admin override.
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
	// claim already recorded who claimed it; subsequent polls don't change state.
	if g.Status == domain.GrantActive {
		if g.IsPastCredentialTTL(now) {
			writeErr(w, http.StatusGone, "credentials expired")
			return
		}
		writeJSON(w, http.StatusOK, h.buildClaimResponse(r.Context(), g))
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

	// Ephemeral grants take the async outbox path: emit an intent, wait briefly
	// for a result. Non-ephemeral grants flip straight to ACTIVE on the shared-
	// account path below.
	if h.provisioner != nil && g.IsEphemeral() {
		h.claimEphemeral(w, r, g, isOperator, isOwner)
		return
	}

	prev := g.Status
	g.Status = domain.GrantActive
	g.ExpiresAt = h.claimExpiry(now)
	g.UpdatedAt = now
	if err := h.transitionGrant(r.Context(), g, prev, w); err != nil {
		return
	}
	// Admin-on-behalf: record the handoff ONLY after the transition succeeds,
	// so a 409/410 from validation doesn't leave a misleading audit row.
	if isOperator && !isOwner {
		h.auditOnBehalfClaim(r, g)
	}
	h.logger.Info("grant_claimed", "grant_id", g.ID, "expires_at", g.ExpiresAt)
	writeJSON(w, http.StatusOK, h.buildClaimResponse(r.Context(), g))
}

// isTransientProvisionFailure decides retry-vs-give-up for a failed provision
// intent by its closed-enum error_class (spec §8.4.2). The worker's classes are
// prefixed transient_ (recoverable: network blip, transient_exhausted) vs
// terminal_ (a real misconfig: permission, syntax, unreachable, intent_invalid).
// We key on the "transient_" prefix rather than importing the worker's enum so
// the api package stays decoupled from the worker binary. An empty class (or any
// unrecognised value) is treated as terminal — fail closed, don't loop forever.
func isTransientProvisionFailure(errorClass string) bool {
	return strings.HasPrefix(errorClass, "transient_")
}

// maxClaimAutoRetries caps how many times /claim or /claim/status will
// auto-re-arm a transient-failed provision intent before surfacing it as
// terminal (M3). Without a ceiling a hard failure that the worker keeps
// classifying transient oscillates failed↔pending forever, so the poller (or
// reconciler) never terminates. 3 absorbs genuine blips (network, transient
// exhaustion) while bounding a stuck intent. We key off the failed intent's
// worker-reported retry_count: once the worker has burned this many attempts on
// the current armed cycle we stop re-arming.
//
// NOTE: store.ResetIntentForRetry ZEROES retry_count on each re-arm, so this
// only bounds the worker's per-cycle attempts, not the cumulative poll-driven
// reset loop. Durable cross-reset enforcement is a store concern (it would need
// a separate, non-reset counter) — flagged, not fixed here.
const maxClaimAutoRetries = 3

// shouldRetryTransient reports whether a failed provision intent should be
// auto-re-armed: its class is transient AND the worker hasn't already exceeded
// the auto-retry ceiling (M3). A terminal class, or a transient one past the
// cap, returns false so the caller surfaces 422 instead of looping.
func shouldRetryTransient(in domain.Intent) bool {
	return isTransientProvisionFailure(in.ErrorClass) && in.RetryCount < maxClaimAutoRetries
}

// claimEphemeral runs the async provision handshake for an APPROVED ephemeral
// grant (spec §8.5.1): emit the provision intent, short-circuit-wait for the
// worker, then 200 (done) / 422 (failed) / 202 (still working). The grant
// stays APPROVED until a done intent is propagated, so a 202 (or a crash)
// strands nothing — the caller re-polls or the lifecycle reconciler flips it.
func (h *grantsHandler) claimEphemeral(w http.ResponseWriter, r *http.Request, g domain.Grant, isOperator, isOwner bool) {
	// Prefer an already-terminal intent over emitting a new one. EmitProvision
	// is idempotent (deterministic id) but reading first avoids a redundant
	// INSERT/NOTIFY on a re-claim and lets a previously-done intent flip the
	// grant immediately.
	if in, err := h.store.GetLatestIntentForGrant(r.Context(), g.ID, domain.IntentProvision); err == nil {
		switch in.Status {
		case domain.IntentDone:
			h.finishEphemeralClaim(w, r, g, in, isOperator, isOwner)
			return
		case domain.IntentFailed:
			// A TRANSIENT failure (network blip / transient_exhausted) self-heals
			// on re-claim (HIGH-2): reset the row to pending + re-NOTIFY, then fall
			// through to wait on the re-armed intent. Without this the deterministic
			// id + ON CONFLICT DO NOTHING brick the grant at 422 forever. A TERMINAL
			// class — or a transient one past the auto-retry cap (M3) — is surfaced
			// as 422 so we don't loop.
			if shouldRetryTransient(in) {
				if rerr := h.provisioner.RetryProvision(r.Context(), g, h.effectiveCredentialTTL()); rerr != nil {
					h.logger.Warn("grant_provision_retry_failed", "grant_id", g.ID, "err", rerr)
				}
				// fall through to emit/wait on the now-pending intent
			} else {
				writeJSON(w, http.StatusUnprocessableEntity, claimFailedResponse{
					State: string(domain.IntentFailed), ErrorClass: in.ErrorClass, ErrorDetail: in.ErrorDetail,
				})
				return
			}
		}
	}

	// Thread the effective credential TTL (C1) so the worker provisions a
	// backend user with a real `VALID UNTIL` matching the grant's ExpiresAt,
	// not an infinite-lived account.
	intent, err := h.provisioner.EmitProvision(r.Context(), g, h.effectiveCredentialTTL())
	if err != nil {
		h.logger.Warn("grant_provision_emit_failed", "grant_id", g.ID, "err", err)
		writeErr(w, http.StatusInternalServerError, "could not emit provisioning intent")
		return
	}
	res, err := h.provisioner.WaitForResult(r.Context(), intent.ID, claimShortCircuitWait)
	if err != nil {
		// Only ctx cancellation surfaces an error here; a wait timeout returns a
		// non-terminal intent and nil. Treat as "still working" → 202.
		h.logger.Warn("grant_provision_wait_failed", "grant_id", g.ID, "err", err)
		res = intent
	}
	switch res.Status {
	case domain.IntentDone:
		h.finishEphemeralClaim(w, r, g, res, isOperator, isOwner)
	case domain.IntentFailed:
		writeJSON(w, http.StatusUnprocessableEntity, claimFailedResponse{
			State: string(domain.IntentFailed), ErrorClass: res.ErrorClass, ErrorDetail: res.ErrorDetail,
		})
	default:
		// Still pending/in_flight after the short-circuit window: hand the
		// caller a poll target. The grant stays APPROVED.
		w.Header().Set("Location", "/api/v1/grants/"+g.ID+"/claim/status")
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusAccepted, claimPendingResponse{
			IntentID: intent.ID, State: string(res.Status),
		})
	}
}

// finishEphemeralClaim propagates a done provision intent's credential onto the
// grant and flips APPROVED→ACTIVE, then returns 200 + creds. Idempotent: a grant
// already ACTIVE (a concurrent claim/reconciler won the race) just returns the
// current creds. The intent's result fields are already decrypted by the
// portal's encrypting store wrapper (shared SECRETBOX_KEY).
func (h *grantsHandler) finishEphemeralClaim(w http.ResponseWriter, r *http.Request, g domain.Grant, in domain.Intent, isOperator, isOwner bool) {
	if g.Status == domain.GrantActive {
		writeJSON(w, http.StatusOK, h.buildClaimResponse(r.Context(), g))
		return
	}
	if err := h.propagateProvisionResult(r.Context(), &g, in); err != nil {
		// Benign race (MEDIUM-1): the snapshot g was APPROVED at claim() entry,
		// but the reconciler or a concurrent claim flipped it ACTIVE before our
		// CAS ran, so UpdateGrantIfStatus(APPROVED) returns ErrConflict. The grant
		// already carries the same deterministic creds — re-read and return them,
		// mirroring how the reconciler treats this conflict as a no-op. Only a
		// genuinely unexpected store error is a 500.
		if errors.Is(err, store.ErrConflict) {
			if cur, gerr := h.store.GetGrant(r.Context(), g.ID); gerr == nil && cur.Status == domain.GrantActive {
				writeJSON(w, http.StatusOK, h.buildClaimResponse(r.Context(), cur))
				return
			}
		}
		h.logger.Error("grant_provision_propagate_failed", "grant_id", g.ID, "err", err)
		writeErr(w, http.StatusInternalServerError, "could not finalise claim")
		return
	}
	if isOperator && !isOwner {
		h.auditOnBehalfClaim(r, g)
	}
	h.logger.Info("grant_claimed", "grant_id", g.ID, "expires_at", g.ExpiresAt)
	writeJSON(w, http.StatusOK, h.buildClaimResponse(r.Context(), g))
}

// propagateProvisionResult persists the worker's credential onto the grant and
// CAS-transitions APPROVED→ACTIVE, stamping the credential TTL. Mutates g in
// place. Used by the /claim and /claim/status handlers. The lifecycle
// reconciler has its own structurally-different propagate (a free function, not
// a *grantsHandler method) for the same APPROVED→ACTIVE flip; the two are NOT a
// shared helper (extracting one would couple lifecycle↔api), but they now share
// the SAME credential-TTL source — DefaultCredentialTTL — so a grant stamped by
// either path gets an identical TTL (M1).
func (h *grantsHandler) propagateProvisionResult(ctx context.Context, g *domain.Grant, in domain.Intent) error {
	now := time.Now().UTC()
	if err := h.store.SetGrantEphemeral(ctx, g.ID, in.ResultUsername, in.ResultPassword); err != nil {
		return fmt.Errorf("persist ephemeral creds: %w", err)
	}
	prev := g.Status
	g.EphemeralUsername = in.ResultUsername
	g.EphemeralPassword = in.ResultPassword
	g.Status = domain.GrantActive
	g.ExpiresAt = h.claimExpiry(now)
	g.UpdatedAt = now
	if err := h.store.UpdateGrantIfStatus(ctx, *g, prev); err != nil {
		return fmt.Errorf("transition to active: %w", err)
	}
	return nil
}

// claimExpiry computes the phase-3 credential deadline. Security: a credential
// TTL of 0 would mint a never-expiring grant the sweeper never reaps, so we
// fall back to the same nonzero default the auto-approve path uses.
func (h *grantsHandler) claimExpiry(now time.Time) *time.Time {
	exp := now.Add(h.effectiveCredentialTTL())
	return &exp
}

// claimStatus serves GET /api/v1/grants/{id}/claim/status — the poll target a
// caller follows after a 202 from /claim. Reads the latest provision intent and
// either propagates a done result (200 + creds), surfaces a failure (422), or
// reports progress (200). Same ActionClaim gate as /claim.
func (h *grantsHandler) claimStatus(w http.ResponseWriter, r *http.Request, id string) {
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
	// Already ACTIVE: the result was propagated by an earlier /claim or by the
	// reconciler — return creds idempotently (unless the TTL already lapsed).
	if g.Status == domain.GrantActive {
		if g.IsPastCredentialTTL(time.Now().UTC()) {
			writeErr(w, http.StatusGone, "credentials expired")
			return
		}
		writeJSON(w, http.StatusOK, h.buildClaimResponse(r.Context(), g))
		return
	}
	in, err := h.store.GetLatestIntentForGrant(r.Context(), g.ID, domain.IntentProvision)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// No intent emitted yet for this grant. If it's still claimable,
			// 409 nudges the caller to POST /claim first; otherwise 404.
			if g.Status == domain.GrantApproved {
				writeErr(w, http.StatusConflict, "no claim in progress; POST /claim first")
				return
			}
			writeErr(w, http.StatusNotFound, "no provisioning intent for grant")
			return
		}
		h.logger.Error("claim_status_intent_lookup_failed", "grant_id", g.ID, "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	switch in.Status {
	case domain.IntentDone:
		h.finishEphemeralClaim(w, r, g, in, p.IsOperator(), p.IsOwnerOf(g))
	case domain.IntentFailed:
		// Transient failures self-heal (HIGH-2): re-arm the intent and report
		// "in progress" so the poller keeps polling. A terminal class — or a
		// transient one past the auto-retry cap (M3) — stays 422 so a hard
		// failure can't oscillate failed↔pending forever and starve the poller.
		if shouldRetryTransient(in) {
			if rerr := h.provisioner.RetryProvision(r.Context(), g, h.effectiveCredentialTTL()); rerr != nil {
				h.logger.Warn("grant_provision_retry_failed", "grant_id", g.ID, "err", rerr)
			}
			writeJSON(w, http.StatusOK, claimProgressResponse{State: string(domain.IntentPending)})
			return
		}
		writeJSON(w, http.StatusUnprocessableEntity, claimFailedResponse{
			State: string(domain.IntentFailed), ErrorClass: in.ErrorClass, ErrorDetail: in.ErrorDetail,
		})
	default:
		resp := claimProgressResponse{State: string(in.Status)}
		if !in.CreatedAt.IsZero() {
			resp.ElapsedMs = time.Since(in.CreatedAt).Milliseconds()
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// auditOnBehalfClaim records an operator claiming a grant on behalf of its
// owner. Best-effort — failing to persist the audit must not undo a successful
// claim, so a store error is logged and swallowed.
func (h *grantsHandler) auditOnBehalfClaim(r *http.Request, g domain.Grant) {
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

// buildClaimResponse hides the BackendUser/Pass selection — returns the
// ephemeral pair when present, otherwise the shared BackendAccount creds.
// Takes the request context so the shared-account lookup is cancellable along
// with the request (this is a read path, not the backend-mutating provision).
func (h *grantsHandler) buildClaimResponse(ctx context.Context, g domain.Grant) claimResponse {
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
	acct, err := h.store.GetBackendAccount(ctx, g.BackendID, g.Role)
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
		return bearerPrincipal
	}
	return "anonymous"
}

// bearerPrincipal is the identity recorded for any caller authorised via the
// shared static bearer token (no OIDC session). Security: because every
// automation client presenting the bearer collapses to this single constant,
// two bearer-authenticated /approve calls are indistinguishable. The dual-gate
// four-eyes guard therefore treats this identity as incapable of providing an
// independent second approval — see handleApprove's gate2 check.
const bearerPrincipal = "api-bearer"

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

// isKnownRole validates a raw role string against the closed domain.Role enum.
// domain exposes no validity helper, so we check the known set inline here in
// the api package (the domain package must not grow one for this).
func isKnownRole(role string) bool {
	switch domain.Role(role) {
	case domain.RoleRO, domain.RoleApp, domain.RoleDBA:
		return true
	default:
		return false
	}
}

func firstNonEmpty(xs ...string) string {
	for _, s := range xs {
		if s != "" {
			return s
		}
	}
	return ""
}
