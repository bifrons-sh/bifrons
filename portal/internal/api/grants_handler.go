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

	// Entra integration for policy + manager resolution. All notification
	// delivery (mail + webhook) goes through `notifier` — `entra` here is
	// only consulted for policy.Authorize groups lookup + Manager resolution
	// at create time. nil ⇒ policy check and manager resolution skipped.
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

// EntraMetrics re-exports the notify-owned counter bundle under the legacy
// name so obs-sidecar callers keep working without touching internal/.
type EntraMetrics = notify.EntraMetrics

// NewEntraMetrics returns a zero-valued metrics bundle.
func NewEntraMetrics() *EntraMetrics { return notify.NewEntraMetrics() }

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

func (h *grantStatusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/grants/status/")
	if id == "" || strings.Contains(id, "/") {
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

// ServeHTTP dispatches on path + method. Kept mux-free for scaffold simplicity.
//
// Authorisation is per-endpoint:
//   - GET /api/v1/grants           → non-admins see their own; admins see all.
//   - POST /api/v1/grants          → non-admins may create for themselves
//     (policy-gated when Entra RequestPolicy is configured); admins bypass policy.
//   - GET /api/v1/grants/:id       → admin-only.
//   - PATCH/DELETE /api/v1/grants/:id → admin-only.
//   - POST /api/v1/grants/:id/approve|deny → admin-only.
//
// Static-bearer callers pass every admin check.
func (h *grantsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/grants")
	switch {
	case rest == "" || rest == "/":
		switch r.Method {
		case http.MethodGet:
			h.list(w, r)
		case http.MethodPost:
			h.create(w, r)
		default:
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	case strings.HasPrefix(rest, "/"):
		id := strings.TrimPrefix(rest, "/")
		// Sub-resource actions: /:id/approve, /:id/deny, /:id/claim.
		if idx := strings.Index(id, "/"); idx >= 0 {
			action := id[idx+1:]
			id = id[:idx]
			switch {
			case action == "approve" && r.Method == http.MethodPost:
				// Approval is dispatched inside handleApprove based on caller
				// identity (manager half vs admin half) — the requireAdmin
				// gate would reject the manager-half use case.
				h.handleApprove(w, r, id)
			case action == "deny" && r.Method == http.MethodPost:
				// Either party (manager or admin) may deny at any pre-APPROVED
				// stage — handler enforces caller identity.
				h.deny(w, r, id)
			case action == "claim" && r.Method == http.MethodPost:
				h.claim(w, r, id)
			default:
				writeErr(w, http.StatusNotFound, "not found")
			}
			return
		}
		switch r.Method {
		case http.MethodGet:
			// Admins and static-bearer see everything; non-admin OIDC users
			// may GET grants they own (ownership enforced in h.get).
			h.get(w, r, id)
		case http.MethodPatch:
			if !requireAdmin(w, r) {
				return
			}
			h.patch(w, r, id)
		case http.MethodDelete:
			if !requireAdmin(w, r) {
				return
			}
			h.revoke(w, r, id)
		default:
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	default:
		writeErr(w, http.StatusNotFound, "not found")
	}
}

type createGrantReq struct {
	UserID             string `json:"user_id"`
	BackendAddr        string `json:"backend_addr"` // host:port, resolved to backend
	Database           string `json:"database"`
	Role               string `json:"role"`
	Reason             string `json:"reason"`
	RequestedDurationS string `json:"requested_duration,omitempty"` // time.ParseDuration-compatible
	PortalPassword     string `json:"portal_password,omitempty"`    // optional; auto-generated if empty
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
	// groups, not on the target user, so without this check a non-admin
	// whose groups allow a trio could mint creds for any teammate.
	// Admins and static-bearer callers bypass via authz.Authorize.
	p := authz.NewPrincipal(SessionFromContext(r.Context()), h.entra)
	if !p.IsAdmin() {
		if d := authz.Authorize(authz.ActionCreate, domain.Grant{}, p); !d.Allow {
			writeErr(w, http.StatusForbidden, d.Reason)
			return
		}
		if req.UserID == "" {
			req.UserID = p.PortalUserID()
		} else if req.UserID != p.PortalUserID() {
			writeErr(w, http.StatusForbidden, "non-admin may only create grants for self")
			return
		}
	}
	if req.UserID == "" || req.BackendAddr == "" || req.Role == "" {
		writeErr(w, http.StatusBadRequest, "user_id, backend_addr and role are required")
		return
	}
	dur := 4 * time.Hour
	if req.RequestedDurationS != "" {
		d, err := time.ParseDuration(req.RequestedDurationS)
		if err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("invalid requested_duration: %v", err))
			return
		}
		dur = d
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
	//   - OIDC session w/ IsAdmin=true → bypass policy (existing scaffold contract).
	//   - Static-bearer callers → bypass policy (privileged operator credential).
	//   - OIDC session w/ IsAdmin=false → must satisfy the Entra RequestPolicy;
	//     reject otherwise. No OIDC session + no bearer (open mode) also
	//     bypasses — matches the existing "local dev" semantic.
	sess := SessionFromContext(r.Context())
	isNonAdminOIDC := sess != nil && !sess.IsAdmin
	// When Entra is wired, policy.Authorize is the gate. Otherwise the
	// earlier 2.3 self-scope check already validated req.UserID — fall
	// through with no additional authorisation.
	// resolvedMode tracks the policy verdict so /claim can branch ephemeral
	// vs permanent without re-running the lookup. Default permanent so the
	// non-Entra path (no policy file) keeps the legacy shared-account flow.
	resolvedMode := policy.ModePermanent
	if isNonAdminOIDC && h.entra != nil && h.requestPol != nil {
		groups, gerr := h.entra.Groups(r.Context(), sess.Subject)
		if gerr != nil {
			h.logger.Warn("entra_groups_failed", "sub", sess.Subject, "err_class", gerr.Error())
			writeErr(w, http.StatusForbidden, "could not resolve entra groups")
			return
		}
		gIDs := make([]string, 0, len(groups))
		for _, g := range groups {
			gIDs = append(gIDs, g.ID)
		}
		mode, err := h.requestPol.Authorize(gIDs, backend.Name, req.Database, req.Role)
		if err != nil {
			h.entraMetrics.IncPolicyRejected()
			h.logger.Info("entra_policy_rejected",
				"sub", sess.Subject, "instance", backend.Name, "database", req.Database, "level", req.Role,
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
	// must complete. Zero means "feature disabled" — keeps backwards compat
	// with portals that haven't set a window yet.
	if validationWindow > 0 {
		exp := now.Add(validationWindow)
		g.RequestExpiresAt = &exp
	}
	// Legacy `requested_duration` only feeds the auto-approve shortcut (the
	// demo/bootstrap path that skips dual-gate + /claim and issues ACTIVE
	// creds directly). Under the normal tri-phase flow ExpiresAt is stamped
	// at /claim from h.credentialTTL — use `credential_ttl` on the request
	// body to override per-grant.
	// Escape hatch — bootstrap/demo only. Documented as unsafe for prod.
	// Auto-approve collapses the dual-gate AND the claim phase into a single
	// step so the demo path keeps producing immediately-usable creds.
	if h.autoApprove {
		approvedAt := now
		g.Status = domain.GrantActive
		g.ManagerApprovedBy = "auto-approve"
		g.ManagerApprovedAt = &approvedAt
		g.ApprovedAt = &approvedAt
		g.ApprovedBy = "auto-approve"
		exp := now.Add(dur)
		g.ExpiresAt = &exp
	}

	// Resolve the Entra manager (approver) before we persist so ApproverHint
	// AND ManagerSubject land on the row on first write. ManagerSubject is
	// the load-bearing field for the dual-gate dispatch in /approve.
	// Lookup failures are logged; the grant proceeds regardless — a missing
	// manager must never block access (the admin gate alone can still
	// promote it).
	if h.entra != nil && sess != nil && sess.Subject != "" && g.Status == domain.GrantPending {
		mgrCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		mgr, merr := h.entra.Manager(mgrCtx, sess.Subject)
		cancel()
		if merr != nil {
			h.entraMetrics.IncManagerLookupFailed()
			h.logger.Info("entra_manager_missing", "sub", sess.Subject, "fallback", "admin")
		} else {
			g.ApproverHint = firstNonEmpty(mgr.Mail, mgr.UserPrincipalName)
			g.ManagerSubject = mgr.ID
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

// domainPart returns the substring after the last "@", or "<unknown>" when
// there's no "@" in the string. Used so error logs surface only the recipient
// domain, not the full address — the full recipient lands on the Info-level
// success log where it's intended audit.
func domainPart(addr string) string {
	if i := strings.LastIndex(addr, "@"); i >= 0 && i < len(addr)-1 {
		return addr[i+1:]
	}
	return "<unknown>"
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
	// Non-admin OIDC sessions see only their own grants — overrides any
	// user_id query param so a curious user can't probe another user's
	// history by forging it. Admins and static-bearer callers keep the
	// unrestricted view.
	p := authz.NewPrincipal(SessionFromContext(r.Context()), h.entra)
	if !p.IsAdmin() {
		if p.PortalUserID() == "" {
			writeErr(w, http.StatusForbidden, "session has no portal user binding")
			return
		}
		filter.UserID = p.PortalUserID()
	}
	grants, err := h.store.ListGrants(r.Context(), filter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
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
		// 404 rather than 403 so a non-admin can't probe for grant
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

// handleApprove dispatches /approve on caller identity:
//   - PENDING + caller is the grant's recorded manager → MANAGER_APPROVED
//   - MANAGER_APPROVED + caller is admin                → APPROVED
//   - PENDING with admin caller                         → 403 ("manager gate first")
//   - everything else                                   → 403 with the open gate named
//
// Static-bearer callers count as admin (privileged operator credential).
func (h *grantsHandler) handleApprove(w http.ResponseWriter, r *http.Request, id string) {
	g, err := h.store.GetGrant(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "grant not found")
		return
	}
	p := authz.NewPrincipal(SessionFromContext(r.Context()), h.entra)
	switch g.Status {
	case domain.GrantPending:
		if d := authz.Authorize(authz.ActionApproveManager, g, p); !d.Allow {
			writeErr(w, http.StatusForbidden, d.Reason)
			return
		}
		h.managerApprove(w, r, g)
	case domain.GrantManagerApproved:
		if d := authz.Authorize(authz.ActionApproveAdmin, g, p); !d.Allow {
			writeErr(w, http.StatusForbidden, d.Reason)
			return
		}
		h.adminApprove(w, r, g)
	default:
		writeErr(w, http.StatusConflict, fmt.Sprintf("cannot approve: status is %s", g.Status))
	}
}

// managerApprove records the manager half of the dual gate. Does not provision
// ephemeral creds — that happens at /claim after the admin gate.
func (h *grantsHandler) managerApprove(w http.ResponseWriter, r *http.Request, g domain.Grant) {
	prev := g.Status
	now := time.Now().UTC()
	g.Status = domain.GrantManagerApproved
	g.ManagerApprovedBy = principalFrom(r)
	g.ManagerApprovedAt = &now
	g.UpdatedAt = now
	if err := h.transitionGrant(r.Context(), g, prev, w); err != nil {
		return
	}
	h.logger.Info("grant_manager_approved",
		"grant_id", g.ID, "manager", g.ManagerApprovedBy)
	// Notify the admin reachability target so the second gate can fire.
	_ = h.notifier.OnManagerApproved(r.Context(), notify.Event{Grant: g})
	writeJSON(w, http.StatusOK, g)
}

// adminApprove is the second gate. After it fires, the grant is APPROVED and
// the requester can /claim within the claim window. Ephemeral provisioning
// is deferred to /claim — see spec §5.
func (h *grantsHandler) adminApprove(w http.ResponseWriter, r *http.Request, g domain.Grant) {
	prev := g.Status
	now := time.Now().UTC()
	g.Status = domain.GrantApproved
	g.ApprovedAt = &now
	g.ApprovedBy = principalFrom(r)
	// Phase-2 claim window: when the requester must collect their creds.
	if h.claimWindow > 0 {
		ce := now.Add(h.claimWindow)
		g.ClaimExpiresAt = &ce
	}
	// Fail-closed: if the policy resolved this trio as ephemeral but the
	// backend has no DBA BackendAccount configured, we cannot honour the
	// request. Surface 422 so the admin sees a precondition failure and the
	// grant stays at MANAGER_APPROVED.
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
	h.logger.Info("grant_approved",
		"grant_id", g.ID, "approved_by", g.ApprovedBy, "claim_expires_at", g.ClaimExpiresAt)
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
	isAdmin, isOwner := p.IsAdmin(), p.IsOwnerOf(g)
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
	if isAdmin && !isOwner {
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
//	PENDING          -> MANAGER_APPROVED | DENIED | REVOKED
//	MANAGER_APPROVED -> APPROVED | DENIED | REVOKED
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
		return to == domain.GrantManagerApproved || to == domain.GrantDenied || to == domain.GrantRevoked
	case domain.GrantManagerApproved:
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

// requireAdmin enforces admin-only access for approval endpoints. When an OIDC
// session is present it must carry IsAdmin=true; static-bearer callers are
// accepted because the bearer is already a privileged operator credential.
// Writes 403 + false when denied.
func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if sess := SessionFromContext(r.Context()); sess != nil {
		if !sess.IsAdmin {
			writeErr(w, http.StatusForbidden, "admin privileges required")
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
