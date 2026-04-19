package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/entra"
	"github.com/babs/poc-proxies/portal/internal/ephemeral"
	"github.com/babs/poc-proxies/portal/internal/policy"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// grantsHandler serves the /api/v1/grants collection + /api/v1/grants/:id item routes.
type grantsHandler struct {
	store       store.Store
	logger      *slog.Logger
	autoApprove bool
	// webhookURL, when non-empty, receives a POST on grant_requested.
	webhookURL string
	// webhookSecret, when non-empty, is used to HMAC-SHA256-sign the webhook
	// body; receivers verify the hex digest in the X-Portal-Signature header.
	webhookSecret string
	// webhookClient is injected so tests can replace the HTTP client.
	webhookClient *http.Client
	// webhookWG tracks background webhook goroutines so tests (and graceful
	// shutdown) can wait for them without sleeping. Zero-value is fine — a
	// WaitGroup is safe to use uninitialised.
	webhookWG sync.WaitGroup

	// ephemeral is the per-grant backend provisioner. nil = feature disabled;
	// handler falls back to shared BackendAccount path.
	ephemeral *ephemeral.Manager

	// Entra integration — all optional. When entra is nil the policy check
	// and email notification paths are skipped entirely.
	entra        entra.Client
	requestPol   *policy.RequestPolicy
	entraSender  string
	publicURL    string
	entraMetrics *EntraMetrics
	// entraWG tracks background email goroutines for graceful shutdown / tests.
	entraWG sync.WaitGroup
}

// EntraMetrics is a lock-free counter bundle exposed through obs.EntraStatsFn.
type EntraMetrics struct {
	emailSent           atomic.Uint64
	emailFailed         atomic.Uint64
	policyRejected      atomic.Uint64
	managerLookupFailed atomic.Uint64
}

// NewEntraMetrics returns a zero-valued metrics bundle.
func NewEntraMetrics() *EntraMetrics { return &EntraMetrics{} }

// Snapshot returns the current counter values atomically.
func (m *EntraMetrics) Snapshot() (sent, failed, rejected, mgrFail uint64) {
	if m == nil {
		return 0, 0, 0, 0
	}
	return m.emailSent.Load(), m.emailFailed.Load(), m.policyRejected.Load(), m.managerLookupFailed.Load()
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
		// Sub-resource actions: /:id/approve, /:id/deny.
		if idx := strings.Index(id, "/"); idx >= 0 {
			action := id[idx+1:]
			id = id[:idx]
			switch {
			case action == "approve" && r.Method == http.MethodPost:
				if !requireAdmin(w, r) {
					return
				}
				h.approve(w, r, id)
			case action == "deny" && r.Method == http.MethodPost:
				if !requireAdmin(w, r) {
					return
				}
				h.deny(w, r, id)
			default:
				writeErr(w, http.StatusNotFound, "not found")
			}
			return
		}
		switch r.Method {
		case http.MethodGet:
			if !requireAdmin(w, r) {
				return
			}
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
}

func (h *grantsHandler) create(w http.ResponseWriter, r *http.Request) {
	var req createGrantReq
	if err := decodeJSONBody(w, r, defaultBodyLimit, &req); err != nil {
		return
	}
	// Non-admin OIDC sessions can only create grants for themselves.
	// Empty user_id → derive from session; explicit user_id must match.
	// Admins (and static-bearer callers, which carry no session) are
	// free to target any user_id.
	if sess := SessionFromContext(r.Context()); sess != nil && !sess.IsAdmin {
		// When Entra policy is wired, policy.Authorize(groups, backend, role)
		// gates the request — we don't additionally require PortalUserID to be
		// bound. When policy is *not* wired, fall back to the 2.3 self-scope
		// check so non-admins can only create grants for themselves.
		if h.entra == nil || h.requestPol == nil {
			if sess.PortalUserID == "" {
				writeErr(w, http.StatusForbidden, "session has no portal user binding")
				return
			}
			if req.UserID == "" {
				req.UserID = sess.PortalUserID
			} else if req.UserID != sess.PortalUserID {
				writeErr(w, http.StatusForbidden, "non-admin may only create grants for self")
				return
			}
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
		if err := h.requestPol.Authorize(gIDs, backend.ID, req.Role); err != nil {
			if h.entraMetrics != nil {
				h.entraMetrics.policyRejected.Add(1)
			}
			h.logger.Info("entra_policy_rejected",
				"sub", sess.Subject, "backend_id", backend.ID, "role", req.Role,
			)
			writeErr(w, http.StatusForbidden, policy.ErrRequestNotAllowed.Error())
			return
		}
	}

	now := time.Now().UTC()
	expires := now.Add(dur)
	requester := principalFrom(r)

	g := domain.Grant{
		ID:             domain.NewID("g"),
		UserID:         user.ID,
		BackendID:      backend.ID,
		Database:       req.Database,
		Role:           domain.Role(req.Role),
		Status:         domain.GrantPending,
		Reason:         req.Reason,
		PortalPassword: firstNonEmpty(req.PortalPassword, "scaffold-"+domain.NewID("pw")),
		RequestedBy:    requester,
		RequestedAt:    now,
		ExpiresAt:      &expires,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	// Escape hatch — bootstrap/demo only. Documented as unsafe for prod.
	if h.autoApprove {
		g.Status = domain.GrantApproved
		approvedAt := now
		g.ApprovedAt = &approvedAt
		g.ApprovedBy = "auto-approve"
	}

	// Resolve the Entra manager (approver) before we persist so ApproverHint
	// lands on the row on first write. Lookup failures are logged; the grant
	// proceeds regardless — a missing manager must never block access.
	if h.entra != nil && sess != nil && sess.Subject != "" && g.Status == domain.GrantPending {
		mgrCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		mgr, merr := h.entra.Manager(mgrCtx, sess.Subject)
		cancel()
		if merr != nil {
			if h.entraMetrics != nil {
				h.entraMetrics.managerLookupFailed.Add(1)
			}
			h.logger.Info("entra_manager_missing", "sub", sess.Subject, "fallback", "admin")
		} else {
			g.ApproverHint = firstNonEmpty(mgr.Mail, mgr.UserPrincipalName)
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
	// Fire webhook only for genuinely pending grants — skip when auto-approved
	// because the four-eyes notification would be meaningless.
	if g.Status == domain.GrantPending && h.webhookURL != "" {
		h.fireApprovalWebhook(g, user.Username, backend.Address())
	}
	// Fire the Entra approval email on the same non-blocking contract as the
	// webhook — delivery failures must never gate grant creation.
	if g.Status == domain.GrantPending && h.entra != nil && g.ApproverHint != "" && h.entraSender != "" {
		h.fireEntraEmail(g, user, backend)
	}
	writeJSON(w, http.StatusCreated, g)
}

// fireEntraEmail sends the approval notification via Graph /sendMail off the
// hot path. Bounded to a 10s per-attempt deadline; errors are logged (class
// only, never body) and counted against entra_email_failed_total.
func (h *grantsHandler) fireEntraEmail(g domain.Grant, user domain.User, backend domain.Backend) {
	to := g.ApproverHint
	subject := fmt.Sprintf("Access request: %s on %s", g.Role, backend.Name)
	link := ""
	if h.publicURL != "" {
		link = strings.TrimRight(h.publicURL, "/") + "/ui/grants/" + g.ID
	}
	text := fmt.Sprintf(
		"User %s requested %s access on %s (%s).\nReason: %s\nGrant ID: %s\n%s\n",
		displayOr(user), g.Role, backend.Name, backend.Address(), g.Reason, g.ID, link,
	)
	// HTML body kept intentionally plain — no external assets, no remote
	// images (tracking-pixel / CSP concerns). Approvers click the link and
	// authenticate in the portal UI themselves.
	var html string
	if link != "" {
		html = fmt.Sprintf(
			`<p>User <b>%s</b> requested <b>%s</b> access on <b>%s</b> (%s).</p>`+
				`<p>Reason: %s</p><p>Grant ID: %s</p>`+
				`<p><a href="%s">Review in portal</a></p>`,
			escapeHTML(displayOr(user)), escapeHTML(string(g.Role)),
			escapeHTML(backend.Name), escapeHTML(backend.Address()),
			escapeHTML(g.Reason), escapeHTML(g.ID), escapeHTML(link),
		)
	}
	msg := entra.MailMessage{
		To:       []string{to},
		Subject:  subject,
		TextBody: text,
		HTMLBody: html,
	}
	h.entraWG.Add(1)
	go func() {
		defer h.entraWG.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := h.entra.SendMail(ctx, h.entraSender, msg); err != nil {
			if h.entraMetrics != nil {
				h.entraMetrics.emailFailed.Add(1)
			}
			h.logger.Warn("entra_email_failed", "grant_id", g.ID, "to_domain", domainPart(to))
			return
		}
		if h.entraMetrics != nil {
			h.entraMetrics.emailSent.Add(1)
		}
		h.logger.Info("entra_email_sent", "grant_id", g.ID, "to", to)
	}()
}

// displayOr returns the user's DisplayName if set, falling back to username.
func displayOr(u domain.User) string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Username
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

// escapeHTML is a minimal HTML-entity encoder sufficient for interpolating
// user-controlled strings (display name, backend name, reason) into the
// HTML email body. Not using html/template because the message shape is
// small and fixed; a dedicated function keeps the email path allocation-lean.
func escapeHTML(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return r.Replace(s)
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
	if sess := SessionFromContext(r.Context()); sess != nil && !sess.IsAdmin {
		if sess.PortalUserID == "" {
			writeErr(w, http.StatusForbidden, "session has no portal user binding")
			return
		}
		filter.UserID = sess.PortalUserID
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
	writeJSON(w, http.StatusOK, g)
}

type patchGrantReq struct {
	Status string `json:"status,omitempty"` // APPROVED | DENIED | REVOKED
	Reason string `json:"reason,omitempty"`
}

// patch is retained for backwards-compat test-style PATCH updates. It enforces
// the same lifecycle guard as the dedicated /approve and /deny endpoints.
func (h *grantsHandler) patch(w http.ResponseWriter, r *http.Request, id string) {
	var body patchGrantReq
	if err := decodeJSONBody(w, r, defaultBodyLimit, &body); err != nil {
		return
	}
	g, err := h.store.GetGrant(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "grant not found")
		return
	}
	prev := g.Status
	target := domain.GrantStatus(body.Status)
	if !isValidTransition(prev, target) {
		writeErr(w, http.StatusConflict, fmt.Sprintf("illegal transition %s -> %s", prev, target))
		return
	}
	now := time.Now().UTC()
	switch target {
	case domain.GrantApproved:
		g.Status = domain.GrantApproved
		g.ApprovedAt = &now
		g.ApprovedBy = principalFrom(r)
	case domain.GrantDenied:
		g.Status = domain.GrantDenied
		g.DeniedAt = &now
		g.DeniedBy = principalFrom(r)
	case domain.GrantRevoked:
		g.Status = domain.GrantRevoked
		g.RevokedAt = &now
	case domain.GrantExpired:
		g.Status = domain.GrantExpired
	default:
		writeErr(w, http.StatusBadRequest, "status must be APPROVED, DENIED, REVOKED or EXPIRED")
		return
	}
	if body.Reason != "" {
		g.Reason = body.Reason
	}
	g.UpdatedAt = now
	if err := h.transitionGrant(r.Context(), g, prev, w); err != nil {
		return
	}
	h.logger.Info("grant_updated", "grant_id", g.ID, "status", g.Status)
	// Any terminal transition (REVOKED / EXPIRED / DENIED) should drop the
	// ephemeral backend user. PATCH → APPROVED never reaches the ephemeral
	// provisioning path here — approval goes through /approve.
	switch g.Status {
	case domain.GrantRevoked, domain.GrantExpired, domain.GrantDenied:
		h.maybeRevokeEphemeral(r.Context(), g)
	}
	writeJSON(w, http.StatusOK, g)
}

func (h *grantsHandler) approve(w http.ResponseWriter, r *http.Request, id string) {
	g, err := h.store.GetGrant(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "grant not found")
		return
	}
	prev := g.Status
	if !isValidTransition(prev, domain.GrantApproved) {
		writeErr(w, http.StatusConflict, fmt.Sprintf("cannot approve: status is %s", prev))
		return
	}
	now := time.Now().UTC()
	g.Status = domain.GrantApproved
	g.ApprovedAt = &now
	g.ApprovedBy = principalFrom(r)
	// Reset ExpiresAt relative to approval time using the originally requested
	// duration (ExpiresAt - RequestedAt). An admin approving past the request's
	// window should issue a fresh TTL, not hand out a DOA grant.
	if g.ExpiresAt != nil && !g.RequestedAt.IsZero() {
		dur := g.ExpiresAt.Sub(g.RequestedAt)
		if dur > 0 {
			renewed := now.Add(dur)
			g.ExpiresAt = &renewed
		}
	}
	g.UpdatedAt = now
	if err := h.transitionGrant(r.Context(), g, prev, w); err != nil {
		return
	}
	h.logger.Info("grant_approved", "grant_id", g.ID, "approved_by", g.ApprovedBy, "expires_at", g.ExpiresAt)

	// Ephemeral provisioning is best-effort unless a DBA account is present.
	// On provisioner failure we flip the grant back to PENDING and return 500
	// so an admin can retry — an APPROVED-but-not-provisioned grant would
	// mean the policy engine hands out shared creds while the operator thinks
	// the request was isolated.
	if h.ephemeral != nil {
		if err := h.provisionEphemeral(r.Context(), &g); err != nil {
			// Roll back to PENDING. If this rollback itself fails we log and
			// return 500 anyway — the grant is in an inconsistent state
			// either way and an operator must intervene.
			rollbackNow := time.Now().UTC()
			g.Status = domain.GrantPending
			g.ApprovedAt = nil
			g.ApprovedBy = ""
			g.UpdatedAt = rollbackNow
			if rerr := h.store.UpdateGrant(r.Context(), g); rerr != nil {
				h.logger.Error("grant_ephemeral_rollback_failed",
					"grant_id", g.ID, "provision_err", err, "rollback_err", rerr)
			} else {
				h.logger.Warn("grant_ephemeral_provision_failed",
					"grant_id", g.ID, "err", err)
			}
			writeErr(w, http.StatusInternalServerError, "ephemeral provisioning failed")
			return
		}
	}
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
	backends, err := h.store.ListBackends(ctx)
	if err != nil {
		return domain.Backend{}, err
	}
	for _, b := range backends {
		if b.ID == g.BackendID {
			return b, nil
		}
	}
	return domain.Backend{}, store.ErrNotFound
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
	writeJSON(w, http.StatusOK, g)
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

// isValidTransition enforces the grant lifecycle:
//
//	PENDING -> APPROVED | DENIED | REVOKED
//	APPROVED -> EXPIRED | REVOKED
//	DENIED, EXPIRED, REVOKED are terminal.
//
// PENDING -> REVOKED is allowed so a requester can cancel before approval.
//
// Any illegal transition yields 409 Conflict at the HTTP layer.
func isValidTransition(from, to domain.GrantStatus) bool {
	switch from {
	case domain.GrantPending:
		return to == domain.GrantApproved || to == domain.GrantDenied || to == domain.GrantRevoked
	case domain.GrantApproved:
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

// fireApprovalWebhook POSTs the grant request payload to the configured URL.
// Non-blocking: returns immediately; the background goroutine owns timeout +
// one retry. Failures are logged — never surfaced to the client, because
// webhook delivery must not gate grant creation.
func (h *grantsHandler) fireApprovalWebhook(g domain.Grant, username, backendAddr string) {
	// delivered_at is a top-level field receivers use to drop stale / replayed
	// deliveries (alongside HMAC verification). Separate from requested_at so
	// a retry within the same grant-request window carries a fresh value.
	payload := map[string]any{
		"grant_id":     g.ID,
		"user":         username,
		"backend":      backendAddr,
		"role":         string(g.Role),
		"reason":       g.Reason,
		"requested_by": g.RequestedBy,
		"requested_at": g.RequestedAt,
		"delivered_at": time.Now().UTC(),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		h.logger.Error("approval_webhook_marshal", "err", err, "grant_id", g.ID)
		return
	}
	url := h.webhookURL
	client := h.webhookClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	// Receivers authenticate the sender via HMAC-SHA256 over the raw body,
	// hex-encoded in X-Portal-Signature. Empty secret = unsigned (local dev).
	var sig string
	if h.webhookSecret != "" {
		mac := hmac.New(sha256.New, []byte(h.webhookSecret))
		mac.Write(body)
		sig = hex.EncodeToString(mac.Sum(nil))
	}
	h.webhookWG.Add(1)
	go func() {
		defer h.webhookWG.Done()
		// 1 retry on failure — transient 5xx / network errors shouldn't drop
		// the notification. 500ms gap between attempts avoids hammering a
		// target that's already 5xx-ing; bounded to 2 attempts so a sustained
		// outage never queues unboundedly.
		var lastErr error
		for attempt := 0; attempt < 2; attempt++ {
			if attempt > 0 {
				time.Sleep(500 * time.Millisecond)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
			if err != nil {
				cancel()
				lastErr = err
				break // malformed URL — retry won't help
			}
			req.Header.Set("Content-Type", "application/json")
			if sig != "" {
				req.Header.Set("X-Portal-Signature", "sha256="+sig)
			}
			resp, err := client.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				cancel()
				if resp.StatusCode < 500 {
					return
				}
				lastErr = fmt.Errorf("webhook returned status %d", resp.StatusCode)
				continue
			}
			cancel()
			lastErr = err
		}
		h.logger.Warn("approval_webhook_failed", "err", lastErr, "grant_id", g.ID)
	}()
}

func firstNonEmpty(xs ...string) string {
	for _, s := range xs {
		if s != "" {
			return s
		}
	}
	return ""
}
