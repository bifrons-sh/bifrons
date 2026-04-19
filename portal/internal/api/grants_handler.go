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
	entra             entra.Client
	requestPol        *policy.RequestPolicy
	entraSender       string
	publicURL         string
	entraMetrics      *EntraMetrics
	entraAdminMailbox string
	entraAdminGroupID string
	// entraWG tracks background email goroutines for graceful shutdown / tests.
	entraWG sync.WaitGroup

	// Tri-phase lifecycle defaults — used at /create and /approve when the
	// request body doesn't override them. Zero means "feature off" (no
	// deadline), matching the previous single-window behaviour.
	validationWindow time.Duration
	claimWindow      time.Duration
	credentialTTL    time.Duration
}

// EntraMetrics is a lock-free counter bundle exposed through obs.EntraStatsFn.
type EntraMetrics struct {
	emailSent           atomic.Uint64
	emailFailed         atomic.Uint64
	policyRejected      atomic.Uint64
	managerLookupFailed atomic.Uint64
	// Per-kind email counters — surfaced as
	// entra_email_sent_total{kind="manager_request|admin_request|outcome"}.
	emailSentManager atomic.Uint64
	emailSentAdmin   atomic.Uint64
	emailSentOutcome atomic.Uint64
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

// SnapshotByKind returns per-kind email counters: manager_request, admin_request, outcome.
func (m *EntraMetrics) SnapshotByKind() (manager, admin, outcome uint64) {
	if m == nil {
		return 0, 0, 0
	}
	return m.emailSentManager.Load(), m.emailSentAdmin.Load(), m.emailSentOutcome.Load()
}

// emailKind tags an email send so per-kind metrics increment on success.
type emailKind string

const (
	emailKindManagerRequest emailKind = "manager_request"
	emailKindAdminRequest   emailKind = "admin_request"
	emailKindOutcome        emailKind = "outcome"
)

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
			if h.entraMetrics != nil {
				h.entraMetrics.policyRejected.Add(1)
			}
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
		PortalPassword: firstNonEmpty(req.PortalPassword, "scaffold-"+domain.NewID("pw")),
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
			if h.entraMetrics != nil {
				h.entraMetrics.managerLookupFailed.Add(1)
			}
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
// only, never body) and counted against entra_email_failed_total. The kind
// label drives the per-kind counter (manager_request | admin_request | outcome).
func (h *grantsHandler) fireEntraEmail(g domain.Grant, user domain.User, backend domain.Backend) {
	h.sendApprovalEmail(g, []string{g.ApproverHint},
		fmt.Sprintf("Access request: %s on %s", g.Role, backend.Name),
		fmt.Sprintf("User %s requested %s access on %s (%s).\nReason: %s\nGrant ID: %s\n",
			displayOr(user), g.Role, backend.Name, backend.Address(), g.Reason, g.ID),
		emailKindManagerRequest,
	)
}

// fireAdminApprovalEmail notifies admin reachability target(s) once the
// manager half of the dual-gate has fired. Recipients come from the
// configured single mailbox plus / or the resolved Entra group members.
func (h *grantsHandler) fireAdminApprovalEmail(g domain.Grant) {
	if h.entra == nil || h.entraSender == "" {
		return
	}
	recipients := h.adminRecipients(context.Background())
	if len(recipients) == 0 {
		h.logger.Warn("entra_admin_recipients_empty", "grant_id", g.ID)
		return
	}
	subject := fmt.Sprintf("Admin approval needed: %s on backend %s", g.Role, g.BackendID)
	body := fmt.Sprintf("Grant %s is awaiting admin approval (manager %s already approved).\nReason: %s\n",
		g.ID, g.ManagerApprovedBy, g.Reason)
	h.sendApprovalEmail(g, recipients, subject, body, emailKindAdminRequest)
}

// fireOutcomeEmail tells the requester whether the grant landed APPROVED
// (approved=true) or DENIED (false). Best-effort; never blocks.
func (h *grantsHandler) fireOutcomeEmail(g domain.Grant, approved bool) {
	if h.entra == nil || h.entraSender == "" {
		return
	}
	// We address the requester via their session subject — to lazily resolve
	// the email without a Graph round-trip we look up the portal user by
	// requested-by string when it looks like a subject; absent that we skip.
	to := g.RequestedBy
	if to == "" || !strings.Contains(to, "@") {
		// Best-effort lookup: maybe RequestedBy is an Entra subject.
		if g.RequestedBy != "" && h.entra != nil {
			if u, err := h.entra.GetUser(context.Background(), g.RequestedBy); err == nil {
				to = firstNonEmpty(u.Mail, u.UserPrincipalName)
			}
		}
	}
	if to == "" {
		h.logger.Info("entra_outcome_skipped", "grant_id", g.ID, "reason", "no_recipient")
		return
	}
	verdict := "approved"
	if !approved {
		verdict = "denied"
	}
	subject := fmt.Sprintf("Access request %s: %s", verdict, g.ID)
	body := fmt.Sprintf("Your access request %s was %s.\n", g.ID, verdict)
	h.sendApprovalEmail(g, []string{to}, subject, body, emailKindOutcome)
}

// adminRecipients resolves the admin reachability list for fireAdminApprovalEmail.
// Honours both the single-mailbox flag and the group-id flag; returns the
// dedup'd union. Group-resolution failures are logged, never fatal.
func (h *grantsHandler) adminRecipients(ctx context.Context) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(addr string) {
		if addr == "" {
			return
		}
		if _, ok := seen[strings.ToLower(addr)]; ok {
			return
		}
		seen[strings.ToLower(addr)] = struct{}{}
		out = append(out, addr)
	}
	if h.entraAdminMailbox != "" {
		add(h.entraAdminMailbox)
	}
	if h.entraAdminGroupID != "" && h.entra != nil {
		gctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		members, err := h.entra.GroupMembers(gctx, h.entraAdminGroupID)
		cancel()
		if err != nil {
			h.logger.Warn("entra_admin_group_resolve_failed", "group_id", h.entraAdminGroupID, "err_class", err.Error())
		}
		for _, m := range members {
			add(firstNonEmpty(m.Mail, m.UserPrincipalName))
		}
	}
	return out
}

// sendApprovalEmail is the shared off-hot-path mailer. The kind label drives
// the per-kind sent counter; aggregate counters land regardless of kind.
func (h *grantsHandler) sendApprovalEmail(g domain.Grant, to []string, subject, textBody string, kind emailKind) {
	if len(to) == 0 || h.entra == nil || h.entraSender == "" {
		return
	}
	link := ""
	if h.publicURL != "" {
		link = strings.TrimRight(h.publicURL, "/") + "/ui/grants/" + g.ID
	}
	text := textBody
	if link != "" {
		text += link + "\n"
	}
	var html string
	if link != "" {
		html = fmt.Sprintf(
			`<p>%s</p><p><a href="%s">Open in portal</a></p>`,
			escapeHTML(textBody), escapeHTML(link),
		)
	}
	msg := entra.MailMessage{To: to, Subject: subject, TextBody: text, HTMLBody: html}
	h.entraWG.Add(1)
	go func() {
		defer h.entraWG.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := h.entra.SendMail(ctx, h.entraSender, msg); err != nil {
			if h.entraMetrics != nil {
				h.entraMetrics.emailFailed.Add(1)
			}
			h.logger.Warn("entra_email_failed", "grant_id", g.ID, "kind", string(kind), "to_domain", domainPart(to[0]))
			return
		}
		if h.entraMetrics != nil {
			h.entraMetrics.emailSent.Add(1)
			switch kind {
			case emailKindManagerRequest:
				h.entraMetrics.emailSentManager.Add(1)
			case emailKindAdminRequest:
				h.entraMetrics.emailSentAdmin.Add(1)
			case emailKindOutcome:
				h.entraMetrics.emailSentOutcome.Add(1)
			}
		}
		h.logger.Info("entra_email_sent", "grant_id", g.ID, "kind", string(kind), "to_count", len(to))
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
	sess := SessionFromContext(r.Context())
	// Static-bearer (sess==nil) is the privileged operator credential — it
	// can stand in for either gate so existing operator scripts keep working
	// when Entra isn't wired. OIDC sessions split: admin half requires
	// IsAdmin, manager half requires the subject to match ManagerSubject.
	isStaticBearer := sess == nil
	isAdmin := isStaticBearer || sess.IsAdmin
	isManager := isStaticBearer || (sess != nil && g.ManagerSubject != "" && sess.Subject == g.ManagerSubject)

	switch g.Status {
	case domain.GrantPending:
		if !isManager {
			writeErr(w, http.StatusForbidden, "manager approval required first")
			return
		}
		h.managerApprove(w, r, g)
	case domain.GrantManagerApproved:
		if !isAdmin {
			writeErr(w, http.StatusForbidden, "admin approval required")
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
	h.fireAdminApprovalEmail(g)
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
	if g.PolicyMode == policy.ModeEphemeral && h.ephemeral != nil {
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
	h.fireOutcomeEmail(g, true)
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
	// Either party (manager or admin) may deny at any pre-APPROVED stage.
	sess := SessionFromContext(r.Context())
	isAdmin := sess == nil || sess.IsAdmin
	isManager := sess != nil && g.ManagerSubject != "" && sess.Subject == g.ManagerSubject
	if !isAdmin && !isManager {
		writeErr(w, http.StatusForbidden, "deny requires manager or admin")
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
	h.fireOutcomeEmail(g, false)
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
	sess := SessionFromContext(r.Context())
	isAdmin := sess == nil || sess.IsAdmin
	// Owner check: the OIDC PortalUserID matches the grant's UserID, OR the
	// session subject was the original requester (covers principal-from-bearer
	// and OIDC subject-as-requester paths).
	isOwner := false
	if sess != nil {
		if sess.PortalUserID != "" && sess.PortalUserID == g.UserID {
			isOwner = true
		}
		if sess.Subject != "" && sess.Subject == g.RequestedBy {
			isOwner = true
		}
	}
	if !isOwner && !isAdmin {
		writeErr(w, http.StatusForbidden, "claim requires the requester or an admin")
		return
	}
	// Admin-on-behalf: when an admin claims a grant they don't own, the
	// returned creds flow through the admin session — log it prominently so
	// operators can audit who picked up credentials for whom.
	if isAdmin && !isOwner {
		h.logger.Warn("grant_claimed_on_behalf",
			"grant_id", g.ID,
			"owner_user_id", g.UserID,
			"claimed_by", principalFrom(r),
		)
	}

	now := time.Now().UTC()

	// Idempotent re-claim: if already ACTIVE and within ExpiresAt, return the
	// same creds. Past ExpiresAt → 410 Gone.
	if g.Status == domain.GrantActive {
		if g.ExpiresAt != nil && now.After(*g.ExpiresAt) {
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
	if g.ClaimExpiresAt != nil && now.After(*g.ClaimExpiresAt) {
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
	if h.ephemeral != nil && g.PolicyMode == policy.ModeEphemeral {
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
