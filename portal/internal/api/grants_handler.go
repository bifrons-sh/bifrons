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
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
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
// All /api/v1/grants endpoints are admin-only: the user-requests-access flow
// is out of scope for the scaffold, so the whole collection is treated as an
// operator surface. Non-admin OIDC sessions get 403; static-bearer callers
// pass through (the bearer is already a privileged operator credential).
func (h *grantsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
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
				h.approve(w, r, id)
			case action == "deny" && r.Method == http.MethodPost:
				h.deny(w, r, id)
			default:
				writeErr(w, http.StatusNotFound, "not found")
			}
			return
		}
		switch r.Method {
		case http.MethodGet:
			h.get(w, r, id)
		case http.MethodPatch:
			h.patch(w, r, id)
		case http.MethodDelete:
			h.revoke(w, r, id)
		default:
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	default:
		writeErr(w, http.StatusNotFound, "not found")
	}
}

type createGrantReq struct {
	UserID             string        `json:"user_id"`
	BackendAddr        string        `json:"backend_addr"` // host:port, resolved to backend
	Database           string        `json:"database"`
	Role               string        `json:"role"`
	Reason             string        `json:"reason"`
	RequestedDuration  time.Duration `json:"-"`
	RequestedDurationS string        `json:"requested_duration,omitempty"`
	PortalPassword     string        `json:"portal_password,omitempty"` // optional; auto-generated if empty
}

func (h *grantsHandler) create(w http.ResponseWriter, r *http.Request) {
	var req createGrantReq
	if err := decodeJSONBody(w, r, defaultBodyLimit, &req); err != nil {
		return
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
		"expires_at", g.ExpiresAt,
	)
	// Fire webhook only for genuinely pending grants — skip when auto-approved
	// because the four-eyes notification would be meaningless.
	if g.Status == domain.GrantPending && h.webhookURL != "" {
		h.fireApprovalWebhook(g, user.Username, backend.Address())
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
	target := domain.GrantStatus(body.Status)
	if !isValidTransition(g.Status, target) {
		writeErr(w, http.StatusConflict, fmt.Sprintf("illegal transition %s -> %s", g.Status, target))
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
	if err := h.store.UpdateGrant(r.Context(), g); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.logger.Info("grant_updated", "grant_id", g.ID, "status", g.Status)
	writeJSON(w, http.StatusOK, g)
}

func (h *grantsHandler) approve(w http.ResponseWriter, r *http.Request, id string) {
	g, err := h.store.GetGrant(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "grant not found")
		return
	}
	if !isValidTransition(g.Status, domain.GrantApproved) {
		writeErr(w, http.StatusConflict, fmt.Sprintf("cannot approve: status is %s", g.Status))
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
	if err := h.store.UpdateGrant(r.Context(), g); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.logger.Info("grant_approved", "grant_id", g.ID, "approved_by", g.ApprovedBy, "expires_at", g.ExpiresAt)
	writeJSON(w, http.StatusOK, g)
}

func (h *grantsHandler) deny(w http.ResponseWriter, r *http.Request, id string) {
	g, err := h.store.GetGrant(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "grant not found")
		return
	}
	if !isValidTransition(g.Status, domain.GrantDenied) {
		writeErr(w, http.StatusConflict, fmt.Sprintf("cannot deny: status is %s", g.Status))
		return
	}
	now := time.Now().UTC()
	g.Status = domain.GrantDenied
	g.DeniedAt = &now
	g.DeniedBy = principalFrom(r)
	g.UpdatedAt = now
	if err := h.store.UpdateGrant(r.Context(), g); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.logger.Info("grant_denied", "grant_id", g.ID, "denied_by", g.DeniedBy)
	writeJSON(w, http.StatusOK, g)
}

func (h *grantsHandler) revoke(w http.ResponseWriter, r *http.Request, id string) {
	g, err := h.store.GetGrant(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "grant not found")
		return
	}
	if !isValidTransition(g.Status, domain.GrantRevoked) {
		writeErr(w, http.StatusConflict, fmt.Sprintf("cannot revoke: status is %s", g.Status))
		return
	}
	now := time.Now().UTC()
	g.Status = domain.GrantRevoked
	g.RevokedAt = &now
	g.UpdatedAt = now
	if err := h.store.UpdateGrant(r.Context(), g); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.logger.Info("grant_revoked", "grant_id", g.ID)
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
	payload := map[string]any{
		"grant_id":     g.ID,
		"user":         username,
		"backend":      backendAddr,
		"role":         string(g.Role),
		"reason":       g.Reason,
		"requested_by": g.RequestedBy,
		"requested_at": g.RequestedAt,
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
