package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// grantsHandler serves the /api/v1/grants collection + /api/v1/grants/:id item routes.
type grantsHandler struct {
	store  store.Store
	logger *slog.Logger
}

// ServeHTTP dispatches on path + method. Kept mux-free for scaffold simplicity.
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
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
	approvedAt := now // scaffold: auto-approve on create to keep the e2e loop simple

	g := domain.Grant{
		ID:             domain.NewID("g"),
		UserID:         user.ID,
		BackendID:      backend.ID,
		Database:       req.Database,
		Role:           domain.Role(req.Role),
		Status:         domain.GrantApproved,
		Reason:         req.Reason,
		PortalPassword: firstNonEmpty(req.PortalPassword, "scaffold-"+domain.NewID("pw")),
		ApprovedBy:     "scaffold",
		RequestedAt:    now,
		ApprovedAt:     &approvedAt,
		ExpiresAt:      &expires,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := h.store.CreateGrant(r.Context(), g); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.logger.Info("grant_created", "grant_id", g.ID, "user", user.Username, "backend", backend.Address(), "role", g.Role, "expires_at", g.ExpiresAt)
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

func (h *grantsHandler) patch(w http.ResponseWriter, r *http.Request, id string) {
	var body patchGrantReq
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	g, err := h.store.GetGrant(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "grant not found")
		return
	}
	now := time.Now().UTC()
	switch domain.GrantStatus(body.Status) {
	case domain.GrantApproved:
		g.Status = domain.GrantApproved
		g.ApprovedAt = &now
		g.ApprovedBy = "api" // scaffold: no session context
	case domain.GrantDenied:
		g.Status = domain.GrantDenied
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

func (h *grantsHandler) revoke(w http.ResponseWriter, r *http.Request, id string) {
	g, err := h.store.GetGrant(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "grant not found")
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

func firstNonEmpty(xs ...string) string {
	for _, s := range xs {
		if s != "" {
			return s
		}
	}
	return ""
}
