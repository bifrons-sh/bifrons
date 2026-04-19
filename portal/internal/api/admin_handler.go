package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// adminHandler exposes minimal seed endpoints for scaffold demos.
// Routes are mounted via registerAdminRoutes, which uses Go 1.22 method +
// pattern matching so each endpoint is declared once with its HTTP verb.
type adminHandler struct {
	store  store.Store
	logger *slog.Logger
}

// registerAdminRoutes wires every admin endpoint onto mux. GET /backends is
// open to any authenticated caller so operator SPAs can render the fleet
// overview; every mutation is admin-gated via adminOnly wrapping.
func registerAdminRoutes(mux *http.ServeMux, h *adminHandler) {
	mux.HandleFunc("GET /api/v1/backends", h.listBackends)
	mux.Handle("POST /api/v1/users", adminOnly(http.HandlerFunc(h.createUser)))
	mux.Handle("POST /api/v1/backends", adminOnly(http.HandlerFunc(h.createBackend)))
	mux.Handle("POST /api/v1/backends/{id}/accounts", adminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.upsertAccount(w, r, r.PathValue("id"))
	})))
}

// adminOnly wraps next with the admin guard. requireAdmin writes 403 + false
// when denied so we can short-circuit here without duplicating the message.
func adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// listBackends returns the registered backends. Read-only and non-sensitive:
// addresses + types are already visible to operators via the proxy endpoints,
// and backend accounts (which carry secrets) live on a separate sub-resource
// that isn't enumerated here.
func (h *adminHandler) listBackends(w http.ResponseWriter, r *http.Request) {
	bs, err := h.store.ListBackends(r.Context())
	if err != nil {
		h.logger.Error("list_backends_failed", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, bs)
}

type createUserReq struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name,omitempty"`
	Email       string `json:"email,omitempty"`
	IsAdmin     bool   `json:"is_admin,omitempty"`
}

func (h *adminHandler) createUser(w http.ResponseWriter, r *http.Request) {
	var req createUserReq
	if err := decodeJSONBody(w, r, defaultBodyLimit, &req); err != nil {
		return
	}
	if req.Username == "" {
		writeErr(w, http.StatusBadRequest, "username is required")
		return
	}
	now := time.Now().UTC()
	u := domain.User{
		ID:          domain.NewID("u"),
		Username:    req.Username,
		DisplayName: req.DisplayName,
		Email:       req.Email,
		IsAdmin:     req.IsAdmin,
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := h.store.CreateUser(r.Context(), u); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	h.logger.Info("user_created", "id", u.ID, "username", u.Username)
	writeJSON(w, http.StatusCreated, u)
}

type createBackendReq struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Host      string   `json:"host"`
	Port      int      `json:"port"`
	Databases []string `json:"databases,omitempty"`
}

func (h *adminHandler) createBackend(w http.ResponseWriter, r *http.Request) {
	var req createBackendReq
	if err := decodeJSONBody(w, r, defaultBodyLimit, &req); err != nil {
		return
	}
	if req.Name == "" || req.Host == "" || req.Port == 0 || req.Type == "" {
		writeErr(w, http.StatusBadRequest, "name, type, host, port are required")
		return
	}
	now := time.Now().UTC()
	b := domain.Backend{
		ID:        domain.NewID("b"),
		Name:      req.Name,
		Type:      domain.ProxyType(req.Type),
		Host:      req.Host,
		Port:      req.Port,
		Databases: req.Databases,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := h.store.CreateBackend(r.Context(), b); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	h.logger.Info("backend_created", "id", b.ID, "name", b.Name, "addr", b.Address())
	writeJSON(w, http.StatusCreated, b)
}

type upsertAccountReq struct {
	Role        string `json:"role"`
	Username    string `json:"username"`
	// Exactly one of PasswordRef / Password must be set.
	//   PasswordRef: "env://NAME" or "file:///path" — resolved on demand, never stored.
	//   Password:    literal secret — encrypted at rest by the Encrypting store.
	PasswordRef string `json:"password_ref,omitempty"`
	Password    string `json:"password,omitempty"`
}

func (h *adminHandler) upsertAccount(w http.ResponseWriter, r *http.Request, backendID string) {
	var req upsertAccountReq
	if err := decodeJSONBody(w, r, defaultBodyLimit, &req); err != nil {
		return
	}
	if req.Role == "" || req.Username == "" {
		writeErr(w, http.StatusBadRequest, "role, username required")
		return
	}
	if (req.PasswordRef == "") == (req.Password == "") {
		writeErr(w, http.StatusBadRequest, "exactly one of password_ref or password must be set")
		return
	}
	now := time.Now().UTC()
	a := domain.BackendAccount{
		ID:          domain.NewID("ba"),
		BackendID:   backendID,
		Role:        domain.Role(req.Role),
		Username:    req.Username,
		PasswordRef: req.PasswordRef,
		Password:    req.Password,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := h.store.UpsertBackendAccount(r.Context(), a); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.logger.Info("backend_account_upserted", "backend_id", backendID, "role", a.Role)
	writeJSON(w, http.StatusCreated, a)
}
