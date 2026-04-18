package api

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// adminHandler exposes minimal seed endpoints for scaffold demos:
//   POST /api/v1/users
//   POST /api/v1/backends
//   POST /api/v1/backends/{id}/accounts
type adminHandler struct {
	store  store.Store
	logger *slog.Logger
}

func (h *adminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Seed endpoints mint users, backends, and backend-account credentials —
	// all operator-level actions. Gate behind the same admin check /grants
	// uses so a non-admin OIDC session can't escalate by creating its own
	// admin user or planting backend accounts with attacker-owned PasswordRef.
	if !requireAdmin(w, r) {
		return
	}
	switch {
	case r.URL.Path == "/api/v1/users" && r.Method == http.MethodPost:
		h.createUser(w, r)
	case r.URL.Path == "/api/v1/backends" && r.Method == http.MethodPost:
		h.createBackend(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/v1/backends/") && strings.HasSuffix(r.URL.Path, "/accounts") && r.Method == http.MethodPost:
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/backends/"), "/accounts")
		h.upsertAccount(w, r, id)
	default:
		writeErr(w, http.StatusNotFound, "not found")
	}
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
	PasswordRef string `json:"password_ref,omitempty"`
	// Deprecated: clients should send password_ref (e.g. "env://DB_APP_RW_PW").
	// Accepted only for backwards-compat with the pre-secrets admin API.
	Password string `json:"password,omitempty"`
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
	if req.PasswordRef == "" && req.Password == "" {
		writeErr(w, http.StatusBadRequest, "password_ref or password required")
		return
	}
	now := time.Now().UTC()
	a := domain.BackendAccount{
		ID:          domain.NewID("ba"),
		BackendID:   backendID,
		Role:        domain.Role(req.Role),
		Username:    req.Username,
		PasswordRef: req.PasswordRef,
		// Drop legacy Password when PasswordRef is supplied — prefer the ref so
		// we never persist the cleartext alongside it.
		Password:  passwordFallback(req.PasswordRef, req.Password),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := h.store.UpsertBackendAccount(r.Context(), a); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.logger.Info("backend_account_upserted", "backend_id", backendID, "role", a.Role)
	// Response body never echoes either secret field (both are json:"-" or redacted).
	writeJSON(w, http.StatusCreated, a)
}

// passwordFallback returns the legacy password only when no ref is configured;
// keeps the store from holding both forms for the same account.
func passwordFallback(ref, pw string) string {
	if ref != "" {
		return ""
	}
	return pw
}
