package api

import (
	"encoding/json"
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
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
	Role     string `json:"role"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *adminHandler) upsertAccount(w http.ResponseWriter, r *http.Request, backendID string) {
	var req upsertAccountReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Role == "" || req.Username == "" || req.Password == "" {
		writeErr(w, http.StatusBadRequest, "role, username, password required")
		return
	}
	now := time.Now().UTC()
	a := domain.BackendAccount{
		ID:        domain.NewID("ba"),
		BackendID: backendID,
		Role:      domain.Role(req.Role),
		Username:  req.Username,
		Password:  req.Password,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := h.store.UpsertBackendAccount(r.Context(), a); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.logger.Info("backend_account_upserted", "backend_id", backendID, "role", a.Role)
	writeJSON(w, http.StatusCreated, a)
}
