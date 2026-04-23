package api

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// adminHandler serves the user + backend admin surface. Read endpoints are
// open to any authenticated caller (the SPA renders fleet + org views without
// admin); every mutation is admin-gated via adminOnly wrapping. Non-admin
// reads go through a trimmed DTO — see publicUser / toPublicUser.
type adminHandler struct {
	store  store.Store
	logger *slog.Logger
}

// registerAdminRoutes wires every admin endpoint onto mux using Go 1.22
// method+pattern matching.
func registerAdminRoutes(mux *http.ServeMux, h *adminHandler) {
	mux.HandleFunc("GET /api/v1/users", h.listUsers)
	mux.HandleFunc("GET /api/v1/users/{id}", h.getUser)
	mux.HandleFunc("GET /api/v1/backends", h.listBackends)
	mux.Handle("POST /api/v1/users", adminOnly(http.HandlerFunc(h.createUser)))
	mux.Handle("PATCH /api/v1/users/{id}", adminOnly(http.HandlerFunc(h.patchUser)))
	mux.Handle("POST /api/v1/backends", adminOnly(http.HandlerFunc(h.createBackend)))
	mux.Handle("POST /api/v1/backends/{id}/accounts", adminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.upsertAccount(w, r, r.PathValue("id"))
	})))
}

// publicUser is the shape returned to non-admin callers: enough to render
// names in the SPA without exposing the is_admin flag (recon surface),
// external_id (IdP subject — binds portal user to IdP identity),
// validator_user_id (full reporting chain is admin-only), or any secret
// material. Admins see domain.User directly.
type publicUser struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name,omitempty"`
	Email       string `json:"email,omitempty"`
}

func toPublicUser(u domain.User) publicUser {
	return publicUser{
		ID:          u.ID,
		Username:    u.Username,
		DisplayName: u.DisplayName,
		Email:       u.Email,
	}
}

func toPublicUsers(us []domain.User) []publicUser {
	out := make([]publicUser, 0, len(us))
	for _, u := range us {
		out = append(out, toPublicUser(u))
	}
	return out
}

// publicGroup drops external_id — the upstream IdP's object id — from
// non-admin responses. The slug is public (it drives the policy YAML
// operators write) but the IdP id is not.
type publicGroup struct {
	ID          string `json:"id"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name,omitempty"`
}

func toPublicGroup(g domain.Group) publicGroup {
	return publicGroup{ID: g.ID, Slug: g.Slug, DisplayName: g.DisplayName}
}

func toPublicGroups(gs []domain.Group) []publicGroup {
	out := make([]publicGroup, 0, len(gs))
	for _, g := range gs {
		out = append(out, toPublicGroup(g))
	}
	return out
}

// listUsers returns every user. Non-admin callers get the trimmed publicUser
// shape; admins get the full domain.User (still minus PasswordHash via the
// json:"-" tag — defence in depth against scan leaks).
func (h *adminHandler) listUsers(w http.ResponseWriter, r *http.Request) {
	us, err := h.store.ListUsers(r.Context())
	if err != nil {
		h.logger.Error("list_users_failed", "err_class", errClass(err))
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if callerIsAdmin(r) {
		writeJSON(w, http.StatusOK, us)
		return
	}
	writeJSON(w, http.StatusOK, toPublicUsers(us))
}

// getUser returns a single user by id. Trimmed for non-admins.
func (h *adminHandler) getUser(w http.ResponseWriter, r *http.Request) {
	u, err := h.store.GetUser(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	if callerIsAdmin(r) {
		writeJSON(w, http.StatusOK, u)
		return
	}
	writeJSON(w, http.StatusOK, toPublicUser(u))
}

// patchUserReq is a sparse update: only non-nil fields are applied. Pointer
// semantics let callers distinguish "clear the value" (set *"") from "leave
// alone" (nil).
type patchUserReq struct {
	DisplayName *string `json:"display_name,omitempty"`
	Email       *string `json:"email,omitempty"`
	ExternalID  *string `json:"external_id,omitempty"`
	IsAdmin     *bool   `json:"is_admin,omitempty"`
	Status      *string `json:"status,omitempty"`
}

// patchUser reconciles mutable scalar attributes of an existing user. Admin
// only. Used by the entra-sync script to back-fill external_id on users that
// predate OIDC binding and to repair drift on display_name / email.
func (h *adminHandler) patchUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req patchUserReq
	if err := decodeJSONBody(w, r, defaultBodyLimit, &req); err != nil {
		return
	}
	u, err := h.store.GetUser(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	if req.DisplayName != nil {
		u.DisplayName = *req.DisplayName
	}
	if req.Email != nil {
		u.Email = *req.Email
	}
	if req.ExternalID != nil {
		u.ExternalID = *req.ExternalID
	}
	// Detect a demotion before applying it: the store routes through the
	// transactional UpdateUserDemote in that case so the last-admin guard
	// can't lose to two concurrent patches against different admins.
	demoting := req.IsAdmin != nil && !*req.IsAdmin && u.IsAdmin
	if req.IsAdmin != nil {
		u.IsAdmin = *req.IsAdmin
	}
	if req.Status != nil {
		// Schema only knows two values; reject anything else here so a typo
		// can't quietly disable a user (status="disable" silently keeps them
		// active because the row stays "active") or leave the row in a state
		// the rest of the system doesn't recognise.
		switch *req.Status {
		case "active", "disabled":
			u.Status = *req.Status
		default:
			writeErr(w, http.StatusBadRequest, "status must be 'active' or 'disabled'")
			return
		}
	}
	var werr error
	if demoting {
		werr = h.store.UpdateUserDemote(r.Context(), u)
	} else {
		werr = h.store.UpdateUser(r.Context(), u)
	}
	if werr != nil {
		if errors.Is(werr, store.ErrLastAdmin) {
			writeErr(w, http.StatusConflict, "cannot demote: at least one admin must remain — promote another user first")
			return
		}
		if errors.Is(werr, store.ErrNotFound) {
			// Either the row is gone or a concurrent patch drifted updated_at
			// under our CAS. The client should re-read + retry — 409 is the
			// honest shape for an RMW race, 404 for "user genuinely gone".
			// We can't tell the two apart cheaply; prefer 409 so a naive
			// retry eventually succeeds.
			writeErr(w, http.StatusConflict, "user changed under us; retry")
			return
		}
		if errors.Is(werr, store.ErrConflict) {
			writeErr(w, http.StatusConflict, "external_id already in use")
			return
		}
		h.logger.Error("patch_user_failed", "user_id", id, "err_class", errClass(werr))
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.logger.Info("user_patched", "user_id", id, "by", principalFrom(r))
	// Re-read so the response carries the canonical updated_at the store
	// just wrote, instead of the stale CAS witness on `u`. Lets a client
	// chain a follow-up PATCH without a separate GET.
	fresh, gerr := h.store.GetUser(r.Context(), id)
	if gerr != nil {
		// Patch landed; only the read-back failed. Return what we have so the
		// client at least learns the patch succeeded — UpdatedAt will be
		// stale but a future PATCH will surface the correct value via a 409.
		writeJSON(w, http.StatusOK, u)
		return
	}
	writeJSON(w, http.StatusOK, fresh)
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

// callerIsAdmin reports whether the caller has admin privileges for read
// endpoints that switch on role. Mirrors requireAdmin's acceptance set:
//   - OIDC session with IsAdmin=true → admin
//   - no OIDC session (static-bearer or open dev mode) → admin
// Used to pick between the full domain.User view and the trimmed publicUser.
func callerIsAdmin(r *http.Request) bool {
	if sess := SessionFromContext(r.Context()); sess != nil {
		return sess.IsAdmin
	}
	return true
}

// errClass returns a compact tag describing err's kind so driver-level
// strings (which may embed connection details / DSN fragments) never hit
// operator logs verbatim. Falls back to the type name for unknown errors.
func errClass(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, store.ErrNotFound):
		return "not_found"
	case errors.Is(err, store.ErrConflict):
		return "conflict"
	default:
		return "store_error"
	}
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
	// ExternalID binds the new user to an IdP subject (OIDC `sub`). Populated
	// by the entra-sync script so OIDC login can resolve sync-provisioned users
	// via store.GetUserByExternalID — the portal otherwise has no way to learn
	// the subject once the user shows up.
	ExternalID string `json:"external_id,omitempty"`
	IsAdmin    bool   `json:"is_admin,omitempty"`
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
		ExternalID:  req.ExternalID,
		IsAdmin:     req.IsAdmin,
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := h.store.CreateUser(r.Context(), u); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeErr(w, http.StatusConflict, "username or external_id already in use")
			return
		}
		h.logger.Error("create_user_failed", "username", req.Username, "err_class", errClass(err))
		writeErr(w, http.StatusInternalServerError, "internal error")
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
