package api

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/babs/poc-proxies/internal/auth"
	"github.com/babs/poc-proxies/portal/internal/policy"
)

// authHandler serves POST /api/v1/auth — the proxy credential lookup endpoint.
type authHandler struct {
	engine *policy.Engine
	logger *slog.Logger
}

func (h *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req auth.LookupRequest
	if err := decodeJSONBody(w, r, defaultBodyLimit, &req); err != nil {
		return
	}
	defer r.Body.Close()

	resp, err := h.engine.Resolve(r.Context(), req)
	if err != nil {
		switch {
		case errors.Is(err, policy.ErrNoActiveGrant):
			h.logger.Info("auth_denied", "username", req.Username, "backend", req.BackendServer, "reason", "no_active_grant")
			writeErr(w, http.StatusUnauthorized, "no active grant for user")
		case errors.Is(err, policy.ErrGrantExpired):
			h.logger.Info("auth_denied", "username", req.Username, "backend", req.BackendServer, "reason", "grant_expired")
			writeErr(w, http.StatusForbidden, "grant expired or revoked")
		default:
			h.logger.Error("auth_error", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal error")
		}
		return
	}

	h.logger.Info("auth_granted",
		"username", req.Username,
		"proxy_type", req.ProxyType,
		"backend", req.BackendServer,
		"grant_id", resp.GrantID,
		"role", resp.Role,
	)
	writeJSON(w, http.StatusOK, resp)
}
