package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// auditHandler serves POST /api/v1/audit/query — batched query audit ingestion.
type auditHandler struct {
	store  store.Store
	logger *slog.Logger
}

type auditRequest struct {
	Entries []domain.AuditEntry `json:"entries"`
}

type auditResponse struct {
	Accepted int `json:"accepted"`
}

func (h *auditHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req auditRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	defer r.Body.Close()

	if err := h.store.AppendAudit(r.Context(), req.Entries); err != nil {
		h.logger.Error("audit_store_error", "err", err)
		writeErr(w, http.StatusInternalServerError, "failed to persist audit")
		return
	}
	h.logger.Info("audit_batch_accepted", "count", len(req.Entries))
	writeJSON(w, http.StatusAccepted, auditResponse{Accepted: len(req.Entries)})
}
