package api

import (
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

// Bounds on the audit ingest endpoint. Proxies batch on their own schedule;
// these caps stop a buggy/malicious proxy (or a poisoned shipper) from OOMing
// the portal with a multi-GB POST or a billion-row single transaction.
const (
	auditMaxBodyBytes   = 10 << 20 // 10 MiB
	auditMaxEntriesPost = 10_000   // matches a generous upstream batch window
)

func (h *auditHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	defer r.Body.Close()
	var req auditRequest
	if err := decodeJSONBody(w, r, auditMaxBodyBytes, &req); err != nil {
		return
	}
	if len(req.Entries) > auditMaxEntriesPost {
		writeErr(w, http.StatusRequestEntityTooLarge,
			"too many entries in single batch")
		return
	}

	if err := h.store.AppendAudit(r.Context(), req.Entries); err != nil {
		h.logger.Error("audit_store_error", "err", err)
		writeErr(w, http.StatusInternalServerError, "failed to persist audit")
		return
	}
	h.logger.Info("audit_batch_accepted", "count", len(req.Entries))
	writeJSON(w, http.StatusAccepted, auditResponse{Accepted: len(req.Entries)})
}
