package api

import (
	"encoding/json"
	"errors"
	"net/http"
)

// writeJSON serialises v as JSON with the given status.
// Swallows encode errors — if the client is gone, there's nothing useful to do.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr emits a uniform error body.
func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// defaultBodyLimit caps JSON payloads for small-shape endpoints (admin seed +
// grant CRUD). Oversized POSTs on these surfaces are almost certainly abuse;
// the audit ingest endpoint uses its own larger limit (see audit_handler.go).
const defaultBodyLimit = 64 << 10 // 64 KiB

// decodeJSONBody wraps json decoding with a MaxBytesReader and responds with
// a typed HTTP error on oversize / bad JSON. Unknown fields are *tolerated*
// for forward-compat — proxies and clients can add fields without breaking
// older portals; callers that want strict mode can add DisallowUnknownFields
// themselves.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, limit int64, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeErr(w, http.StatusRequestEntityTooLarge, "request body too large")
			return err
		}
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return err
	}
	return nil
}
