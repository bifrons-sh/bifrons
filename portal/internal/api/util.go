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
// a typed HTTP error on oversize / bad JSON. Unknown fields are tolerated for
// forward-compat — used by proxy-facing endpoints (/api/v1/auth, audit) where
// a new portal feature must not break older proxies.
//
// User/admin write endpoints should use decodeJSONBodyStrict instead so a
// typo'd field (`is_admin` instead of `is_operator`) surfaces as a 400 rather
// than a silent no-op.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, limit int64, v any) error {
	return decodeJSONBodyOpt(w, r, limit, v, false)
}

// decodeJSONBodyStrict is decodeJSONBody with DisallowUnknownFields enabled.
// Use for write endpoints where unknown fields almost certainly mean a typo
// or a client-side misunderstanding — surface them loudly instead of swallowing.
func decodeJSONBodyStrict(w http.ResponseWriter, r *http.Request, limit int64, v any) error {
	return decodeJSONBodyOpt(w, r, limit, v, true)
}

func decodeJSONBodyOpt(w http.ResponseWriter, r *http.Request, limit int64, v any, strict bool) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(v); err != nil {
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
