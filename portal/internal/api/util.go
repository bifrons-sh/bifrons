package api

import (
	"encoding/json"
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
