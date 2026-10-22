package server

import (
	"encoding/json"
	"net/http"

	"nazr/api/internal/auth"
)

// Error codes used in {"error","message"} bodies.
const (
	codeBadRequest       = "bad_request"
	codePayloadTooLarge  = "payload_too_large"
	codeStoreUnavailable = "store_unavailable"
	codeInternal         = "internal"
	codeNotFound         = "not_found"
	codeRateLimited      = "rate_limited"
)

func writeError(w http.ResponseWriter, status int, code, message string) {
	auth.WriteError(w, status, code, message)
}

// storeUnavailable writes 503 store_unavailable with Retry-After: 2.
func storeUnavailable(w http.ResponseWriter, message string) {
	w.Header().Set("Retry-After", "2")
	writeError(w, http.StatusServiceUnavailable, codeStoreUnavailable, message)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func notFound(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotFound, codeNotFound, "not found")
}
