package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"nazr/api/internal/auth"
	"nazr/api/internal/store"
)

type createKeyRequest struct {
	Label              string   `json:"label"`
	AllowedOrigins     []string `json:"allowed_origins"`
	RateLimitPerMinute *int     `json:"rate_limit_per_minute"`
}

type keyJSON struct {
	ID                 string     `json:"id"`
	Key                string     `json:"key,omitempty"` // plaintext, only on create
	Prefix             string     `json:"prefix"`
	Label              string     `json:"label"`
	AllowedOrigins     []string   `json:"allowed_origins"`
	RateLimitPerMinute *int       `json:"rate_limit_per_minute"`
	CreatedAt          time.Time  `json:"created_at"`
	RevokedAt          *time.Time `json:"revoked_at"`
	LastUsedAt         *time.Time `json:"last_used_at"`
}

func toKeyJSON(k store.APIKey) keyJSON {
	origins := k.AllowedOrigins
	if origins == nil {
		origins = []string{}
	}
	return keyJSON{ID: k.ID, Prefix: k.Prefix, Label: k.Label, AllowedOrigins: origins,
		RateLimitPerMinute: k.RateLimitPerMinute, CreatedAt: k.CreatedAt, RevokedAt: k.RevokedAt, LastUsedAt: k.LastUsedAt}
}

// handleCreateKey creates a key and returns its plaintext exactly once.
func (s *server) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(s.Cfg.BodyLimit)))
	if err != nil {
		if isTooLarge(err) {
			writeError(w, http.StatusRequestEntityTooLarge, codePayloadTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, codeBadRequest, "unreadable body")
		return
	}
	var req createKeyRequest
	if err := json.Unmarshal(data, &req); err != nil {
		writeError(w, http.StatusBadRequest, codeBadRequest, "body must be a JSON object")
		return
	}
	req.Label = strings.TrimSpace(req.Label)
	if req.Label == "" {
		writeError(w, http.StatusBadRequest, codeBadRequest, `"label" is required`)
		return
	}
	if req.RateLimitPerMinute != nil && *req.RateLimitPerMinute <= 0 {
		writeError(w, http.StatusBadRequest, codeBadRequest, `"rate_limit_per_minute" must be positive`)
		return
	}
	if err := auth.ValidateOrigins(req.AllowedOrigins); err != nil {
		writeError(w, http.StatusBadRequest, codeBadRequest, `"allowed_origins": `+err.Error())
		return
	}
	var origins []string
	for _, o := range req.AllowedOrigins {
		if o = strings.TrimSpace(o); o != "" && !slices.Contains(origins, o) {
			origins = append(origins, o)
		}
	}
	plain, hash, prefix := auth.GenerateKey()
	k, err := s.Store.CreateKey(r.Context(), store.NewKey{Hash: hash, Prefix: prefix, Label: req.Label,
		AllowedOrigins: origins, RateLimitPerMinute: req.RateLimitPerMinute})
	if err != nil {
		s.Logger.Error("server: create key failed", "err", err)
		storeUnavailable(w, "could not create key")
		return
	}
	out := toKeyJSON(k)
	out.Key = plain
	writeJSON(w, http.StatusCreated, out)
}

// handleListKeys lists keys (never their secrets).
func (s *server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	ks, err := s.Store.ListKeys(r.Context())
	if err != nil {
		s.Logger.Error("server: list keys failed", "err", err)
		storeUnavailable(w, "could not list keys")
		return
	}
	out := make([]keyJSON, 0, len(ks))
	for _, k := range ks {
		out = append(out, toKeyJSON(k))
	}
	writeJSON(w, http.StatusOK, out)
}

// handleRevokeKey revokes a key by ID. The key cache is keyed by hash, which
// is not known here, so a cached entry is not invalidated: revocation reaches
// every replica within the cache TTL.
func (s *server) handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	err := s.Store.RevokeKey(r.Context(), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, codeNotFound, "no such key")
	case err != nil:
		s.Logger.Error("server: revoke key failed", "err", err)
		storeUnavailable(w, "could not revoke key")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
