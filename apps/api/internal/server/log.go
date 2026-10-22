package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"nazr/api/internal/auth"
)

// handleLog accepts client debug logs. The body is discarded unless
// NAZR_LOG_RETENTION is set; then valid JSON bodies are stored, tied to the
// API key when a valid, unrevoked x-api-key accompanies them. No
// authentication is required and the answer is always 204.
func (s *server) handleLog(w http.ResponseWriter, r *http.Request) {
	defer w.WriteHeader(http.StatusNoContent)
	if s.Cfg.LogRetention <= 0 {
		_, _ = io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, int64(s.Cfg.BodyLimit)))
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(s.Cfg.BodyLimit)))
	if err != nil || !json.Valid(data) {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), storeTimeout)
	defer cancel()
	var keyID *string
	if plain := strings.TrimSpace(r.Header.Get("x-api-key")); plain != "" {
		if k, err := s.Store.FindKeyByHash(ctx, auth.HashKey(plain)); err == nil && k != nil && k.RevokedAt == nil {
			id := k.ID
			keyID = &id
		}
	}
	if err := s.Store.InsertClientLog(ctx, keyID, json.RawMessage(data)); err != nil {
		s.Logger.Warn("server: insert client log failed", "err", err, "request_id", requestIDFrom(r.Context()))
	}
}
