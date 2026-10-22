package server

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"strconv"

	"nazr/api/internal/auth"
)

// maxLogBody caps a /log body; client debug logs are small.
const maxLogBody = 16 << 10

// handleLog accepts client debug logs. It is unauthenticated and rate limited
// per client IP at NAZR_DEFAULT_RATE_LIMIT (429), and bodies over 16 KiB are
// rejected (413). Otherwise the answer is 204: the body is discarded unless
// NAZR_LOG_RETENTION is set; then valid JSON bodies are stored, tied to the
// API key when a valid, unrevoked x-api-key accompanies them (resolved
// through the key cache).
func (s *server) handleLog(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if s.Limiter != nil {
		addr, _ := s.clientIP(r)
		ok, retry, err := s.Limiter.Allow(ctx, "log:"+addr.String(), s.Cfg.DefaultRateLimit)
		if err != nil {
			s.Logger.Warn("server: log rate limiter failed, allowing", "err", err)
		} else if !ok {
			w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(retry.Seconds())))))
			writeError(w, http.StatusTooManyRequests, codeRateLimited, "rate limit exceeded")
			return
		}
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxLogBody))
	if err != nil {
		if isTooLarge(err) {
			writeError(w, http.StatusRequestEntityTooLarge, codePayloadTooLarge, "log body exceeds "+strconv.Itoa(maxLogBody)+" bytes")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	defer w.WriteHeader(http.StatusNoContent)
	if s.Cfg.LogRetention <= 0 || !json.Valid(data) {
		return
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	var keyID *string
	if plain := r.Header.Get("x-api-key"); plain != "" {
		k, err := auth.LookupKey(sctx, s.KeyCache, s.Store, plain)
		if err != nil {
			s.Logger.Warn("server: log key lookup failed", "err", err, "request_id", requestIDFrom(ctx))
		} else if k != nil && k.RevokedAt == nil {
			id := k.ID
			keyID = &id
		}
	}
	if err := s.Store.InsertClientLog(sctx, keyID, json.RawMessage(data)); err != nil {
		s.Logger.Warn("server: insert client log failed", "err", err, "request_id", requestIDFrom(ctx))
	}
}
