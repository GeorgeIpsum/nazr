package server

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"nazr/api/internal/ipintel"
	"nazr/api/internal/ua"
)

// beaconEventWindow is how recent a matching /thumbmark event must be for a
// beacon to count.
const beaconEventWindow = 10 * time.Minute

type beaconBody struct {
	UA        string `json:"ua"`
	Thumbmark string `json:"thumbmark"`
	JA4       string `json:"ja4"`
	JA4Source string `json:"ja4_source"`
}

// handleBeacon records a (JA4, UA family) observation. It is sent with
// sendBeacon (no custom headers), so it is unauthenticated and rate limited
// per client IP at NAZR_DEFAULT_RATE_LIMIT. To make seeding the corpus
// harder, an observation is recorded only when the same client IP produced a
// /thumbmark event with the body's thumbmark in the last 10 minutes.
// Malformed or unmatched bodies are ignored: the answer is 204 unless the
// limiter rejects the request (429).
func (s *server) handleBeacon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	addr, view := s.clientIP(r)
	if s.Limiter != nil {
		ok, retry, err := s.Limiter.Allow(ctx, "beacon:"+addr.String(), s.Cfg.DefaultRateLimit)
		if err != nil {
			s.Logger.Warn("server: beacon rate limiter failed, allowing", "err", err)
		} else if !ok {
			w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(retry.Seconds())))))
			writeError(w, http.StatusTooManyRequests, codeRateLimited, "rate limit exceeded")
			return
		}
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(s.Cfg.BodyLimit)))
	var b beaconBody
	if err != nil || json.Unmarshal(data, &b) != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	ja4 := ""
	switch {
	case view.TLS != nil && view.TLS.JA4 != "":
		ja4 = view.TLS.JA4
	case proxiedJA4(r, s.Cfg) != "":
		ja4 = proxiedJA4(r, s.Cfg)
	default:
		ja4 = strings.TrimSpace(b.JA4)
	}
	tm := strings.TrimSpace(b.Thumbmark)
	if ja4 != "" && strings.TrimSpace(b.UA) != "" && tm != "" && addr.IsValid() {
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
		defer cancel()
		now := s.Now().UTC()
		seen, err := s.Store.HasRecentEvent(sctx, ipintel.Identifier(addr, s.Cfg.IPHashSalt), tm, now.Add(-beaconEventWindow))
		switch {
		case err != nil:
			s.Logger.Warn("server: beacon event check failed", "err", err, "request_id", requestIDFrom(ctx))
		case seen:
			if err := s.Store.RecordUAJA4(sctx, ja4, ua.Family(b.UA), now); err != nil {
				s.Logger.Warn("server: record ua/ja4 observation failed", "err", err, "request_id", requestIDFrom(ctx))
			}
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
