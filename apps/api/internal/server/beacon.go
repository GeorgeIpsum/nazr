package server

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"

	"nazr/api/internal/ua"
)

type beaconBody struct {
	UA        string `json:"ua"`
	Thumbmark string `json:"thumbmark"`
	JA4       string `json:"ja4"`
	JA4Source string `json:"ja4_source"`
}

// handleBeacon records a (JA4, UA family) observation. It is sent with
// sendBeacon (no custom headers), so it is unauthenticated and rate limited
// per client IP at NAZR_DEFAULT_RATE_LIMIT. Malformed bodies are ignored:
// the answer is 204 unless the limiter rejects the request (429).
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
	if ja4 != "" && strings.TrimSpace(b.UA) != "" {
		family := ua.Family(b.UA)
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
		if err := s.Store.RecordUAJA4(sctx, ja4, family, s.Now().UTC()); err != nil {
			s.Logger.Warn("server: record ua/ja4 observation failed", "err", err, "request_id", requestIDFrom(ctx))
		}
		cancel()
	}
	w.WriteHeader(http.StatusNoContent)
}
