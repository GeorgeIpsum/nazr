package server

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"nazr/api/internal/auth"
	"nazr/api/internal/ipintel"
	"nazr/api/internal/store"
	"nazr/api/internal/widgettoken"
)

// Siteverify error codes.
const (
	svInvalidSecret    = "invalid-secret"
	svInvalidToken     = "invalid-token"
	svTokenExpired     = "token-expired"
	svReplayed         = "replayed"
	svRemoteIPMismatch = "remoteip-mismatch"
)

// siteverifyRequest is the host backend's verification request.
type siteverifyRequest struct {
	Secret   string `json:"secret"`
	Token    string `json:"token"`
	RemoteIP string `json:"remoteip"`
}

// siteverifyResponse is the verification result. Failures carry only
// success and one error code, except remoteip-mismatch, which keeps the rest.
type siteverifyResponse struct {
	Success        bool                `json:"success"`
	ChallengeTS    string              `json:"challenge_ts,omitempty"`
	Hostname       string              `json:"hostname,omitempty"`
	Verdict        string              `json:"verdict,omitempty"`
	Correlation    *correlationJSON    `json:"correlation,omitempty"`
	Classification *classificationInfo `json:"classification,omitempty"`
	Signals        map[string]bool     `json:"signals,omitempty"`
	ErrorCodes     []string            `json:"error_codes"`
}

// correlationJSON is the report's Phase 1 correlation; a nil match is unknown.
type correlationJSON struct {
	Matched  bool  `json:"matched"`
	IPMatch  *bool `json:"ip_match"`
	JA4Match *bool `json:"ja4_match"`
	UAMatch  *bool `json:"ua_match"`
}

func siteverifyFailure(code string) siteverifyResponse {
	return siteverifyResponse{ErrorCodes: []string{code}}
}

// handleSiteverify verifies a widget token for the key owning the secret and
// spends it once. Token problems are 200 with success false; a bad secret is
// 401, a bad request 400.
func (s *server) handleSiteverify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rid := requestIDFrom(ctx)
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusBadRequest, codeBadRequest, "Content-Type must be application/json")
		return
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		if isTooLarge(err) {
			writeError(w, http.StatusRequestEntityTooLarge, codePayloadTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, codeBadRequest, "unreadable body")
		return
	}
	var req siteverifyRequest
	if err := json.Unmarshal(data, &req); err != nil || req.Secret == "" || req.Token == "" {
		writeError(w, http.StatusBadRequest, codeBadRequest, `body must be a JSON object with "secret" and "token"`)
		return
	}

	key, err := s.Store.FindKeyBySecretHash(ctx, auth.HashKey(req.Secret))
	if err != nil {
		s.Logger.Error("server: siteverify key lookup failed", "err", err, "request_id", rid)
		storeUnavailable(w, "key lookup unavailable")
		return
	}
	if key == nil || key.RevokedAt != nil {
		writeJSON(w, http.StatusUnauthorized, siteverifyFailure(svInvalidSecret))
		return
	}
	if !s.allowSiteverify(w, r, key) {
		return
	}

	claims, err := widgettoken.Parse(req.Token, func(kid string) (*ecdsa.PublicKey, bool) {
		k, ok := s.Signing.Lookup(kid)
		if !ok {
			return nil, false
		}
		return &k.Private.PublicKey, true
	})
	if err != nil || claims.Audience != key.ID {
		writeJSON(w, http.StatusOK, siteverifyFailure(svInvalidToken))
		return
	}
	// Expiry is checked before the row is spent, so an expired token
	// cannot burn it.
	if s.Now().Unix() >= claims.Expires {
		writeJSON(w, http.StatusOK, siteverifyFailure(svTokenExpired))
		return
	}

	row, err := s.Store.MarkWidgetVerified(ctx, key.ID, claims.ID)
	switch {
	case errors.Is(err, store.ErrAlreadyVerified):
		writeJSON(w, http.StatusOK, siteverifyFailure(svReplayed))
		return
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusOK, siteverifyFailure(svInvalidToken))
		return
	case err != nil:
		s.Logger.Error("server: siteverify mark verified failed", "err", err, "request_id", rid)
		storeUnavailable(w, "could not verify token")
		return
	}

	corr, err := s.Store.WidgetReportCorrelation(ctx, key.ID, claims.ID, widgetMatchWindow)
	if err != nil {
		s.Logger.Error("server: siteverify correlation failed", "err", err, "request_id", rid)
		storeUnavailable(w, "could not verify token")
		return
	}

	out := siteverifyResponse{Success: true, Hostname: row.Hostname, Verdict: row.Verdict, ErrorCodes: []string{},
		Correlation: &correlationJSON{Matched: corr.Matched, IPMatch: corr.IPMatch, JA4Match: corr.JA4Match, UAMatch: corr.UAMatch}}
	if row.TokenIssuedAt != nil {
		out.ChallengeTS = row.TokenIssuedAt.UTC().Format(time.RFC3339)
	}
	if len(row.Classification) > 0 && string(row.Classification) != "null" {
		var c classificationInfo
		if json.Unmarshal(row.Classification, &c) == nil {
			out.Classification = &c
		}
	}
	if len(row.Signals) > 0 {
		_ = json.Unmarshal(row.Signals, &out.Signals)
	}
	if req.RemoteIP != "" && !s.remoteIPMatches(req.RemoteIP, row) {
		out.Success = false
		out.ErrorCodes = []string{svRemoteIPMismatch}
	}
	writeJSON(w, http.StatusOK, out)
}

// allowSiteverify applies the key's rate limit like auth.Middleware: the
// key's own rate else the default, failing open on a limiter error. A denied
// request is answered 429 and false is returned.
func (s *server) allowSiteverify(w http.ResponseWriter, r *http.Request, key *store.APIKey) bool {
	rate := s.Cfg.DefaultRateLimit
	if key.RateLimitPerMinute != nil {
		rate = *key.RateLimitPerMinute
	}
	ok, retry, err := s.Limiter.Allow(r.Context(), key.ID, rate)
	if err != nil {
		s.Logger.Warn("server: rate limiter failed, allowing siteverify", "err", err, "request_id", requestIDFrom(r.Context()))
		return true
	}
	if !ok {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(retry.Seconds())))))
		writeError(w, http.StatusTooManyRequests, codeRateLimited, "rate limit exceeded")
		return false
	}
	return true
}

// remoteIPMatches compares the caller-supplied visitor IP with the report's
// stored IP, or with its salted identifier when only the hash is stored. An
// unparseable remoteip or a report with neither never matches.
func (s *server) remoteIPMatches(remote string, row store.WidgetReport) bool {
	addr, err := netip.ParseAddr(remote)
	if err != nil {
		return false
	}
	addr = addr.WithZone("").Unmap()
	if row.IP != nil {
		return row.IP.Unmap() == addr
	}
	return row.IPHash != "" && ipintel.Identifier(addr, s.Cfg.IPHashSalt) == row.IPHash
}
