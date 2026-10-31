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
	SecretPrefix       string     `json:"secret_prefix"`
	Secret             string     `json:"secret,omitempty"` // plaintext verify secret, only on create
}

func toKeyJSON(k store.APIKey) keyJSON {
	origins := k.AllowedOrigins
	if origins == nil {
		origins = []string{}
	}
	return keyJSON{ID: k.ID, Prefix: k.Prefix, Label: k.Label, AllowedOrigins: origins,
		RateLimitPerMinute: k.RateLimitPerMinute, CreatedAt: k.CreatedAt, RevokedAt: k.RevokedAt, LastUsedAt: k.LastUsedAt,
		SecretPrefix: k.SecretPrefix}
}

// handleCreateKey creates a key with a verify secret and returns both
// plaintexts exactly once.
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
	secret, secretHash, secretPrefix := auth.GenerateSecret()
	k, err := s.Store.CreateKey(r.Context(), store.NewKey{Hash: hash, Prefix: prefix, Label: req.Label,
		AllowedOrigins: origins, RateLimitPerMinute: req.RateLimitPerMinute, SecretHash: secretHash, SecretPrefix: secretPrefix})
	if err != nil {
		s.Logger.Error("server: create key failed", "err", err)
		storeUnavailable(w, "could not create key")
		return
	}
	out := toKeyJSON(k)
	out.Key = plain
	out.Secret = secret
	writeJSON(w, http.StatusCreated, out)
}

// rotatedSecretJSON is the response to a secret rotation.
type rotatedSecretJSON struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
}

// handleRotateSecret replaces a key's verify secret and returns the new
// plaintext exactly once. The old secret stops working immediately.
func (s *server) handleRotateSecret(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	secret, hash, prefix := auth.GenerateSecret()
	err := s.Store.SetKeySecret(r.Context(), id, hash, prefix)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, codeNotFound, "no such key")
	case err != nil:
		s.Logger.Error("server: set key secret failed", "err", err)
		storeUnavailable(w, "could not set key secret")
	default:
		writeJSON(w, http.StatusOK, rotatedSecretJSON{ID: id, Secret: secret})
	}
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

// probeReportJSON is the canvas-probe entropy report.
type probeReportJSON struct {
	WindowDays     int     `json:"window_days"`
	Visitors       int64   `json:"visitors"`
	DistinctProbes int64   `json:"distinct_probes"`
	Ratio          float64 `json:"ratio"`
	Verdict        string  `json:"verdict"`
}

// probeVerdict classifies the distinct-probe/visitor ratio. Too few visitors
// (including none) is insufficient_data.
func probeVerdict(visitors, distinct int64) (ratio float64, verdict string) {
	if visitors == 0 {
		return 0, "insufficient_data"
	}
	ratio = float64(distinct) / float64(visitors)
	switch {
	case visitors < store.ProbeNMin:
		return ratio, "insufficient_data"
	case ratio <= store.ProbeRLow:
		return ratio, "too_low"
	case ratio >= store.ProbeRHigh:
		return ratio, "too_unique"
	}
	return ratio, "ok"
}

// handleCanvasProbeReport reports how well a key's canvas probe discriminates
// visitors. An unknown key simply has no events.
func (s *server) handleCanvasProbeReport(w http.ResponseWriter, r *http.Request) {
	if !store.ValidUUID(r.PathValue("id")) {
		writeError(w, http.StatusNotFound, codeNotFound, "no such key")
		return
	}
	since := s.Now().Add(-store.ProbeWindowDays * 24 * time.Hour)
	visitors, distinct, err := s.Store.CanvasProbeEntropy(r.Context(), r.PathValue("id"), since)
	if err != nil {
		s.Logger.Error("server: canvas probe report failed", "err", err)
		storeUnavailable(w, "could not compute canvas probe report")
		return
	}
	ratio, verdict := probeVerdict(visitors, distinct)
	writeJSON(w, http.StatusOK, probeReportJSON{WindowDays: store.ProbeWindowDays, Visitors: visitors,
		DistinctProbes: distinct, Ratio: ratio, Verdict: verdict})
}

// widgetSummaryJSON is the per-key widget correlation summary.
type widgetSummaryJSON struct {
	WindowDays      int   `json:"window_days"`
	Reports         int64 `json:"reports"`
	Matched         int64 `json:"matched"`
	Unmatched       int64 `json:"unmatched"`
	EventsUnmatched int64 `json:"events_unmatched"`
	IPMismatch      int64 `json:"ip_mismatch"`
	JA4Mismatch     int64 `json:"ja4_mismatch"`
	JA4Unknown      int64 `json:"ja4_unknown"`
	UAMismatch      int64 `json:"ua_mismatch"`
	Pass            int64 `json:"pass"`
	Inconclusive    int64 `json:"inconclusive"`
	PowFailed       int64 `json:"pow_failed"`
	Verified        int64 `json:"verified"`
	Replayed        int64 `json:"replayed"`

	Interactive       int64 `json:"interactive"`
	InteractiveFailed int64 `json:"interactive_failed"`
	// InteractionSignals counts the signals that fired on interactive_failed
	// reports; always present, {} when none.
	InteractionSignals map[string]int64 `json:"interaction_signals"`
}

// handleWidgetSummary reports how a key's widget reports correlate with its
// /thumbmark events. An unknown key simply has no reports.
func (s *server) handleWidgetSummary(w http.ResponseWriter, r *http.Request) {
	since := s.Now().Add(-store.ProbeWindowDays * 24 * time.Hour)
	sum, err := s.Store.WidgetSummary(r.Context(), r.PathValue("id"), since, widgetMatchWindow)
	if err != nil {
		s.Logger.Error("server: widget summary failed", "err", err)
		storeUnavailable(w, "could not compute widget summary")
		return
	}
	signals := sum.InteractionSignals
	if signals == nil {
		signals = map[string]int64{}
	}
	writeJSON(w, http.StatusOK, widgetSummaryJSON{WindowDays: store.ProbeWindowDays, Reports: sum.Reports,
		Matched: sum.Matched, Unmatched: sum.Unmatched, EventsUnmatched: sum.EventsUnmatched,
		IPMismatch: sum.IPMismatch, JA4Mismatch: sum.JA4Mismatch, JA4Unknown: sum.JA4Unknown, UAMismatch: sum.UAMismatch,
		Pass: sum.Pass, Inconclusive: sum.Inconclusive, PowFailed: sum.PowFailed, Verified: sum.Verified, Replayed: sum.Replayed,
		Interactive: sum.Interactive, InteractiveFailed: sum.InteractiveFailed, InteractionSignals: signals})
}
