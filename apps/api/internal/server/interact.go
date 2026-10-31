package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"nazr/api/internal/auth"
	"nazr/api/internal/fingerprint"
	"nazr/api/internal/interaction"
	"nazr/api/internal/store"
	"nazr/api/internal/widgettoken"
)

// Interactive step verdicts (spec section 3.3).
const (
	verdictInteractive       = "interactive"
	verdictInteractiveFailed = "interactive_failed"
)

// interactBody is a decoded, bounds-checked /widget/interact body.
type interactBody struct {
	challenge, pow string
	trace          interaction.Trace
}

// parseInteract applies the interact bounds: challenge 1..512 bytes, pow
// 1..32 ASCII digits, trace an object that decodes into a valid Trace.
// Unknown trace keys are ignored.
func parseInteract(raw map[string]any) (interactBody, bool) {
	var b interactBody
	var ok bool
	if b.challenge, ok = raw["challenge"].(string); !ok || len(b.challenge) < 1 || len(b.challenge) > 512 {
		return b, false
	}
	if b.pow, ok = raw["pow"].(string); !ok || !validPow(b.pow) {
		return b, false
	}
	tm, ok := raw["trace"].(map[string]any)
	if !ok {
		return b, false
	}
	tb, err := json.Marshal(tm)
	if err != nil || json.Unmarshal(tb, &b.trace) != nil || !b.trace.Valid() {
		return b, false
	}
	return b, true
}

// storedInteraction is the report's interaction column: the trace fields,
// the rules that fired and the click delay.
type storedInteraction struct {
	interaction.Trace
	Signals   map[string]bool `json:"signals"`
	ElapsedMS int             `json:"elapsed_ms"`
}

// handleInteract answers the frame's interactive step. Like the report, the
// response is always 200 JSON after the middleware.
func (s *server) handleInteract(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.processInteract(r))
}

// processInteract verifies the interactive-stage challenge and its
// proof-of-work, scores the trace and upgrades the inconclusive report once.
// Only a successful upgrade with a passing trace yields a token.
func (s *server) processInteract(r *http.Request) widgetOutcome {
	invalid := widgetOutcome{Verdict: verdictInvalid}
	ctx := r.Context()
	key := auth.KeyFromContext(ctx)
	raw, err := fingerprint.Decode(r.Body, int64(s.Cfg.BodyLimit))
	if key == nil || err != nil || s.Signing == nil {
		return invalid
	}
	body, ok := parseInteract(raw)
	if !ok {
		return invalid
	}
	now := s.Now().UTC()
	ch, err := widgettoken.ParseChallenge(body.challenge, func(kid string) ([]byte, bool) {
		k, ok := s.Signing.Lookup(kid)
		return k.Secret, ok
	}, now)
	if err != nil || ch.Stage != widgettoken.StageInteractive {
		return invalid
	}
	if !widgettoken.VerifyPoW(ch.ID, body.pow, ch.Bits) {
		return invalid
	}

	passed, signals := interaction.Score(body.trace)
	fired := map[string]bool{}
	for name, f := range signals {
		if f {
			fired[name] = true
		}
	}
	verdict, issuedAt := verdictInteractiveFailed, (*time.Time)(nil)
	if passed {
		verdict, issuedAt = verdictInteractive, &now
	}
	summary, err := marshalJSON(storedInteraction{Trace: body.trace, Signals: fired,
		ElapsedMS: body.trace.ClickMS - body.trace.ShownMS})
	if err != nil {
		return invalid
	}
	// The conditional update is the single-use check, so it precedes issuance.
	uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if _, err := s.Store.UpgradeWidgetReport(uctx, key.ID, ch.ID, verdict, summary, issuedAt); err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.Logger.Error("server: upgrade widget report failed", "err", err, "request_id", requestIDFrom(ctx))
		}
		return invalid
	}
	if !passed {
		return widgetOutcome{Verdict: verdict}
	}
	return widgetOutcome{Verdict: verdict, Token: s.signWidgetToken(r, key.ID, ch, now, verdictInteractive)}
}
