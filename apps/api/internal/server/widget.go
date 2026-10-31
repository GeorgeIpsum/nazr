package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"nazr/api/internal/auth"
	"nazr/api/internal/classify"
	"nazr/api/internal/fingerprint"
	"nazr/api/internal/ipintel"
	"nazr/api/internal/store"
	"nazr/api/internal/widgettoken"

	"github.com/oklog/ulid/v2"
)

// widgetMatchWindow is how far apart a widget report and a /thumbmark event
// with the same nonce may be and still correlate.
const widgetMatchWindow = 10 * time.Minute

const (
	widgetJSType     = "text/javascript; charset=utf-8"
	widgetFrameRules = "; default-src 'none'; script-src 'self'; connect-src 'self'; worker-src 'self'"
)

// widgetAssets is the built widget, loaded into memory once at startup.
type widgetAssets struct {
	loader     []byte
	loaderETag string
	bundleName string
	bundle     []byte
	workerName string
	worker     []byte
	frame      *template.Template
}

// newWidgetAssets loads loader.js, the frame bundle named by manifest.json
// the proof-of-work worker and the frame.html template from fsys.
func newWidgetAssets(fsys fs.FS) (*widgetAssets, error) {
	loader, err := fs.ReadFile(fsys, "loader.js")
	if err != nil {
		return nil, err
	}
	mb, err := fs.ReadFile(fsys, "manifest.json")
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Frame  string `json:"frame"`
		Worker string `json:"worker"`
	}
	if err := json.Unmarshal(mb, &manifest); err != nil {
		return nil, fmt.Errorf("manifest.json: %w", err)
	}
	bundle, err := fs.ReadFile(fsys, manifest.Frame)
	if err != nil {
		return nil, err
	}
	if manifest.Worker == "" {
		return nil, errors.New("manifest.json: no worker entry")
	}
	worker, err := fs.ReadFile(fsys, manifest.Worker)
	if err != nil {
		return nil, err
	}
	html, err := fs.ReadFile(fsys, "frame.html")
	if err != nil {
		return nil, err
	}
	tmpl, err := template.New("frame.html").Parse(string(html))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(loader)
	return &widgetAssets{
		loader:     loader,
		loaderETag: `"` + hex.EncodeToString(sum[:])[:16] + `"`,
		bundleName: manifest.Frame,
		bundle:     bundle,
		workerName: manifest.Worker,
		worker:     worker,
		frame:      tmpl,
	}, nil
}

// handleWidgetLoader serves loader.js. Its path is fixed, so it is cached
// briefly and revalidated by ETag rather than marked immutable.
func (s *server) handleWidgetLoader(wa *widgetAssets) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Type", widgetJSType)
		h.Set("Cache-Control", "public, max-age=300")
		h.Set("ETag", wa.loaderETag)
		http.ServeContent(w, r, "loader.js", time.Time{}, bytes.NewReader(wa.loader))
	}
}

// handleWidgetBundle serves the content-hashed frame bundle or worker named
// by the manifest; any other name is 404.
func (s *server) handleWidgetBundle(wa *widgetAssets) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name, body := r.PathValue("bundle"), wa.bundle
		switch name {
		case wa.bundleName:
		case wa.workerName:
			body = wa.worker
		default:
			notFound(w, r)
			return
		}
		h := w.Header()
		h.Set("Content-Type", widgetJSType)
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(body))
	}
}

// frameData is what frame.html is rendered with.
type frameData struct {
	Bundle, Worker, Challenge, Origin string
	PowBits                           int
}

// handleWidgetJWKS publishes the public signing keys.
func (s *server) handleWidgetJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=3600")
	writeJSON(w, http.StatusOK, s.Signing.JWKS())
}

// handleWidgetFrame renders the frame for the key in ?k=, allowing it to be
// framed only by the key's allowed origins. An unknown, malformed, missing or
// revoked key is 403 with an empty body.
func (s *server) handleWidgetFrame(wa *widgetAssets) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		k, err := auth.LookupKey(r.Context(), s.KeyCache, s.Store, r.URL.Query().Get("k"))
		if err != nil {
			s.Logger.Error("server: widget key lookup failed", "err", err, "request_id", requestIDFrom(r.Context()))
			storeUnavailable(w, "key store unavailable")
			return
		}
		if k == nil || k.RevokedAt != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var active widgettoken.Key
		ok := false
		if s.Signing != nil {
			active, ok = s.Signing.Active(s.Now())
		}
		if !ok {
			s.Logger.Error("server: no active widget signing key", "request_id", requestIDFrom(r.Context()))
			w.Header().Set("Retry-After", "2")
			writeError(w, http.StatusServiceUnavailable, codeSigningUnavailable, "widget signing unavailable")
			return
		}
		origin := widgettoken.EmbeddingOrigin(r.Header.Get("Referer"))
		ch := widgettoken.MintChallenge(active.Secret, widgettoken.Challenge{
			ID: ulid.Make().String(), Expires: s.Now().Add(widgetMatchWindow).Unix(), Bits: s.Cfg.PowBits,
			Kid: active.Kid, Origin: origin, Key: k.ID,
		})
		var buf bytes.Buffer
		data := frameData{Bundle: wa.bundleName, Worker: wa.workerName, Challenge: ch,
			Origin: origin, PowBits: s.Cfg.PowBits}
		if err := wa.frame.Execute(&buf, data); err != nil {
			s.Logger.Error("server: widget frame template failed", "err", err, "request_id", requestIDFrom(r.Context()))
			writeError(w, http.StatusInternalServerError, codeInternal, "internal server error")
			return
		}
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "frame-ancestors "+frameAncestors(k.AllowedOrigins)+widgetFrameRules)
		_, _ = w.Write(buf.Bytes())
	}
}

// frameAncestors maps a key's allowed origins to a CSP frame-ancestors
// source list: "*" when the list is empty or contains "*".
func frameAncestors(origins []string) string {
	var out []string
	for _, o := range origins {
		o = strings.TrimSpace(o)
		if o == "*" {
			return "*"
		}
		if o != "" {
			out = append(out, o)
		}
	}
	if len(out) == 0 {
		return "*"
	}
	return strings.Join(out, " ")
}

// validNonce reports whether s is 1..64 printable ASCII bytes (0x20..0x7e);
// anything else is treated as an absent nonce.
func validNonce(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// Widget report verdicts (spec section 3.3).
const (
	verdictPass         = "pass"
	verdictInconclusive = "inconclusive"
	verdictPowFailed    = "pow_failed"
	verdictInvalid      = "invalid"
)

// widgetReportOptions is the frame client's stabilization: it runs in an
// iframe and may be in a private window.
var widgetReportOptions = fingerprint.Options{Stabilize: []string{"private", "iframe"}}

// widgetOutcome is the /widget/report response.
type widgetOutcome struct {
	Verdict string `json:"verdict"`
	Token   string `json:"token,omitempty"`
	// Interactive offers the second, harder challenge to an inconclusive
	// visitor whose reputation alone held the pass back.
	Interactive *interactiveOffer `json:"interactive,omitempty"`
}

// interactiveOffer is the stage "interactive" challenge the frame redeems
// after the interactive step.
type interactiveOffer struct {
	Challenge string `json:"challenge"`
	Bits      int    `json:"bits"`
	// TTLMS is the challenge's remaining life in milliseconds by the
	// server's clock, so the frame can time it out without trusting its own.
	TTLMS int64 `json:"ttl_ms"`
}

// interactiveOffer mints the interactive-stage challenge for ch with the
// secret of the key that signed ch: same id, expiry, signing key, API key and
// origin, at the configured extra difficulty. now is the handler's clock.
func (s *server) interactiveOffer(ch widgettoken.Challenge, secret []byte, now time.Time) *interactiveOffer {
	next := ch
	next.Bits = s.Cfg.PowBits + s.Cfg.WidgetInteractiveExtraBits
	next.Stage = widgettoken.StageInteractive
	ttl := max(ch.Expires*1000-now.UnixMilli(), 0)
	return &interactiveOffer{Challenge: widgettoken.MintChallenge(secret, next), Bits: next.Bits, TTLMS: ttl}
}

// widgetReportBody is a decoded, bounds-checked report.
type widgetReportBody struct {
	challenge, pow, clientHash string
	components                 map[string]any
}

// parseWidgetReport applies the report bounds: challenge 1..512 bytes, pow
// 1..32 ASCII digits, components an object, clientHash absent or 1..64 hex.
func parseWidgetReport(raw map[string]any) (widgetReportBody, bool) {
	var b widgetReportBody
	var ok bool
	if b.challenge, ok = raw["challenge"].(string); !ok || len(b.challenge) < 1 || len(b.challenge) > 512 {
		return b, false
	}
	if b.pow, ok = raw["pow"].(string); !ok || !validPow(b.pow) {
		return b, false
	}
	if b.components, ok = raw["components"].(map[string]any); !ok {
		return b, false
	}
	if v, present := raw["clientHash"]; present {
		if b.clientHash, ok = v.(string); !ok || !validCanvasProbe(b.clientHash) {
			return b, false
		}
	}
	return b, true
}

// validPow reports whether s is 1..32 ASCII digits.
func validPow(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// handleWidgetReport answers the frame's report with a verdict and, on pass,
// a token. The key's origin scoping is skipped (the frame runs on nazr's
// origin); after the middleware the response is always 200 JSON.
func (s *server) handleWidgetReport(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.processWidgetReport(r))
}

// processWidgetReport verifies the challenge and proof-of-work, classifies
// the frame's request, stores the report keyed by the challenge id and signs
// a token on pass. Only a stored, first-use pass yields a token.
func (s *server) processWidgetReport(r *http.Request) widgetOutcome {
	invalid := widgetOutcome{Verdict: verdictInvalid}
	ctx := r.Context()
	key := auth.KeyFromContext(ctx)
	raw, err := fingerprint.Decode(r.Body, int64(s.Cfg.BodyLimit))
	if key == nil || err != nil || s.Signing == nil {
		return invalid
	}
	body, ok := parseWidgetReport(raw)
	if !ok {
		return invalid
	}
	now := s.Now().UTC()
	ch, err := widgettoken.ParseChallenge(body.challenge, func(kid string) ([]byte, bool) {
		k, ok := s.Signing.Lookup(kid)
		return k.Secret, ok
	}, now)
	// A staged challenge is redeemed at the interactive endpoint only.
	if err != nil || ch.Stage != "" {
		return invalid
	}
	// A challenge is redeemed under the key it was minted for. Challenges
	// minted before the binding carry no key and expire within the window.
	if ch.Key != "" && ch.Key != key.ID {
		return invalid
	}
	// The difficulty is the challenge's, which nazr minted and MACed.
	powOK := widgettoken.VerifyPoW(ch.ID, body.pow, ch.Bits)

	addr, view := s.clientIP(r)
	s.countParseErrors(ctx, view)
	var lookup ipintel.Lookup
	if s.Intel != nil && addr.IsValid() {
		lookup = s.Intel.Lookup(addr)
	}
	sc, ja4 := serverComponents(r, view, requestOrder(r), s.Cfg, addr, lookup)
	merged := fingerprint.Merge(body.components, filterServer(sc, body.components, widgetReportOptions))
	in, h2fpStr := s.classifyInput(r, view, body.components, lookup, ja4)
	cls := classify.Classify(in)
	delete(cls.Signals, "canvas_probe_anomaly") // never scored here

	verdict := verdictInconclusive
	switch {
	case !powOK:
		verdict = verdictPowFailed
	case !cls.Bot && cls.DangerLevel <= s.Cfg.WidgetPassMaxDanger:
		verdict = verdictPass
	}

	rep := store.WidgetReport{
		ID: ch.ID, APIKeyID: key.ID, Nonce: ch.ID, Thumbmark: fingerprint.Hash(merged),
		ClientHash: body.clientHash, IP: s.storedIP(addr), JA4: ja4, H2FP: h2fpStr, UserAgent: in.UserAgent,
		Components: s.storedComponents(body.components, sc), CreatedAt: now,
		Hostname: ch.Origin, PowOK: powOK, Verdict: verdict,
	}
	rep.Classification, _ = marshalJSON(classificationInfo{Tor: cls.Tor, VPN: cls.VPN, Bot: cls.Bot,
		Datacenter: cls.Datacenter, PrivateRelay: cls.PrivateRelay, DangerLevel: cls.DangerLevel})
	rep.Signals, _ = marshalJSON(cls.Signals)
	if addr.IsValid() {
		rep.IPHash = ipintel.Identifier(addr, s.Cfg.IPHashSalt)
	}
	if verdict == verdictPass {
		rep.TokenIssuedAt = &now
	}
	// The insert is the single-use check, so it precedes issuance.
	ictx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if err := s.Store.InsertWidgetReport(ictx, rep); err != nil {
		if errors.Is(err, store.ErrDuplicateReport) {
			return invalid
		}
		s.Logger.Error("server: insert widget report failed", "err", err, "request_id", requestIDFrom(ctx))
		if verdict == verdictPass {
			// A store outage must not mint credentials.
			verdict = verdictInconclusive
		}
		return widgetOutcome{Verdict: verdict}
	}
	if verdict != verdictPass {
		out := widgetOutcome{Verdict: verdict}
		if verdict == verdictInconclusive && !cls.Bot && s.Cfg.WidgetInteractive {
			if k, ok := s.Signing.Lookup(ch.Kid); ok {
				out.Interactive = s.interactiveOffer(ch, k.Secret, now)
			}
		}
		return out
	}
	return widgetOutcome{Verdict: verdict, Token: s.signWidgetToken(r, key.ID, ch, now, verdictPass)}
}

// signWidgetToken signs a pass token for ch with the key active at now, or
// returns "" (logged) when there is no active key or signing fails.
func (s *server) signWidgetToken(r *http.Request, keyID string, ch widgettoken.Challenge, now time.Time, verdict string) string {
	rid := requestIDFrom(r.Context())
	active, ok := s.Signing.Active(now)
	if !ok {
		s.Logger.Error("server: no active widget signing key", "request_id", rid)
		return ""
	}
	iss := s.Cfg.WidgetIssuer
	if iss == "" {
		iss = "https://" + r.Host
	}
	tok, err := widgettoken.Sign(active.Private, active.Kid, widgettoken.Claims{
		Issuer: iss, Audience: keyID, ID: ch.ID, IssuedAt: now.Unix(),
		Expires: now.Add(s.Cfg.WidgetTokenTTL).Unix(), Hostname: ch.Origin, Verdict: verdict,
	})
	if err != nil {
		s.Logger.Error("server: sign widget token failed", "err", err, "request_id", rid)
		return ""
	}
	return tok
}
