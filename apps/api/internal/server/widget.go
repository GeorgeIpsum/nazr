package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"nazr/api/internal/auth"
	"nazr/api/internal/fingerprint"
	"nazr/api/internal/h2fp"
	"nazr/api/internal/ipintel"
	"nazr/api/internal/store"
)

// widgetMatchWindow is how far apart a widget report and a /thumbmark event
// with the same nonce may be and still correlate.
const widgetMatchWindow = 10 * time.Minute

const (
	widgetJSType     = "text/javascript; charset=utf-8"
	widgetFrameRules = "; default-src 'none'; script-src 'self'; connect-src 'self'"
)

// widgetAssets is the built widget, loaded into memory once at startup.
type widgetAssets struct {
	loader     []byte
	loaderETag string
	bundleName string
	bundle     []byte
	frame      *template.Template
}

// newWidgetAssets loads loader.js, the frame bundle named by manifest.json
// and the frame.html template from fsys.
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
		Frame string `json:"frame"`
	}
	if err := json.Unmarshal(mb, &manifest); err != nil {
		return nil, fmt.Errorf("manifest.json: %w", err)
	}
	bundle, err := fs.ReadFile(fsys, manifest.Frame)
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

// handleWidgetBundle serves the content-hashed frame bundle named by the
// manifest; any other name is 404.
func (s *server) handleWidgetBundle(wa *widgetAssets) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("bundle") != wa.bundleName {
			notFound(w, r)
			return
		}
		h := w.Header()
		h.Set("Content-Type", widgetJSType)
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
		http.ServeContent(w, r, wa.bundleName, time.Time{}, bytes.NewReader(wa.bundle))
	}
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
		var buf bytes.Buffer
		if err := wa.frame.Execute(&buf, struct{ Bundle string }{wa.bundleName}); err != nil {
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

// handleWidgetReport stores the frame's report: its nonce, client components
// and client hash, with the thumbmark recomputed from this connection. The
// key's origin scoping is skipped (the frame runs on nazr's origin), and the
// response is always 204: a malformed body is dropped, never answered.
func (s *server) handleWidgetReport(w http.ResponseWriter, r *http.Request) {
	s.storeWidgetReport(r)
	w.WriteHeader(http.StatusNoContent)
}

// storeWidgetReport validates and stores one report, dropping it silently
// when the body is malformed.
func (s *server) storeWidgetReport(r *http.Request) {
	ctx := r.Context()
	key := auth.KeyFromContext(ctx)
	raw, err := fingerprint.Decode(r.Body, int64(s.Cfg.BodyLimit))
	if key == nil || err != nil {
		return
	}
	nonce, _ := raw["nonce"].(string)
	comps, ok := raw["components"].(map[string]any)
	clientHash, _ := raw["clientHash"].(string)
	if !validNonce(nonce) || !ok || (clientHash != "" && !validCanvasProbe(clientHash)) {
		return
	}

	addr, view := s.clientIP(r)
	s.countParseErrors(ctx, view)
	var lookup ipintel.Lookup
	if s.Intel != nil && addr.IsValid() {
		lookup = s.Intel.Lookup(addr)
	}
	sc, ja4 := serverComponents(r, view, requestOrder(r), s.Cfg, addr, lookup)
	merged := fingerprint.Merge(comps, filterServer(sc, comps, fingerprint.OptionsFromRequest(nil)))

	rep := store.WidgetReport{
		ID: requestIDFrom(ctx), APIKeyID: key.ID, Nonce: nonce, Thumbmark: fingerprint.Hash(merged),
		ClientHash: clientHash, IP: s.storedIP(addr), JA4: ja4, UserAgent: r.Header.Get("User-Agent"),
		Components: s.storedComponents(comps, sc), CreatedAt: s.Now().UTC(),
	}
	if addr.IsValid() {
		rep.IPHash = ipintel.Identifier(addr, s.Cfg.IPHashSalt)
	}
	if view.H2 != nil {
		rep.H2FP = h2fp.Akamai(view.H2)
	}
	ictx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if err := s.Store.InsertWidgetReport(ictx, rep); err != nil {
		s.Logger.Error("server: insert widget report failed", "err", err, "request_id", rep.ID)
	}
}
