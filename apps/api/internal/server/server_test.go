package server

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/oklog/ulid/v2"

	"nazr/api/internal/auth"
	"nazr/api/internal/config"
	"nazr/api/internal/conn"
	"nazr/api/internal/fingerprint"
	"nazr/api/internal/httpfp"
	"nazr/api/internal/ipintel"
	"nazr/api/internal/store"
	"nazr/api/internal/tlsfp"
	"nazr/api/internal/widgettoken"
)

func TestStockBodyClientHash(t *testing.T) {
	body := stockBody(t)
	for _, k := range []string{"components", "options", "clientHash", "version", "path"} {
		if _, ok := body[k]; !ok {
			t.Fatalf("stock body missing %q", k)
		}
	}
	if _, ok := body["api_key"]; ok {
		t.Fatal("stock body must not carry api_key")
	}
	want := fingerprint.Hash(body["components"].(map[string]any))
	if body["clientHash"] != want {
		t.Fatalf("clientHash %v, want %s", body["clientHash"], want)
	}
}

func TestThumbmarkHappyPath(t *testing.T) {
	e := newEnv(t, nil)
	body := stockBody(t)
	body["metadata"] = map[string]any{"order": "A-17", "n": json.Number("3")}
	// The request's own wire order (with Origin) must be the one used: a
	// stale entry queued first, for different header names, is skipped.
	order := append(slices.Clone(testHeaderOrder), "Origin")
	holder := fullHolderOrder(t, []string{"x-stale"})
	holder.PushOrder(http.MethodPost, order)
	r := thumbmarkReq(t, e.key, marshal(t, body))
	r.Header.Set("Origin", "https://shop.example")
	r = r.WithContext(WithHolder(r.Context(), holder))
	w := e.do(r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	resp := decodeResp(t, w)

	// Independently compute the expected thumbmark from the real fingerprint
	// functions over the same server inputs.
	addr := netip.MustParseAddr("203.0.113.42")
	server := map[string]any{
		"tls":    holder.TLS.Component(),
		"h2":     holder.H2.Component(),
		"header": httpfp.Component(r, order),
		"ip":     ipintel.Component(addr, e.intel.lookup),
	}
	client := body["components"].(map[string]any)
	opts := fingerprint.OptionsFromRequest(body["options"].(map[string]any))
	want := fingerprint.Hash(fingerprint.Merge(client, filterLikeClient(server, client, opts)))
	if resp["thumbmark"] != want {
		t.Fatalf("thumbmark %v want %s", resp["thumbmark"], want)
	}
	// Chrome + stabilize private drops tls.extensions; the naive (browserless)
	// filter would not, so the hash proves the client's browser was used.
	if naive := fingerprint.Hash(fingerprint.Merge(client, fingerprint.Filter(server, opts))); naive == want {
		t.Fatal("test inputs do not exercise browser-dependent filtering")
	}
	if got := path(resp, "components", "tls", "ja4"); got != holder.TLS.JA4 || got == "" {
		t.Fatalf("tls.ja4 %v", got)
	}
	if path(resp, "components", "tls", "extensions") == nil {
		t.Fatal("response components must be unfiltered (tls.extensions missing)")
	}
	if got := path(resp, "components", "h2", "fingerprint"); got != holder.H2.Fingerprint {
		t.Fatalf("h2.fingerprint %v", got)
	}
	if got := path(resp, "components", "header", "ja4h"); got != httpfp.JA4HStable(r, order) {
		t.Fatalf("header.ja4h %v", got)
	}
	if got := path(resp, "components", "ip", "address"); got != "203.0.113.42" {
		t.Fatalf("ip.address %v", got)
	}
	if got := path(resp, "info", "visitor", "isNew"); got != true {
		t.Fatalf("isNew %v", got)
	}
	if got := path(resp, "info", "visitor", "firstSeen"); got != testNow.Format(time.RFC3339) {
		t.Fatalf("firstSeen %v", got)
	}
	if path(resp, "info", "visitor", "id") != resp["visitorId"] || resp["visitorId"] == "" {
		t.Fatalf("visitorId %v / %v", resp["visitorId"], path(resp, "info", "visitor", "id"))
	}
	rid, _ := resp["requestId"].(string)
	if _, err := ulid.ParseStrict(rid); err != nil || w.Header().Get("X-Request-Id") != rid {
		t.Fatalf("requestId %q header %q: %v", rid, w.Header().Get("X-Request-Id"), err)
	}
	if fmt.Sprint(resp["metadata"]) != fmt.Sprint(map[string]any{"order": "A-17", "n": json.Number("3")}) {
		t.Fatalf("metadata %v", resp["metadata"])
	}
	if resp["version"] != "test-1.0" {
		t.Fatalf("version %v", resp["version"])
	}
	if _, ok := resp["collect"]; ok {
		t.Fatal("collect must be absent when TLS was captured")
	}
	ipInfo := path(resp, "info", "ip_address").(map[string]any)
	if ipInfo["ip_address"] != "203.0.113.42" || ipInfo["ip_version"] != "v4" ||
		ipInfo["ip_identifier"] != ipintel.Identifier(addr, "salt") ||
		ipInfo["autonomous_system_number"] != json.Number("64496") {
		t.Fatalf("ip_address %v", ipInfo)
	}
	if path(resp, "info", "country", "iso_code") != "US" || path(resp, "info", "country", "continent", "code") != "NA" {
		t.Fatalf("country %v", path(resp, "info", "country"))
	}
	if path(resp, "info", "uniqueness", "score") != json.Number("1") {
		t.Fatalf("uniqueness %v", path(resp, "info", "uniqueness"))
	}
	for _, k := range []string{"tor", "vpn", "bot", "datacenter", "private_relay", "danger_level"} {
		if path(resp, "info", "classification", k) == nil {
			t.Fatalf("classification.%s missing", k)
		}
	}
	if _, ok := path(resp, "info", "signals", "ua_tls_mismatch").(bool); !ok {
		t.Fatalf("signals %v", path(resp, "info", "signals"))
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("ACAO %q", w.Header().Get("Access-Control-Allow-Origin"))
	}
	// JA3 is event-only: it hashes Chromium's per-connection extension order.
	tlsc := path(resp, "components", "tls").(map[string]any)
	if _, ok := tlsc["ja3"]; ok {
		t.Fatalf("tls component carries ja3: %v", tlsc)
	}
	if _, ok := tlsc["ja3_hash"]; ok {
		t.Fatalf("tls component carries ja3_hash: %v", tlsc)
	}

	if len(e.store.events) != 1 {
		t.Fatalf("events %d", len(e.store.events))
	}
	ev := e.store.events[0]
	if ev.IP == nil || *ev.IP != addr || ev.IPHash == "" || ev.ID != rid || ev.Thumbmark != want ||
		ev.APIKeyID != keyID || ev.VisitorID != resp["visitorId"] || ev.JA4 != holder.TLS.JA4 ||
		ev.JA3Hash == "" || ev.JA3Hash != holder.TLS.JA3Hash ||
		ev.ClientHash != body["clientHash"] || ev.Path != "/" || ev.UserAgent != chromeUA ||
		len(ev.Classification) == 0 || len(ev.Signals) == 0 || len(ev.Metadata) == 0 || ev.Components != nil {
		t.Fatalf("event %+v", ev)
	}
	// events.ja4h keeps the full fingerprint; the component carries a_b.
	if ev.JA4H != httpfp.JA4HFull(r, order) || strings.Count(ev.JA4H, "_") != 3 ||
		!strings.HasPrefix(ev.JA4H, path(resp, "components", "header", "ja4h").(string)+"_") {
		t.Fatalf("event ja4h %q", ev.JA4H)
	}
}

func TestThumbmarkStabilizeExcludesServerKeys(t *testing.T) {
	e := newEnv(t, nil)
	body := stockBody(t)
	body["options"] = map[string]any{"stabilize": []any{"private"}}
	client := body["components"].(map[string]any)
	client["system"].(map[string]any)["browser"] = map[string]any{"name": "Firefox", "version": "131.0"}
	holder := fullHolder(t)
	r := thumbmarkReq(t, e.key, marshal(t, body))
	r = r.WithContext(WithHolder(r.Context(), holder))
	w := e.do(r)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	resp := decodeResp(t, w)

	server := map[string]any{
		"tls":    holder.TLS.Component(),
		"h2":     holder.H2.Component(),
		"header": httpfp.Component(r, testHeaderOrder),
		"ip":     ipintel.Component(netip.MustParseAddr("203.0.113.42"), e.intel.lookup),
	}
	without := map[string]any{}
	for k, v := range server {
		without[k] = v
	}
	tlsNoExt := map[string]any{}
	for k, v := range holder.TLS.Component() {
		if k != "extensions" {
			tlsNoExt[k] = v
		}
	}
	without["tls"] = tlsNoExt
	excluded := fingerprint.Hash(fingerprint.Merge(client, without))
	included := fingerprint.Hash(fingerprint.Merge(client, server))
	if excluded == included {
		t.Fatal("hashes should differ")
	}
	if resp["thumbmark"] != excluded {
		t.Fatalf("thumbmark %v want %s (with extensions would be %s)", resp["thumbmark"], excluded, included)
	}
	if path(resp, "components", "tls", "extensions") == nil {
		t.Fatal("response components must stay unfiltered")
	}
}

func TestThumbmarkSimpleRequestTextPlain(t *testing.T) {
	e := newEnv(t, nil)
	r := thumbmarkReq(t, e.key, marshal(t, stockBody(t)))
	r.Header.Set("Content-Type", "text/plain;charset=UTF-8")
	r.Header.Del("Authorization")
	w := e.do(r)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if resp := decodeResp(t, w); resp["thumbmark"] == "" || resp["thumbmark"] == nil {
		t.Fatalf("no thumbmark: %v", resp)
	}
}

func TestThumbmarkErrors(t *testing.T) {
	stock := func(t *testing.T) []byte { return marshal(t, stockBody(t)) }
	t.Run("no key", func(t *testing.T) {
		e := newEnv(t, nil)
		wantError(t, e.do(thumbmarkReq(t, "", stock(t))), 403, "unauthorized")
	})
	t.Run("bad json", func(t *testing.T) {
		e := newEnv(t, nil)
		wantError(t, e.do(thumbmarkReq(t, e.key, []byte(`{"components":`))), 400, "bad_request")
	})
	t.Run("not an object", func(t *testing.T) {
		e := newEnv(t, nil)
		wantError(t, e.do(thumbmarkReq(t, e.key, []byte(`[1,2]`))), 400, "bad_request")
	})
	t.Run("too large", func(t *testing.T) {
		e := newEnv(t, func(c *config.Config, _ *fakeStore) { c.BodyLimit = 256 })
		big := `{"components":{"x":"` + strings.Repeat("a", 1000) + `"}}`
		wantError(t, e.do(thumbmarkReq(t, e.key, []byte(big))), 413, "payload_too_large")
	})
	t.Run("store down", func(t *testing.T) {
		e := newEnv(t, func(_ *config.Config, s *fakeStore) { s.pingErr = errBoom })
		w := e.do(thumbmarkReq(t, e.key, stock(t)))
		wantError(t, w, 503, "store_unavailable")
		if w.Header().Get("Retry-After") != "2" {
			t.Fatalf("Retry-After %q", w.Header().Get("Retry-After"))
		}
	})
	t.Run("resolver error", func(t *testing.T) {
		e := newEnv(t, nil)
		e.repo.err = errBoom
		wantError(t, e.do(thumbmarkReq(t, e.key, stock(t))), 503, "store_unavailable")
	})
	t.Run("components not object", func(t *testing.T) {
		e := newEnv(t, nil)
		wantError(t, e.do(thumbmarkReq(t, e.key, []byte(`{"components":"nope"}`))), 400, "bad_request")
	})
	t.Run("components missing", func(t *testing.T) {
		e := newEnv(t, nil)
		wantError(t, e.do(thumbmarkReq(t, e.key, []byte(`{"version":"1.12.0"}`))), 400, "bad_request")
	})
	t.Run("unsupported content type", func(t *testing.T) {
		e := newEnv(t, nil)
		r := thumbmarkReq(t, e.key, stock(t))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		wantError(t, e.do(r), 400, "bad_request")
	})
}

func TestCORSPreflight(t *testing.T) {
	pre := func(origin string) *http.Request {
		r := httptest.NewRequest(http.MethodOptions, "/thumbmark", nil)
		r.Header.Set("Origin", origin)
		r.Header.Set("Access-Control-Request-Method", "POST")
		r.Header.Set("Access-Control-Request-Headers", "content-type,x-api-key,authorization")
		return r
	}
	e := newEnv(t, nil)
	w := e.do(pre("https://b.com"))
	if w.Code != 204 {
		t.Fatalf("status %d", w.Code)
	}
	h := w.Header()
	if h.Get("Access-Control-Allow-Origin") != "*" ||
		h.Get("Access-Control-Allow-Methods") != "POST, OPTIONS" ||
		h.Get("Access-Control-Allow-Headers") != "content-type, x-api-key, authorization" ||
		h.Get("Access-Control-Max-Age") != "86400" {
		t.Fatalf("headers %v", h)
	}
	if w := e.do(httptest.NewRequest(http.MethodOptions, "/beacon", nil)); w.Code != 204 {
		t.Fatalf("beacon preflight %d", w.Code)
	}

	e = newEnv(t, func(c *config.Config, _ *fakeStore) { c.CORSOrigins = []string{"https://a.com"} })
	w = e.do(pre("https://b.com"))
	if w.Code != 204 || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("unlisted origin: %d %v", w.Code, w.Header())
	}
	w = e.do(pre("https://a.com"))
	if w.Header().Get("Access-Control-Allow-Origin") != "https://a.com" || w.Header().Get("Vary") != "Origin" {
		t.Fatalf("listed origin: %v", w.Header())
	}
}

func TestOriginScopedKeyOnRealRequest(t *testing.T) {
	e := newEnv(t, func(_ *config.Config, s *fakeStore) {
		for _, k := range s.keys {
			k.AllowedOrigins = []string{"https://shop.example"}
		}
	})
	r := thumbmarkReq(t, e.key, marshal(t, stockBody(t)))
	r.Header.Set("Origin", "https://evil.example")
	wantError(t, e.do(r), 403, "origin_not_allowed")

	r = thumbmarkReq(t, e.key, marshal(t, stockBody(t)))
	r.Header.Set("Origin", "https://shop.example")
	w := e.do(r)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "https://shop.example" || w.Header().Get("Vary") != "Origin" {
		t.Fatalf("headers %v", w.Header())
	}
}

func TestStoreIPHashMode(t *testing.T) {
	e := newEnv(t, func(c *config.Config, _ *fakeStore) { c.StoreIP = "hash"; c.StoreComponents = true })
	if w := e.do(thumbmarkReq(t, e.key, marshal(t, stockBody(t)))); w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	ev := e.store.events[0]
	if ev.IP != nil || ev.IPHash != ipintel.Identifier(netip.MustParseAddr("203.0.113.42"), "salt") {
		t.Fatalf("ip %v hash %q", ev.IP, ev.IPHash)
	}
	var comps map[string]any
	if err := json.Unmarshal(ev.Components, &comps); err != nil || comps["header"] == nil || comps["system"] == nil {
		t.Fatalf("components %s: %v", ev.Components, err)
	}
}

func TestCollectDirectiveSampled(t *testing.T) {
	e := newEnv(t, nil)
	e.rand = 0
	resp := decodeResp(t, e.do(thumbmarkReq(t, e.key, marshal(t, stockBody(t)))))
	c, ok := resp["collect"].(map[string]any)
	if !ok || c["source"] != "none" || c["ja4"] != "" {
		t.Fatalf("collect %v", resp["collect"])
	}
	if path(resp, "components", "tls") != nil {
		t.Fatal("no tls component expected")
	}

	e.rand = 1
	resp = decodeResp(t, e.do(thumbmarkReq(t, e.key, marshal(t, stockBody(t)))))
	if _, ok := resp["collect"]; ok {
		t.Fatal("collect must be absent when not sampled")
	}

	e.rand = 0
	r := thumbmarkReq(t, e.key, marshal(t, stockBody(t)))
	r = r.WithContext(WithHolder(r.Context(), fullHolder(t)))
	resp = decodeResp(t, e.do(r))
	if _, ok := resp["collect"]; ok {
		t.Fatal("collect must be absent when TLS was captured")
	}
}

// seedEvent records a /thumbmark event for thumbmark from addr at time at.
func seedEvent(e *env, addr, thumbmark string, at time.Time) {
	e.store.events = append(e.store.events, store.Event{
		Thumbmark: thumbmark, IPHash: ipintel.Identifier(netip.MustParseAddr(addr), e.cfg.IPHashSalt), CreatedAt: at,
	})
}

func TestBeaconRecordsObservation(t *testing.T) {
	e := newEnv(t, nil)
	seedEvent(e, "192.0.2.1", "abc", testNow.Add(-time.Minute)) // httptest's RemoteAddr
	tr := &tlsfp.Result{JA4: "t13d1516h2_8daaf6152771_02713d6af862"}
	body := `{"ua":"` + chromeUA + `","thumbmark":"abc","ja4":"t13d_body","ja4_source":"client"}`
	r := httptest.NewRequest(http.MethodPost, "/beacon", strings.NewReader(body))
	r.Header.Set("Content-Type", "text/plain;charset=UTF-8")
	r = r.WithContext(WithHolder(r.Context(), &conn.Holder{TLS: tr}))
	w := e.do(r)
	if w.Code != 204 {
		t.Fatalf("status %d", w.Code)
	}
	if len(e.store.obs) != 1 || e.store.obs[0] != [2]string{tr.JA4, "chrome"} {
		t.Fatalf("obs %v", e.store.obs)
	}

	r = httptest.NewRequest(http.MethodPost, "/beacon", strings.NewReader(body))
	if w := e.do(r); w.Code != 204 || len(e.store.obs) != 2 || e.store.obs[1] != [2]string{"t13d_body", "chrome"} {
		t.Fatalf("body ja4: %d %v", w.Code, e.store.obs)
	}

	r = httptest.NewRequest(http.MethodPost, "/beacon", strings.NewReader(`garbage`))
	if w := e.do(r); w.Code != 204 || len(e.store.obs) != 2 {
		t.Fatalf("garbage: %d %v", w.Code, e.store.obs)
	}
}

func TestBeaconRequiresRecentMatchingEvent(t *testing.T) {
	e := newEnv(t, nil)
	body := `{"ua":"` + chromeUA + `","thumbmark":"abc","ja4":"t13d_body"}`
	send := func(remote string) {
		r := httptest.NewRequest(http.MethodPost, "/beacon", strings.NewReader(body))
		r.RemoteAddr = remote
		if w := e.do(r); w.Code != 204 {
			t.Fatalf("status %d", w.Code)
		}
	}
	send("192.0.2.1:1") // no event at all
	seedEvent(e, "192.0.2.1", "abc", testNow.Add(-11*time.Minute))
	send("192.0.2.1:1") // event too old
	seedEvent(e, "192.0.2.2", "abc", testNow)
	send("192.0.2.1:1") // event from another IP
	seedEvent(e, "192.0.2.1", "other", testNow)
	send("192.0.2.1:1") // event for another thumbmark
	if len(e.store.obs) != 0 {
		t.Fatalf("unmatched beacons recorded: %v", e.store.obs)
	}
	seedEvent(e, "192.0.2.1", "abc", testNow.Add(-10*time.Minute))
	send("192.0.2.1:1")
	if len(e.store.obs) != 1 || e.store.obs[0] != [2]string{"t13d_body", "chrome"} {
		t.Fatalf("matched beacon: %v", e.store.obs)
	}
	r := httptest.NewRequest(http.MethodPost, "/beacon", strings.NewReader(`{"ua":"x","ja4":"y"}`))
	if w := e.do(r); w.Code != 204 || len(e.store.obs) != 1 {
		t.Fatalf("beacon without thumbmark recorded: %v", e.store.obs)
	}
}

func TestBeaconRateLimited(t *testing.T) {
	e := newEnv(t, func(c *config.Config, _ *fakeStore) { c.DefaultRateLimit = 1 })
	seedEvent(e, "198.51.100.7", "tm", testNow)
	send := func() int {
		r := httptest.NewRequest(http.MethodPost, "/beacon", strings.NewReader(`{"ua":"x","ja4":"y","thumbmark":"tm"}`))
		r.RemoteAddr = "198.51.100.7:1000"
		return e.do(r).Code
	}
	if c := send(); c != 204 {
		t.Fatalf("first %d", c)
	}
	if c := send(); c != 429 {
		t.Fatalf("second %d", c)
	}
	if len(e.store.obs) != 1 {
		t.Fatalf("obs %v", e.store.obs)
	}
}

func TestLogDiscardedByDefault(t *testing.T) {
	e := newEnv(t, nil)
	r := httptest.NewRequest(http.MethodPost, "/log", strings.NewReader(`{"thumbmark":"x"}`))
	if w := e.do(r); w.Code != 204 || len(e.store.logs) != 0 {
		t.Fatalf("%d %v", w.Code, e.store.logs)
	}

	e = newEnv(t, func(c *config.Config, _ *fakeStore) { c.LogRetention = 24 * time.Hour })
	r = httptest.NewRequest(http.MethodPost, "/log", strings.NewReader(`{"thumbmark":"x"}`))
	if w := e.do(r); w.Code != 204 || len(e.store.logs) != 1 || e.store.logKeys[0] != nil {
		t.Fatalf("%d %v", w.Code, e.store.logs)
	}
	if string(e.store.logs[0]) != `{"thumbmark":"x"}` {
		t.Fatalf("body %s", e.store.logs[0])
	}
	r = httptest.NewRequest(http.MethodPost, "/log", strings.NewReader(`{"a":1}`))
	r.Header.Set("x-api-key", e.key)
	if w := e.do(r); w.Code != 204 || len(e.store.logs) != 2 || e.store.logKeys[1] == nil || *e.store.logKeys[1] != keyID {
		t.Fatalf("%d %v", w.Code, e.store.logKeys)
	}
	r = httptest.NewRequest(http.MethodPost, "/log", strings.NewReader(`not json`))
	if w := e.do(r); w.Code != 204 || len(e.store.logs) != 2 {
		t.Fatalf("invalid json stored: %d %v", w.Code, e.store.logs)
	}
}

func TestLogLimitsAndKeyCache(t *testing.T) {
	e := newEnvCache(t, func(c *config.Config, _ *fakeStore) {
		c.LogRetention = 24 * time.Hour
		c.DefaultRateLimit = 3
	}, auth.NewKeyCache(time.Minute, nil))
	send := func(body, key string) int {
		r := httptest.NewRequest(http.MethodPost, "/log", strings.NewReader(body))
		r.RemoteAddr = "198.51.100.9:1000"
		if key != "" {
			r.Header.Set("x-api-key", key)
		}
		return e.do(r).Code
	}
	if c := send(`{"a":1}`, e.key); c != 204 {
		t.Fatalf("first %d", c)
	}
	if c := send(`{"a":2}`, e.key); c != 204 {
		t.Fatalf("second %d", c)
	}
	if e.store.findCalls != 1 {
		t.Fatalf("FindKeyByHash called %d times, want 1 (key cache bypassed)", e.store.findCalls)
	}
	if len(e.store.logKeys) != 2 || e.store.logKeys[1] == nil || *e.store.logKeys[1] != keyID {
		t.Fatalf("log keys %v", e.store.logKeys)
	}
	big := `{"a":"` + strings.Repeat("x", 16<<10) + `"}`
	if c := send(big, ""); c != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized log %d, want 413", c)
	}
	if len(e.store.logs) != 2 {
		t.Fatal("oversized log stored")
	}
	if c := send(`{"a":3}`, ""); c != http.StatusTooManyRequests {
		t.Fatalf("fourth %d, want 429", c)
	}
	if c := send(`{}`, "nzr_garbage"); c != http.StatusTooManyRequests || e.store.findCalls != 1 {
		t.Fatalf("%d / find calls %d", c, e.store.findCalls)
	}
}

func TestLogMalformedKeySkipsLookup(t *testing.T) {
	e := newEnv(t, func(c *config.Config, _ *fakeStore) { c.LogRetention = time.Hour })
	r := httptest.NewRequest(http.MethodPost, "/log", strings.NewReader(`{}`))
	r.Header.Set("x-api-key", "not-a-key")
	if w := e.do(r); w.Code != 204 || e.store.findCalls != 0 || len(e.store.logs) != 1 || e.store.logKeys[0] != nil {
		t.Fatalf("%d calls=%d logs=%v", w.Code, e.store.findCalls, e.store.logKeys)
	}
}

func TestReadyzReportsSources(t *testing.T) {
	e := newEnv(t, nil)
	e.intel.status = map[string]ipintel.SourceStatus{
		"maxmind-GeoLite2-City": {Loaded: false, LastError: "401"},
		"tor":                   {Loaded: true, Rows: 1200, FetchedAt: testNow},
	}
	w := e.do(httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	resp := decodeResp(t, w)
	if resp["tls_mode"] != "terminate" || resp["store"] != "ok" || resp["version"] != "test-1.0" {
		t.Fatalf("readyz %v", resp)
	}
	if path(resp, "sources", "maxmind-GeoLite2-City", "loaded") != false ||
		path(resp, "sources", "maxmind-GeoLite2-City", "last_error") != "401" ||
		path(resp, "sources", "tor", "rows") != json.Number("1200") {
		t.Fatalf("sources %v", resp["sources"])
	}

	e.store.pingErr = errBoom
	w = e.do(httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != 200 {
		t.Fatalf("answer within 1s not reused: %d", w.Code)
	}
	e.now = e.now.Add(time.Second)
	w = e.do(httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != 503 || decodeResp(t, w)["store"] != "error" {
		t.Fatalf("store down: %d %s", w.Code, w.Body.String())
	}
}

func TestReadyzTrimsSourceErrors(t *testing.T) {
	e := newEnv(t, func(c *config.Config, _ *fakeStore) { c.DataDir = "/srv/nazr-data/" })
	e.intel.status = map[string]ipintel.SourceStatus{
		"tor": {LastError: "tor: open /srv/nazr-data/tor.txt: permission denied\ngoroutine 1 [running]:\nmain.main()"},
	}
	resp := decodeResp(t, e.do(httptest.NewRequest(http.MethodGet, "/readyz", nil)))
	if got := path(resp, "sources", "tor", "last_error"); got != "tor: open <data>/tor.txt: permission denied" {
		t.Fatalf("last_error %q", got)
	}
}

func TestProxiedModeReadsJA4Header(t *testing.T) {
	e := newEnv(t, func(c *config.Config, _ *fakeStore) { c.TLSMode = "proxied" })
	ja4 := "t13d1516h2_8daaf6152771_02713d6af862"
	e.rand = 0
	r := thumbmarkReq(t, e.key, marshal(t, stockBody(t)))
	r.Header.Set("x-ja4", ja4)
	r.Header.Set("X-Forwarded-For", "192.0.2.9")
	w := e.do(r)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	resp := decodeResp(t, w)
	tlsc, _ := path(resp, "components", "tls").(map[string]any)
	if len(tlsc) != 1 || tlsc["ja4"] != ja4 {
		t.Fatalf("tls %v", tlsc)
	}
	if path(resp, "components", "ip", "address") != "192.0.2.9" {
		t.Fatalf("ip %v", path(resp, "components", "ip"))
	}
	if _, ok := resp["collect"]; ok {
		t.Fatal("collect must be absent when the proxy supplied JA4")
	}
	if len(e.store.uaQueries) != 1 || e.store.uaQueries[0] != ja4 || e.store.events[0].JA4 != ja4 {
		t.Fatalf("ja4 not used for families/event: %v", e.store.uaQueries)
	}

	r = thumbmarkReq(t, e.key, marshal(t, stockBody(t)))
	resp = decodeResp(t, e.do(r))
	if path(resp, "components", "tls") != nil {
		t.Fatalf("tls %v", path(resp, "components", "tls"))
	}
	if _, ok := resp["collect"]; !ok {
		t.Fatal("collect expected without JA4 header")
	}
}

func TestJA4FamiliesUnionFeedsClassifier(t *testing.T) {
	// A Chrome UA whose JA4 is only known as Firefox (FoxIO) and curl (local
	// observations) trips ua_tls_mismatch.
	e := newEnv(t, func(_ *config.Config, s *fakeStore) { s.uaFamilies = []string{"curl"} })
	holder := fullHolder(t)
	e.intel.families[holder.TLS.JA4] = []string{"Firefox"}
	r := thumbmarkReq(t, e.key, marshal(t, stockBody(t)))
	r = r.WithContext(WithHolder(r.Context(), holder))
	resp := decodeResp(t, e.do(r))
	if path(resp, "info", "signals", "ua_tls_mismatch") != true {
		t.Fatalf("signals %v", path(resp, "info", "signals"))
	}
	// Adding chrome via local observations clears it.
	e.store.uaFamilies = []string{"chrome"}
	r = thumbmarkReq(t, e.key, marshal(t, stockBody(t)))
	r = r.WithContext(WithHolder(r.Context(), holder))
	resp = decodeResp(t, e.do(r))
	if path(resp, "info", "signals", "ua_tls_mismatch") != false {
		t.Fatalf("signals %v", path(resp, "info", "signals"))
	}
}

func TestPanicRecovered(t *testing.T) {
	e := newEnv(t, func(_ *config.Config, s *fakeStore) { s.panicPing = true })
	w := e.do(thumbmarkReq(t, e.key, marshal(t, stockBody(t))))
	wantError(t, w, 500, "internal")
	if w.Header().Get("X-Request-Id") == "" {
		t.Fatal("request id header missing")
	}
	e.store.mu.Lock()
	e.store.panicPing = false
	e.store.mu.Unlock()
	if w := e.do(thumbmarkReq(t, e.key, marshal(t, stockBody(t)))); w.Code != 200 {
		t.Fatalf("next request %d: %s", w.Code, w.Body.String())
	}
}

func TestAdminKeys(t *testing.T) {
	e := newEnv(t, func(c *config.Config, _ *fakeStore) { c.AdminToken = "s3cret" })
	req := func(method, target, body, token string) *http.Request {
		r := httptest.NewRequest(method, target, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		return r
	}
	wantError(t, e.do(req("GET", "/admin/keys", "", "")), 403, "unauthorized")
	wantError(t, e.do(req("POST", "/admin/keys", `{}`, "s3cret")), 400, "bad_request")
	w := e.do(req("POST", "/admin/keys", `{"label":"shop","allowed_origins":["https://ok.example","shop.example/path"]}`, "s3cret"))
	wantError(t, w, 400, "bad_request")
	if !strings.Contains(w.Body.String(), "shop.example/path") {
		t.Fatalf("error does not name the bad origin: %s", w.Body.String())
	}

	w = e.do(req("POST", "/admin/keys", `{"label":"shop","allowed_origins":["https://shop.example"],"rate_limit_per_minute":120}`, "s3cret"))
	if w.Code != 201 {
		t.Fatalf("create %d: %s", w.Code, w.Body.String())
	}
	var created map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	plain, _ := created["key"].(string)
	if !strings.HasPrefix(plain, "nzr_") || created["prefix"] != plain[4:12] || created["label"] != "shop" {
		t.Fatalf("created %v", created)
	}
	k := e.store.keys[auth.HashKey(plain)]
	if k == nil || k.RateLimitPerMinute == nil || *k.RateLimitPerMinute != 120 || k.AllowedOrigins[0] != "https://shop.example" {
		t.Fatalf("stored %+v", k)
	}

	w = e.do(req("GET", "/admin/keys", "", "s3cret"))
	if w.Code != 200 || strings.Contains(w.Body.String(), plain) || !strings.Contains(w.Body.String(), created["id"].(string)) {
		t.Fatalf("list %d: %s", w.Code, w.Body.String())
	}
	var list []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list) != 2 {
		t.Fatalf("list %s: %v", w.Body.String(), err)
	}
	if _, has := list[0]["key"]; has {
		t.Fatal("list must not expose keys")
	}

	w = e.do(req("DELETE", "/admin/keys/"+created["id"].(string), "", "s3cret"))
	if w.Code != 204 || len(e.store.revoked) != 1 || e.store.revoked[0] != created["id"] {
		t.Fatalf("delete %d %v", w.Code, e.store.revoked)
	}
	wantError(t, e.do(req("DELETE", "/admin/keys/nope", "", "s3cret")), 404, "not_found")

	e = newEnv(t, nil)
	wantError(t, e.do(req("GET", "/admin/keys", "", "anything")), 404, "not_found")
}

func TestClientIPProxiedRightmostUntrusted(t *testing.T) {
	cfg := defaultConfig(t)
	cfg.TLSMode = "proxied"
	cfg.TrustedProxies = []string{"10.0.0.0/8"}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:443"
	r.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.2")
	if got := ClientIP(r, nil, cfg); got != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("got %v", got)
	}
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 1.1.1.1, 10.0.0.2")
	r.Header.Add("X-Forwarded-For", "10.0.0.3")
	if got := ClientIP(r, nil, cfg); got != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("multi-line got %v", got)
	}
	r.Header.Del("X-Forwarded-For")
	if got := ClientIP(r, nil, cfg); got != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("fallback got %v", got)
	}

	cfg.TLSMode = "terminate"
	r.Header.Set("X-Forwarded-For", "1.1.1.1")
	h := &conn.Holder{RemoteAddr: netip.MustParseAddrPort("[::ffff:198.51.100.4]:9")}
	if got := ClientIP(r, h, cfg); got != netip.MustParseAddr("198.51.100.4") {
		t.Fatalf("terminate holder got %v", got)
	}
	if got := ClientIP(r, nil, cfg); got != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("terminate remote got %v", got)
	}
}

func TestServerComponentsStringifiable(t *testing.T) {
	cfg := defaultConfig(t)
	r := thumbmarkReq(t, "", nil)
	r.Header.Set("Sec-CH-UA", `"Chromium";v="126"`)
	view := fullHolder(t).Snapshot()
	sc, _ := serverComponents(r, view, testHeaderOrder, cfg, netip.MustParseAddr("2001:db8::1"),
		ipintel.Lookup{ASN: 1, Tor: true, Country: "DE"})
	for _, k := range []string{"tls", "h2", "header", "ip"} {
		if sc[k] == nil {
			t.Fatalf("%s missing", k)
		}
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("StableStringify(%s) panicked: %v", k, p)
				}
			}()
			_ = fingerprint.StableStringify(sc[k])
		}()
	}
	// The header component's shape: cookie-free ja4h (two parts), the
	// request's own lowercased order, and only present headers.
	hdr := sc["header"].(map[string]any)
	want := []string{"ja4h", "order", "userAgent", "accept", "acceptEncoding", "acceptLanguage", "clientHints"}
	if len(hdr) != len(want) {
		t.Fatalf("header keys %v, want %v", hdr, want)
	}
	for _, k := range want {
		if _, ok := hdr[k]; !ok {
			t.Fatalf("header.%s missing: %v", k, hdr)
		}
	}
	if j := hdr["ja4h"].(string); strings.Count(j, "_") != 1 || j != httpfp.JA4HStable(r, testHeaderOrder) {
		t.Fatalf("header.ja4h %q", j)
	}
	if o := hdr["order"].([]string); len(o) != len(testHeaderOrder) || o[0] != "host" {
		t.Fatalf("header.order %v", o)
	}
	cfg.TLSMode = "proxied"
	r.Header.Set("x-ja4", "t13d_x")
	sc, _ = serverComponents(r, conn.HolderView{}, nil, cfg, netip.Addr{}, ipintel.Lookup{})
	_ = fingerprint.StableStringify(sc)
	if _, ok := sc["ip"]; ok {
		t.Fatal("invalid address must not produce an ip component")
	}
}

func TestOperationalRoutes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<h1>demo</h1>"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, func(c *config.Config, _ *fakeStore) { c.DemoDir = dir })
	if w := e.do(httptest.NewRequest("GET", "/healthz", nil)); w.Code != 200 || w.Body.String() != "ok" {
		t.Fatalf("healthz %d %q", w.Code, w.Body.String())
	}
	if w := e.do(httptest.NewRequest("GET", "/", nil)); w.Code != 200 || w.Body.String() != "nazr test-1.0\n" ||
		!strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("banner %d %q", w.Code, w.Body.String())
	}
	if w := e.do(httptest.NewRequest("GET", "/demo/", nil)); w.Code != 200 || !strings.Contains(w.Body.String(), "demo") {
		t.Fatalf("demo %d %q", w.Code, w.Body.String())
	}
	wantError(t, e.do(httptest.NewRequest("GET", "/nope", nil)), 404, "not_found")

	e = newEnv(t, nil)
	wantError(t, e.do(httptest.NewRequest("GET", "/demo/", nil)), 404, "not_found")
}

func TestMetricsHandler(t *testing.T) {
	e := newEnv(t, nil)
	e.intel.status = map[string]ipintel.SourceStatus{"tor": {Loaded: false, LastError: "x"}}
	e.do(thumbmarkReq(t, e.key, marshal(t, stockBody(t))))
	w := httptest.NewRecorder()
	NewMetricsHandler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	out := w.Body.String()
	for _, want := range []string{
		`nazr_requests_total{route="thumbmark",status="200"}`,
		`nazr_request_duration_seconds_bucket{route="thumbmark"`,
		`nazr_classification_total{bot="false",datacenter="false",private_relay="false",tor="false",vpn="false"}`,
		`nazr_list_stale{source="tor"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %s", want)
		}
	}
}

func TestEveryRouteClaimsItsHeaderOrder(t *testing.T) {
	// A request rejected before /thumbmark runs (403, unknown key) still
	// consumes its queued order, so the next request with the same names
	// gets its own entry rather than the rejected request's.
	e := newEnv(t, nil)
	h := &conn.Holder{RemoteAddr: netip.MustParseAddrPort("203.0.113.42:5555")}
	rejected := []string{"x-api-key", "authorization", "accept-encoding", "accept-language", "accept", "user-agent", "content-type"}
	h.PushOrder(http.MethodPost, rejected)
	h.PushOrder(http.MethodPost, testHeaderOrder)
	r := thumbmarkReq(t, "nzr_unknown", marshal(t, stockBody(t)))
	if w := e.do(r.WithContext(WithHolder(r.Context(), h))); w.Code != http.StatusForbidden {
		t.Fatalf("status %d", w.Code)
	}
	r = thumbmarkReq(t, e.key, marshal(t, stockBody(t)))
	w := e.do(r.WithContext(WithHolder(r.Context(), h)))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	got := path(decodeResp(t, w), "components", "header", "order")
	want := []any{}
	for _, n := range testHeaderOrder {
		want = append(want, strings.ToLower(n))
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
}

// The readiness and root routes carry the global CORS policy so a page on
// another origin (the demo's status banner) can read them.
func TestReadinessRoutesCORS(t *testing.T) {
	get := func(e *env, target, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		return e.do(r)
	}
	wild := newEnv(t, nil)
	listed := newEnv(t, func(c *config.Config, _ *fakeStore) { c.CORSOrigins = []string{"https://demo.example"} })
	for _, target := range []string{"/healthz", "/readyz", "/"} {
		if w := get(wild, target, "https://any.example"); w.Code != 200 || w.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Fatalf("%s wildcard: %d ACAO %q", target, w.Code, w.Header().Get("Access-Control-Allow-Origin"))
		}
		w := get(listed, target, "https://demo.example")
		if w.Code != 200 || w.Header().Get("Access-Control-Allow-Origin") != "https://demo.example" ||
			!slices.Contains(w.Header().Values("Vary"), "Origin") {
			t.Fatalf("%s allowed origin: %d %v", target, w.Code, w.Header())
		}
		w = get(listed, target, "https://evil.example")
		if w.Code != 200 || w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("%s unlisted origin: %d ACAO %q", target, w.Code, w.Header().Get("Access-Control-Allow-Origin"))
		}
	}
}

// A prober that disconnects mid-request must not cache a 503 for everyone
// else: the store ping does not inherit the request's cancellation.
func TestReadyzIgnoresProberCancellation(t *testing.T) {
	e := newEnv(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := e.do(httptest.NewRequest(http.MethodGet, "/readyz", nil).WithContext(ctx))
	if w.Code != 200 {
		t.Fatalf("cancelled prober got %d: %s", w.Code, w.Body.String())
	}
	if w := e.do(httptest.NewRequest(http.MethodGet, "/readyz", nil)); w.Code != 200 {
		t.Fatalf("next prober got cached %d: %s", w.Code, w.Body.String())
	}
}

func postProbe(t *testing.T, probe any, set bool) (string, store.Event, int) {
	t.Helper()
	e := newEnv(t, nil)
	body := stockBody(t)
	if set {
		body["canvas_probe"] = probe
	}
	w := e.do(thumbmarkReq(t, e.key, marshal(t, body)))
	if w.Code != http.StatusOK {
		return "", store.Event{}, w.Code
	}
	resp := decodeResp(t, w)
	if len(e.store.events) != 1 {
		t.Fatalf("events %d", len(e.store.events))
	}
	tm, _ := resp["thumbmark"].(string)
	return tm, e.store.events[0], w.Code
}

func TestThumbmarkCanvasProbe(t *testing.T) {
	baseTM, baseEv, _ := postProbe(t, nil, false)
	if baseEv.CanvasProbe != "" {
		t.Fatalf("baseline probe %q", baseEv.CanvasProbe)
	}
	tm, ev, code := postProbe(t, "a1b2c3", true)
	if code != http.StatusOK || ev.CanvasProbe != "a1b2c3" || ev.Cohort == "" {
		t.Fatalf("code %d probe %q cohort %q", code, ev.CanvasProbe, ev.Cohort)
	}
	if tm != baseTM || tm == "" {
		t.Fatalf("probe changed thumbmark: %q vs %q", tm, baseTM)
	}
	for name, v := range map[string]any{
		"non-hex":  "NOT-HEX!!",
		"too-long": strings.Repeat("ab", 100),
		"numeric":  5,
	} {
		tm, ev, code := postProbe(t, v, true)
		if code != http.StatusOK || ev.CanvasProbe != "" || tm != baseTM {
			t.Fatalf("%s: code %d probe %q", name, code, ev.CanvasProbe)
		}
	}
}

func probeSignalResp(t *testing.T, scoring bool, dom string, established bool) (map[string]any, *fakeStore) {
	t.Helper()
	e := newEnv(t, func(c *config.Config, s *fakeStore) {
		c.CanvasProbeScoring = scoring
		s.domValue, s.domEstablished = dom, established
	})
	body := stockBody(t)
	body["canvas_probe"] = "a1b2c3"
	w := e.do(thumbmarkReq(t, e.key, marshal(t, body)))
	if w.Code != http.StatusOK {
		t.Fatalf("code %d: %s", w.Code, w.Body.String())
	}
	return decodeResp(t, w), e.store
}

func TestCanvasProbeScoringOff(t *testing.T) {
	resp, fs := probeSignalResp(t, false, "ffffff", true)
	if _, ok := path(resp, "info", "signals").(map[string]any)["canvas_probe_anomaly"]; ok {
		t.Fatal("signal present with scoring off")
	}
	if fs.domCalls != 0 {
		t.Fatalf("query ran %d times", fs.domCalls)
	}
}

func TestCanvasProbeScoringOn(t *testing.T) {
	resp, fs := probeSignalResp(t, true, "ffffff", true)
	if path(resp, "info", "signals", "canvas_probe_anomaly") != true || fs.domCalls != 1 {
		t.Fatalf("differs: %v calls %d", path(resp, "info", "signals"), fs.domCalls)
	}
	resp, _ = probeSignalResp(t, true, "a1b2c3", true)
	if v, ok := path(resp, "info", "signals").(map[string]any)["canvas_probe_anomaly"]; !ok || v != false {
		t.Fatalf("matches: present=%v v=%v", ok, v)
	}
	resp, _ = probeSignalResp(t, true, "ffffff", false)
	if _, ok := path(resp, "info", "signals").(map[string]any)["canvas_probe_anomaly"]; ok {
		t.Fatal("signal present for unestablished cohort")
	}
}

func TestProbeVerdict(t *testing.T) {
	for _, c := range []struct {
		visitors, distinct int64
		ratio              float64
		verdict            string
	}{
		{0, 0, 0, "insufficient_data"},
		{10, 1, 0.1, "insufficient_data"},
		{100, 3, 0.03, "too_low"},
		{100, 5, 0.05, "too_low"},
		{100, 98, 0.98, "too_unique"},
		{100, 95, 0.95, "too_unique"},
		{100, 50, 0.5, "ok"},
	} {
		r, v := probeVerdict(c.visitors, c.distinct)
		if r != c.ratio || v != c.verdict {
			t.Errorf("probeVerdict(%d,%d) = %v,%q want %v,%q", c.visitors, c.distinct, r, v, c.ratio, c.verdict)
		}
	}
}

func TestAdminCanvasProbeReport(t *testing.T) {
	e := newEnv(t, func(c *config.Config, _ *fakeStore) { c.AdminToken = "s3cret" })
	req := func(token string) *http.Request {
		r := httptest.NewRequest("GET", "/admin/keys/key-1/canvas-probe", nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		return r
	}
	wantError(t, e.do(req("")), 403, "unauthorized")

	e.store.entVisitors, e.store.entDistinct = 100, 3
	w := e.do(req("s3cret"))
	if w.Code != 200 {
		t.Fatalf("report %d: %s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["window_days"] != float64(30) || got["visitors"] != float64(100) || got["distinct_probes"] != float64(3) ||
		got["ratio"] != 0.03 || got["verdict"] != "too_low" {
		t.Fatalf("body %v", got)
	}
	if e.store.entKeyID != "key-1" || !e.store.entSince.Equal(testNow.Add(-30*24*time.Hour)) {
		t.Fatalf("args %q %v", e.store.entKeyID, e.store.entSince)
	}

	e.store.entErr = errBoom
	if w := e.do(req("s3cret")); w.Code != 503 {
		t.Fatalf("store error %d: %s", w.Code, w.Body.String())
	}
}

func postNonce(t *testing.T, nonce any, set bool) (string, store.Event, string) {
	t.Helper()
	e := newEnv(t, nil)
	body := stockBody(t)
	if set {
		body["nonce"] = nonce
	}
	w := e.do(thumbmarkReq(t, e.key, marshal(t, body)))
	if w.Code != http.StatusOK {
		t.Fatalf("code %d: %s", w.Code, w.Body.String())
	}
	resp := decodeResp(t, w)
	if len(e.store.events) != 1 {
		t.Fatalf("events %d", len(e.store.events))
	}
	tm, _ := resp["thumbmark"].(string)
	return tm, e.store.events[0], w.Body.String()
}

func TestThumbmarkNonce(t *testing.T) {
	baseTM, baseEv, _ := postNonce(t, nil, false)
	if baseEv.Nonce != "" || baseTM == "" {
		t.Fatalf("baseline nonce %q tm %q", baseEv.Nonce, baseTM)
	}
	tm, ev, raw := postNonce(t, "n-1", true)
	if ev.Nonce != "n-1" || tm != baseTM {
		t.Fatalf("nonce %q tm %q vs %q", ev.Nonce, tm, baseTM)
	}
	if strings.Contains(raw, "nonce") || strings.Contains(raw, "n-1") {
		t.Fatalf("response leaks nonce: %s", raw)
	}
	for name, v := range map[string]any{
		"numeric":  5,
		"too-long": strings.Repeat("a", 65),
		"control":  "a\tb",
	} {
		tm, ev, _ := postNonce(t, v, true)
		if ev.Nonce != "" || tm != baseTM {
			t.Fatalf("%s: nonce %q", name, ev.Nonce)
		}
	}
}

func widgetFS() fstest.MapFS {
	return fstest.MapFS{
		"loader.js":          {Data: []byte("/* loader */")},
		"frame.abcd1234.js":  {Data: []byte("/* frame */")},
		"frame.html":         {Data: []byte(`<script src="/widget/v1/{{.Bundle}}"></script>`)},
		"worker.ef012345.js": {Data: []byte("/* worker */")},
		"manifest.json":      {Data: []byte(`{"frame":"frame.abcd1234.js","worker":"worker.ef012345.js"}`)},
	}
}

func TestWidgetRoutes404WithoutAssets(t *testing.T) {
	e := newEnv(t, nil)
	for _, p := range []string{"/widget/v1/loader.js", "/widget/v1/frame?k=" + e.key, "/widget/v1/frame.abcd1234.js"} {
		wantError(t, e.do(httptest.NewRequest("GET", p, nil)), 404, "not_found")
	}
}

func TestWidgetLoaderAndBundle(t *testing.T) {
	e := newEnvWidget(t, nil, widgetFS())
	w := e.do(httptest.NewRequest("GET", "/widget/v1/loader.js", nil))
	if w.Code != 200 || w.Body.String() != "/* loader */" {
		t.Fatalf("loader %d %q", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/javascript; charset=utf-8" {
		t.Fatalf("loader Content-Type %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=300" {
		t.Fatalf("loader Cache-Control %q", cc)
	}
	etag := w.Header().Get("ETag")
	if etag == "" {
		t.Fatal("loader has no ETag")
	}
	r := httptest.NewRequest("GET", "/widget/v1/loader.js", nil)
	r.Header.Set("If-None-Match", etag)
	if w := e.do(r); w.Code != 304 || w.Body.Len() != 0 {
		t.Fatalf("conditional loader %d %q", w.Code, w.Body.String())
	}

	w = e.do(httptest.NewRequest("GET", "/widget/v1/frame.abcd1234.js", nil))
	if w.Code != 200 || w.Body.String() != "/* frame */" {
		t.Fatalf("bundle %d %q", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/javascript; charset=utf-8" {
		t.Fatalf("bundle Content-Type %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Fatalf("bundle Cache-Control %q", cc)
	}
	for _, p := range []string{"/widget/v1/other.js", "/widget/v1/frame.html", "/widget/v1/manifest.json"} {
		wantError(t, e.do(httptest.NewRequest("GET", p, nil)), 404, "not_found")
	}
}

func TestWidgetFrame(t *testing.T) {
	const csp = "; default-src 'none'; script-src 'self'; connect-src 'self'; worker-src 'self'"
	e := newEnvWidget(t, nil, widgetFS())
	w := e.do(httptest.NewRequest("GET", "/widget/v1/frame?k="+e.key, nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `src="/widget/v1/frame.abcd1234.js"`) {
		t.Fatalf("frame %d %q", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("frame Content-Type %q", ct)
	}
	if got := w.Header().Get("Content-Security-Policy"); got != "frame-ancestors *"+csp {
		t.Fatalf("frame CSP %q", got)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("frame Cache-Control %q", cc)
	}
	if _, ok := w.Header()["X-Frame-Options"]; ok {
		t.Fatal("frame sets X-Frame-Options")
	}

	e = newEnvWidget(t, func(_ *config.Config, s *fakeStore) {
		s.byID[keyID].AllowedOrigins = []string{"https://a.com", "https://*.b.com"}
	}, widgetFS())
	w = e.do(httptest.NewRequest("GET", "/widget/v1/frame?k="+e.key, nil))
	if got := w.Header().Get("Content-Security-Policy"); w.Code != 200 || got != "frame-ancestors https://a.com https://*.b.com"+csp {
		t.Fatalf("scoped frame %d CSP %q", w.Code, got)
	}

	unknown, _, _ := auth.GenerateKey()
	for name, q := range map[string]string{"unknown": "?k=" + unknown, "malformed": "?k=nope", "missing": ""} {
		w := e.do(httptest.NewRequest("GET", "/widget/v1/frame"+q, nil))
		if w.Code != 403 || w.Body.Len() != 0 {
			t.Fatalf("%s key: %d %q", name, w.Code, w.Body.String())
		}
	}

	e = newEnvWidget(t, func(_ *config.Config, s *fakeStore) {
		s.byID[keyID].RevokedAt = &testNow
	}, widgetFS())
	if w := e.do(httptest.NewRequest("GET", "/widget/v1/frame?k="+e.key, nil)); w.Code != 403 || w.Body.Len() != 0 {
		t.Fatalf("revoked key: %d %q", w.Code, w.Body.String())
	}

	e = newEnvWidget(t, func(_ *config.Config, s *fakeStore) { s.findErr = errBoom }, widgetFS())
	wantError(t, e.do(httptest.NewRequest("GET", "/widget/v1/frame?k="+e.key, nil)), 503, "store_unavailable")
}

func TestFrameAncestors(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{nil, "*"},
		{[]string{}, "*"},
		{[]string{"*"}, "*"},
		{[]string{"https://a.com", " https://b.com "}, "https://a.com https://b.com"},
	} {
		if got := frameAncestors(tc.in); got != tc.want {
			t.Errorf("frameAncestors(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// widgetReportReq is a /widget/report POST carrying thumbmarkReq's headers
// and an Origin the key is not scoped to.
func widgetReportReq(t *testing.T, key string, body []byte) *http.Request {
	t.Helper()
	r := thumbmarkReq(t, key, body)
	r.URL.Path, r.RequestURI = "/widget/report", "/widget/report"
	r.Header.Set("Origin", "https://nazr.example")
	return r
}

func widgetHolder(t *testing.T) *conn.Holder {
	return fullHolderOrder(t, append(slices.Clone(testHeaderOrder), "Origin"))
}

// mintTestChallenge mints a challenge for origin under testSigningKey, as the
// frame route would at e.now, and returns it with its id.
func mintTestChallenge(t *testing.T, e *env, origin string) (string, string) {
	t.Helper()
	return mintChallengeWith(t, e, testSigningKey, origin)
}

func mintChallengeWith(t *testing.T, e *env, k widgettoken.Key, origin string) (string, string) {
	t.Helper()
	return mintStagedChallenge(e, k, origin, e.cfg.PowBits, "")
}

// mintTestInteractiveChallenge mints a stage "interactive" challenge with the
// given difficulty, as the report handler's offer would.
func mintTestInteractiveChallenge(t *testing.T, e *env, origin string, bits int) (string, string) {
	t.Helper()
	return mintStagedChallenge(e, testSigningKey, origin, bits, widgettoken.StageInteractive)
}

// mintStagedChallenge mints a challenge bound to the test key id, as the
// frame route and the interactive offer do.
func mintStagedChallenge(e *env, k widgettoken.Key, origin string, bits int, stage string) (string, string) {
	id := ulid.Make().String()
	ch := widgettoken.MintChallenge(k.Secret, widgettoken.Challenge{ID: id,
		Expires: e.now.Add(widgetMatchWindow).Unix(), Bits: bits, Kid: k.Kid, Origin: origin, Key: keyID, Stage: stage})
	return ch, id
}

// otherKeyID is an API key id the test env does not authenticate as.
const otherKeyID = "22222222-2222-4222-8222-222222222222"

// widgetBody is a valid report body for challenge ch (id) with a solved
// proof-of-work and the stock client's components.
func widgetBody(t *testing.T, e *env, ch, id string) map[string]any {
	t.Helper()
	return map[string]any{"challenge": ch, "pow": widgettoken.SolvePoW(id, e.cfg.PowBits),
		"components": stockBody(t)["components"], "clientHash": "abc123"}
}

// postReport sends body as a widget report through a full TLS + h2 holder
// and returns the 200 JSON outcome.
func postReport(t *testing.T, e *env, body map[string]any, mod ...func(r *http.Request)) map[string]any {
	t.Helper()
	r := widgetReportReq(t, e.key, marshal(t, body))
	for _, m := range mod {
		m(r)
	}
	w := e.do(r.WithContext(WithHolder(r.Context(), widgetHolder(t))))
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("status %d type %q: %s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	return decodeResp(t, w)
}

func parseTestToken(t *testing.T, tok any) widgettoken.Claims {
	t.Helper()
	s, _ := tok.(string)
	c, err := widgettoken.Parse(s, func(kid string) (*ecdsa.PublicKey, bool) {
		if kid != testSigningKey.Kid {
			return nil, false
		}
		return &testSigningKey.Private.PublicKey, true
	})
	if err != nil {
		t.Fatalf("token %q: %v", s, err)
	}
	return c
}

func TestWidgetReportPass(t *testing.T) {
	e := newEnv(t, nil)
	ch, id := mintTestChallenge(t, e, "https://shop.example")
	out := postReport(t, e, widgetBody(t, e, ch, id))
	if out["verdict"] != "pass" || len(out) != 2 {
		t.Fatalf("outcome %v", out)
	}
	c := parseTestToken(t, out["token"])
	want := widgettoken.Claims{Issuer: "https://example.com", Audience: keyID, ID: id, IssuedAt: testNow.Unix(),
		Expires: testNow.Add(5 * time.Minute).Unix(), Hostname: "https://shop.example", Verdict: "pass"}
	if c != want {
		t.Fatalf("claims %+v want %+v", c, want)
	}
	if len(e.store.reports) != 1 || len(e.repo.visitors) != 0 || len(e.store.events) != 0 {
		t.Fatalf("reports %d visitors %v events %d", len(e.store.reports), e.repo.visitors, len(e.store.events))
	}
	rep := e.store.reports[0]
	if rep.ID != id || rep.Nonce != id || !rep.PowOK || rep.Verdict != "pass" || rep.Hostname != "https://shop.example" ||
		rep.TokenIssuedAt == nil || !rep.TokenIssuedAt.Equal(testNow) || rep.ClientHash != "abc123" || rep.APIKeyID != keyID {
		t.Fatalf("report %+v", rep)
	}
	var cls map[string]any
	if err := json.Unmarshal(rep.Classification, &cls); err != nil || cls["bot"] != false || cls["danger_level"] != float64(0) {
		t.Fatalf("classification %s: %v", rep.Classification, err)
	}
	var sig map[string]bool
	if err := json.Unmarshal(rep.Signals, &sig); err != nil || len(sig) == 0 {
		t.Fatalf("signals %s: %v", rep.Signals, err)
	}
	if _, ok := sig["canvas_probe_anomaly"]; ok {
		t.Fatalf("signals carry canvas_probe_anomaly: %s", rep.Signals)
	}
	if rep.IPHash != ipintel.Identifier(netip.MustParseAddr("203.0.113.42"), "salt") {
		t.Fatalf("ip hash %q", rep.IPHash)
	}
	if rep.JA4 == "" || rep.H2FP == "" || rep.UserAgent != chromeUA {
		t.Fatalf("ja4 %q h2fp %q ua %q", rep.JA4, rep.H2FP, rep.UserAgent)
	}
	if rep.IP == nil || rep.IP.String() != "203.0.113.42" || rep.Components != nil || !rep.CreatedAt.Equal(testNow) {
		t.Fatalf("ip %v components %s created %v", rep.IP, rep.Components, rep.CreatedAt)
	}

	// The same components and connection through /thumbmark, stabilizing
	// "private" and "iframe" like the frame client, hash the same.
	tb := stockBody(t)
	tb["options"] = map[string]any{"stabilize": []any{"private", "iframe"}}
	r := thumbmarkReq(t, e.key, marshal(t, tb))
	r.Header.Set("Origin", "https://nazr.example")
	w := e.do(r.WithContext(WithHolder(r.Context(), widgetHolder(t))))
	if w.Code != http.StatusOK {
		t.Fatalf("thumbmark %d: %s", w.Code, w.Body.String())
	}
	if tm := decodeResp(t, w)["thumbmark"]; tm != rep.Thumbmark {
		t.Fatalf("report thumbmark %q, /thumbmark %q", rep.Thumbmark, tm)
	}

	e = newEnv(t, func(c *config.Config, _ *fakeStore) {
		c.WidgetIssuer, c.StoreComponents, c.StoreIP = "https://nazr.example", true, "hash"
	})
	ch, id = mintTestChallenge(t, e, "https://shop.example")
	if c := parseTestToken(t, postReport(t, e, widgetBody(t, e, ch, id))["token"]); c.Issuer != "https://nazr.example" {
		t.Fatalf("issuer %q", c.Issuer)
	}
	rep = e.store.reports[0]
	var comps map[string]any
	if err := json.Unmarshal(rep.Components, &comps); err != nil || comps["tls"] == nil || comps["system"] == nil {
		t.Fatalf("components %s: %v", rep.Components, err)
	}
	if rep.IP != nil || rep.IPHash == "" {
		t.Fatalf("hash mode ip %v hash %q", rep.IP, rep.IPHash)
	}
}

func TestWidgetReportInconclusive(t *testing.T) {
	e := newEnv(t, nil)
	ch, id := mintTestChallenge(t, e, "https://shop.example")
	body := widgetBody(t, e, ch, id)
	comps := body["components"].(map[string]any)
	priv := maps.Clone(comps["privacy"].(map[string]any))
	priv["webdriver"] = true
	comps["privacy"] = priv
	if out := postReport(t, e, body); out["verdict"] != "inconclusive" || len(out) != 1 {
		t.Fatalf("webdriver outcome %v", out)
	}
	if rep := e.store.reports[0]; rep.Verdict != "inconclusive" || rep.TokenIssuedAt != nil || !rep.PowOK {
		t.Fatalf("report %+v", rep)
	}

	noLang := func(r *http.Request) { r.Header.Del("Accept-Language") }
	for maxDanger, want := range map[int]string{0: "inconclusive", 2: "pass"} {
		e := newEnv(t, func(c *config.Config, _ *fakeStore) { c.WidgetPassMaxDanger = maxDanger })
		ch, id := mintTestChallenge(t, e, "https://shop.example")
		out := postReport(t, e, widgetBody(t, e, ch, id), noLang)
		if out["verdict"] != want {
			t.Fatalf("max danger %d: outcome %v, want %s", maxDanger, out, want)
		}
		if (out["token"] != nil) != (want == "pass") {
			t.Fatalf("max danger %d: token %v", maxDanger, out["token"])
		}
		var cls map[string]any
		_ = json.Unmarshal(e.store.reports[0].Classification, &cls)
		if cls["danger_level"] != float64(1) || cls["bot"] != false {
			t.Fatalf("classification %v", cls)
		}
	}
}

func TestWidgetReportInteractiveOffer(t *testing.T) {
	noLang := func(r *http.Request) { r.Header.Del("Accept-Language") }
	setup := func(interactive bool) *env {
		return newEnv(t, func(c *config.Config, _ *fakeStore) {
			c.WidgetPassMaxDanger = 0
			c.WidgetInteractive = interactive
			c.WidgetInteractiveExtraBits = 4
		})
	}

	e := setup(true)
	ch, id := mintTestChallenge(t, e, "https://shop.example")
	out := postReport(t, e, widgetBody(t, e, ch, id), noLang)
	if out["verdict"] != "inconclusive" || out["token"] != nil {
		t.Fatalf("outcome %v", out)
	}
	offer, _ := out["interactive"].(map[string]any)
	// ttl_ms is the challenge's remaining life by the server's clock.
	if offer == nil || len(offer) != 3 || fmt.Sprint(offer["bits"]) != strconv.Itoa(e.cfg.PowBits+4) ||
		fmt.Sprint(offer["ttl_ms"]) != "600000" {
		t.Fatalf("offer %v", out["interactive"])
	}
	got, err := widgettoken.ParseChallenge(offer["challenge"].(string), func(kid string) ([]byte, bool) {
		return testSigningKey.Secret, kid == testSigningKey.Kid
	}, e.now)
	if err != nil {
		t.Fatalf("offer challenge: %v", err)
	}
	orig, _ := widgettoken.ParseChallenge(ch, func(string) ([]byte, bool) { return testSigningKey.Secret, true }, e.now)
	if got.Stage != widgettoken.StageInteractive || got.ID != id || got.Expires != orig.Expires ||
		got.Origin != "https://shop.example" || got.Kid != testSigningKey.Kid || got.Bits != e.cfg.PowBits+4 ||
		got.Key != keyID {
		t.Fatalf("offer %+v", got)
	}
	if rep := e.store.reports[0]; rep.Verdict != "inconclusive" || rep.TokenIssuedAt != nil {
		t.Fatalf("report %+v", rep)
	}

	// Reported four minutes after the frame minted it: six minutes left.
	ch, id = mintTestChallenge(t, e, "https://shop.example")
	e.now = testNow.Add(4 * time.Minute)
	out = postReport(t, e, widgetBody(t, e, ch, id), noLang)
	if offer, _ := out["interactive"].(map[string]any); offer == nil || fmt.Sprint(offer["ttl_ms"]) != "360000" {
		t.Fatalf("late offer %v", out["interactive"])
	}
	e.now = testNow

	// A bot is not offered the step.
	ch, id = mintTestChallenge(t, e, "https://shop.example")
	body := widgetBody(t, e, ch, id)
	comps := body["components"].(map[string]any)
	priv := maps.Clone(comps["privacy"].(map[string]any))
	priv["webdriver"] = true
	comps["privacy"] = priv
	if out := postReport(t, e, body); out["verdict"] != "inconclusive" || out["interactive"] != nil {
		t.Fatalf("webdriver outcome %v", out)
	}

	// Disabled.
	e = setup(false)
	ch, id = mintTestChallenge(t, e, "https://shop.example")
	if out := postReport(t, e, widgetBody(t, e, ch, id), noLang); out["verdict"] != "inconclusive" || out["interactive"] != nil {
		t.Fatalf("disabled outcome %v", out)
	}

	// A pass carries a token and no offer.
	e = newEnv(t, func(c *config.Config, _ *fakeStore) { c.WidgetInteractive = true })
	ch, id = mintTestChallenge(t, e, "https://shop.example")
	if out := postReport(t, e, widgetBody(t, e, ch, id)); out["verdict"] != "pass" || out["interactive"] != nil {
		t.Fatalf("pass outcome %v", out)
	}

	// A failed insert offers nothing.
	e = setup(true)
	e.store.reportErr = errBoom
	ch, id = mintTestChallenge(t, e, "https://shop.example")
	if out := postReport(t, e, widgetBody(t, e, ch, id), noLang); out["verdict"] != "inconclusive" || out["interactive"] != nil {
		t.Fatalf("store error outcome %v", out)
	}
}

func TestWidgetReportRejectsStagedChallenge(t *testing.T) {
	e := newEnv(t, nil)
	ch, id := mintTestInteractiveChallenge(t, e, "https://shop.example", e.cfg.PowBits)
	if out := postReport(t, e, widgetBody(t, e, ch, id)); out["verdict"] != "invalid" || len(out) != 1 {
		t.Fatalf("outcome %v", out)
	}
	if len(e.store.reports) != 0 {
		t.Fatalf("stored %+v", e.store.reports)
	}
}

func TestWidgetReportKeyBinding(t *testing.T) {
	mint := func(e *env, key string) (string, string) {
		id := ulid.Make().String()
		return widgettoken.MintChallenge(testSigningKey.Secret, widgettoken.Challenge{ID: id,
			Expires: e.now.Add(widgetMatchWindow).Unix(), Bits: e.cfg.PowBits, Kid: testSigningKey.Kid,
			Origin: "https://shop.example", Key: key}), id
	}

	// Minted for another key: invalid, nothing stored.
	e := newEnv(t, nil)
	ch, id := mint(e, otherKeyID)
	if out := postReport(t, e, widgetBody(t, e, ch, id)); out["verdict"] != "invalid" || len(out) != 1 {
		t.Fatalf("other key outcome %v", out)
	}
	if len(e.store.reports) != 0 {
		t.Fatalf("stored %+v", e.store.reports)
	}

	// Minted before the binding (no key): accepted for its window.
	ch, id = mint(e, "")
	if out := postReport(t, e, widgetBody(t, e, ch, id)); out["verdict"] != "pass" || out["token"] == nil {
		t.Fatalf("keyless outcome %v", out)
	}
	if len(e.store.reports) != 1 || e.store.reports[0].ID != id {
		t.Fatalf("stored %+v", e.store.reports)
	}
}

func TestWidgetReportPowFailed(t *testing.T) {
	e := newEnv(t, nil)
	ch, id := mintTestChallenge(t, e, "https://shop.example")
	bad := ""
	for i := 0; ; i++ {
		if c := strconv.Itoa(i); !widgettoken.VerifyPoW(id, c, e.cfg.PowBits) {
			bad = c
			break
		}
	}
	body := widgetBody(t, e, ch, id)
	body["pow"] = bad
	if out := postReport(t, e, body); out["verdict"] != "pow_failed" || len(out) != 1 {
		t.Fatalf("outcome %v", out)
	}
	if len(e.store.reports) != 1 {
		t.Fatalf("reports %d", len(e.store.reports))
	}
	if rep := e.store.reports[0]; rep.PowOK || rep.Verdict != "pow_failed" || rep.TokenIssuedAt != nil || rep.ID != id {
		t.Fatalf("report %+v", rep)
	}
}

func TestWidgetReportInvalid(t *testing.T) {
	invalid := func(t *testing.T, e *env, body map[string]any) {
		t.Helper()
		if out := postReport(t, e, body); out["verdict"] != "invalid" || len(out) != 1 {
			t.Fatalf("outcome %v", out)
		}
		if len(e.store.reports) != 0 {
			t.Fatalf("stored %+v", e.store.reports)
		}
	}
	for name, mut := range map[string]func(e *env, b map[string]any){
		"tampered mac": func(_ *env, b map[string]any) {
			// Flip the MAC's first character: its last one carries
			// padding bits a decoder may ignore.
			payload, mac, _ := strings.Cut(b["challenge"].(string), ".")
			first := "A"
			if mac[0] == 'A' {
				first = "B"
			}
			b["challenge"] = payload + "." + first + mac[1:]
		},
		"expired":           func(e *env, _ map[string]any) { e.now = testNow.Add(11 * time.Minute) },
		"long challenge":    func(_ *env, b map[string]any) { b["challenge"] = strings.Repeat("a", 513) },
		"empty challenge":   func(_ *env, b map[string]any) { b["challenge"] = "" },
		"non-digit pow":     func(_ *env, b map[string]any) { b["pow"] = "12a" },
		"long pow":          func(_ *env, b map[string]any) { b["pow"] = strings.Repeat("1", 33) },
		"numeric pow":       func(_ *env, b map[string]any) { b["pow"] = 12 },
		"missing comps":     func(_ *env, b map[string]any) { delete(b, "components") },
		"string comps":      func(_ *env, b map[string]any) { b["components"] = "x" },
		"numeric hash":      func(_ *env, b map[string]any) { b["clientHash"] = 5 },
		"bad hash":          func(_ *env, b map[string]any) { b["clientHash"] = "zz" },
		"empty hash":        func(_ *env, b map[string]any) { b["clientHash"] = "" },
		"phase 1 body":      func(_ *env, b map[string]any) { delete(b, "challenge"); delete(b, "pow"); b["nonce"] = "n-1" },
		"missing challenge": func(_ *env, b map[string]any) { delete(b, "challenge") },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			ch, id := mintTestChallenge(t, e, "https://shop.example")
			body := widgetBody(t, e, ch, id)
			mut(e, body)
			invalid(t, e, body)
		})
	}

	t.Run("unknown kid", func(t *testing.T) {
		e := newEnv(t, nil)
		other := testSigningKey
		other.Kid = "nope"
		ch, id := mintChallengeWith(t, e, other, "https://shop.example")
		invalid(t, e, widgetBody(t, e, ch, id))
	})

	t.Run("no signing", func(t *testing.T) {
		e := newEnvWidgetSigning(t, nil, nil, nil)
		ch, id := mintTestChallenge(t, e, "https://shop.example")
		invalid(t, e, widgetBody(t, e, ch, id))
	})

	t.Run("reused challenge", func(t *testing.T) {
		e := newEnv(t, nil)
		ch, id := mintTestChallenge(t, e, "https://shop.example")
		body := widgetBody(t, e, ch, id)
		first := postReport(t, e, body)
		if first["verdict"] != "pass" {
			t.Fatalf("first %v", first)
		}
		if out := postReport(t, e, body); out["verdict"] != "invalid" || len(out) != 1 {
			t.Fatalf("second %v", out)
		}
		if len(e.store.reports) != 1 {
			t.Fatalf("reports %d", len(e.store.reports))
		}
		parseTestToken(t, first["token"])
	})

	retired := testNow.Add(-time.Hour)
	old := testSigningKey
	old.Kid, old.Secret, old.CreatedAt, old.RetiredAt = "old", []byte("fedcba9876543210fedcba9876543210"), testNow.Add(-48*time.Hour), &retired
	t.Run("retired key in grace", func(t *testing.T) {
		e := newEnvWidgetSigning(t, nil, nil, widgettoken.NewStaticKeyring(testSigningKey, old))
		ch, id := mintChallengeWith(t, e, old, "https://shop.example")
		out := postReport(t, e, widgetBody(t, e, ch, id))
		if out["verdict"] != "pass" {
			t.Fatalf("outcome %v", out)
		}
		if c := parseTestToken(t, out["token"]); c.ID != id {
			t.Fatalf("claims %+v", c)
		}
	})
	t.Run("retired key past grace", func(t *testing.T) {
		e := newEnvWidgetSigning(t, nil, nil, widgettoken.NewStaticKeyring(testSigningKey))
		ch, id := mintChallengeWith(t, e, old, "https://shop.example")
		invalid(t, e, widgetBody(t, e, ch, id))
	})
}

func TestWidgetReportStoreError(t *testing.T) {
	e := newEnv(t, nil)
	e.store.reportErr = errBoom
	ch, id := mintTestChallenge(t, e, "https://shop.example")
	if out := postReport(t, e, widgetBody(t, e, ch, id)); out["verdict"] != "inconclusive" || len(out) != 1 {
		t.Fatalf("outcome %v", out)
	}
}

func TestWidgetReportScopedKey(t *testing.T) {
	e := newEnv(t, func(_ *config.Config, s *fakeStore) { s.byID[keyID].AllowedOrigins = []string{"https://a.com"} })
	ch, id := mintTestChallenge(t, e, "https://a.com")
	if out := postReport(t, e, widgetBody(t, e, ch, id)); out["verdict"] != "pass" {
		t.Fatalf("widget report %v", out)
	}
	if len(e.store.reports) != 1 {
		t.Fatalf("reports %d", len(e.store.reports))
	}
	r := thumbmarkReq(t, e.key, marshal(t, stockBody(t)))
	r.Header.Set("Origin", "https://nazr.example")
	wantError(t, e.do(r), 403, "origin_not_allowed")
}

func TestWidgetReportRejectsBody(t *testing.T) {
	// Each body is rejected by validation or size: 200 "invalid", nothing
	// stored; "control" proves a valid body under the same limit is stored.
	const limit = 1024
	for name, body := range map[string]string{
		"array":          `[]`,
		"empty":          `{}`,
		"not json":       `{`,
		"over the limit": `{"challenge":"c","pow":"1","components":{"x":"` + strings.Repeat("a", 2*limit) + `"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, func(c *config.Config, _ *fakeStore) { c.BodyLimit = limit })
			w := e.do(widgetReportReq(t, e.key, []byte(body)))
			if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"verdict":"invalid"}` {
				t.Fatalf("status %d: %q", w.Code, w.Body.String())
			}
			if len(e.store.reports) != 0 {
				t.Fatalf("stored %+v", e.store.reports)
			}
		})
	}

	t.Run("control", func(t *testing.T) {
		e := newEnv(t, func(c *config.Config, _ *fakeStore) { c.BodyLimit = limit })
		ch, id := mintTestChallenge(t, e, "")
		body := map[string]any{"challenge": ch, "pow": widgettoken.SolvePoW(id, e.cfg.PowBits), "components": map[string]any{"a": 1}}
		if b := marshal(t, body); len(b) > limit {
			t.Fatalf("control body %d bytes exceeds the limit", len(b))
		}
		w := e.do(widgetReportReq(t, e.key, marshal(t, body)))
		if w.Code != http.StatusOK || len(e.store.reports) != 1 {
			t.Fatalf("status %d reports %d: %s", w.Code, len(e.store.reports), w.Body.String())
		}
	})

	e := newEnv(t, func(c *config.Config, _ *fakeStore) { c.DefaultRateLimit = 1 })
	ch, id := mintTestChallenge(t, e, "")
	wantError(t, e.do(widgetReportReq(t, "", marshal(t, widgetBody(t, e, ch, id)))), 403, "unauthorized")
	if w := e.do(widgetReportReq(t, e.key, marshal(t, widgetBody(t, e, ch, id)))); w.Code != http.StatusOK {
		t.Fatalf("first %d", w.Code)
	}
	ch, id = mintTestChallenge(t, e, "")
	if w := e.do(widgetReportReq(t, e.key, marshal(t, widgetBody(t, e, ch, id)))); w.Code != http.StatusTooManyRequests {
		t.Fatalf("second %d, want 429", w.Code)
	}
	if len(e.store.reports) != 1 {
		t.Fatalf("reports %d", len(e.store.reports))
	}
}

func TestAdminWidgetSummary(t *testing.T) {
	e := newEnv(t, func(c *config.Config, _ *fakeStore) { c.AdminToken = "s3cret" })
	req := func(token string) *http.Request {
		r := httptest.NewRequest("GET", "/admin/keys/key-1/widget", nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		return r
	}
	wantError(t, e.do(req("")), 403, "unauthorized")

	e.store.summary = store.WidgetSummary{Reports: 10, Matched: 7, Unmatched: 3, IPMismatch: 1, JA4Mismatch: 2, JA4Unknown: 4,
		UAMismatch: 5, EventsUnmatched: 6, Pass: 7, Inconclusive: 2, PowFailed: 1, Verified: 3, Replayed: 1, Interactive: 4, InteractiveFailed: 2,
		InteractionSignals: map[string]int64{"untrusted_event": 2, "too_fast": 1}}
	w := e.do(req("s3cret"))
	if w.Code != 200 {
		t.Fatalf("summary %d: %s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"window_days": float64(30), "reports": float64(10), "matched": float64(7), "unmatched": float64(3),
		"events_unmatched": float64(6), "ip_mismatch": float64(1), "ja4_mismatch": float64(2), "ja4_unknown": float64(4), "ua_mismatch": float64(5),
		"pass": float64(7), "inconclusive": float64(2), "pow_failed": float64(1), "verified": float64(3), "replayed": float64(1),
		"interactive": float64(4), "interactive_failed": float64(2),
		"interaction_signals": map[string]any{"untrusted_event": float64(2), "too_fast": float64(1)}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("body %v", got)
	}
	// A nil map from the store still serializes as an empty object.
	e.store.summary = store.WidgetSummary{}
	w = e.do(req("s3cret"))
	if !strings.Contains(w.Body.String(), `"interaction_signals":{}`) {
		t.Fatalf("empty signals: %s", w.Body.String())
	}

	if e.store.summaryKeyID != "key-1" || e.store.summaryWindow != 10*time.Minute ||
		!e.store.summarySince.Equal(testNow.Add(-30*24*time.Hour)) {
		t.Fatalf("args %q %v %v", e.store.summaryKeyID, e.store.summarySince, e.store.summaryWindow)
	}

	e.store.summaryErr = errBoom
	wantError(t, e.do(req("s3cret")), 503, "store_unavailable")
}

func challengeFS() fstest.MapFS {
	fsys := widgetFS()
	fsys["frame.html"] = &fstest.MapFile{Data: []byte(`<script src="/widget/v1/{{.Bundle}}" data-worker="/widget/v1/{{.Worker}}" data-challenge="{{.Challenge}}" data-pow-bits="{{.PowBits}}" data-origin="{{.Origin}}"></script>`)}
	return fsys
}

func attr(t *testing.T, html, name string) string {
	t.Helper()
	m := regexp.MustCompile(name + `="([^"]*)"`).FindStringSubmatch(html)
	if m == nil {
		t.Fatalf("no %s attribute in %s", name, html)
	}
	return m[1]
}

func TestWidgetFrameChallenge(t *testing.T) {
	e := newEnvWidget(t, nil, challengeFS())
	r := httptest.NewRequest("GET", "/widget/v1/frame?k="+e.key, nil)
	r.Header.Set("Referer", "https://shop.example/cart")
	w := e.do(r)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	c, err := widgettoken.ParseChallenge(attr(t, body, "data-challenge"),
		func(kid string) ([]byte, bool) { return testSigningKey.Secret, kid == "test" }, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.ID) != 26 || c.Expires != testNow.Add(10*time.Minute).Unix() || c.Bits != e.cfg.PowBits ||
		c.Kid != "test" || c.Origin != "https://shop.example" || c.Key != keyID {
		t.Fatalf("challenge %+v", c)
	}
	if got := attr(t, body, "data-pow-bits"); got != strconv.Itoa(e.cfg.PowBits) {
		t.Fatalf("pow bits %q", got)
	}
	if got := attr(t, body, "data-worker"); got != "/widget/v1/worker.ef012345.js" {
		t.Fatalf("worker %q", got)
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.HasSuffix(csp, "; worker-src 'self'") {
		t.Fatalf("csp %q", csp)
	}

	w = e.do(httptest.NewRequest("GET", "/widget/v1/frame?k="+e.key, nil))
	if w.Code != 200 || attr(t, w.Body.String(), "data-origin") != "" {
		t.Fatalf("no referer: %d %s", w.Code, w.Body.String())
	}

	e = newEnvWidgetSigning(t, nil, challengeFS(), nil)
	wantError(t, e.do(httptest.NewRequest("GET", "/widget/v1/frame?k="+e.key, nil)), 503, "signing_unavailable")

	// A lone key that has not activated is not used (EnsureSigningKey never
	// stores one; the route answers as if there were no key).
	pending := testSigningKey
	pending.ActivatesAt = testNow.Add(time.Minute)
	e = newEnvWidgetSigning(t, nil, challengeFS(), widgettoken.NewStaticKeyring(pending))
	wantError(t, e.do(httptest.NewRequest("GET", "/widget/v1/frame?k="+e.key, nil)), 503, "signing_unavailable")
}

// TestWidgetSigningPublishWindow follows a rotation: during the publish hour
// the outgoing key mints challenges and signs tokens, and both keys are in
// the JWKS; after it the new key takes over.
func TestWidgetSigningPublishWindow(t *testing.T) {
	sk, err := widgettoken.Generate(testNow)
	if err != nil {
		t.Fatal(err)
	}
	switchAt := testNow.Add(widgettoken.SigningKeyPublish)
	sk.ActivatesAt = switchAt
	next, err := widgettoken.FromStored(sk)
	if err != nil {
		t.Fatal(err)
	}
	old := testSigningKey
	old.RetiredAt = &switchAt
	e := newEnvWidgetSigning(t, nil, challengeFS(), widgettoken.NewStaticKeyring(old, next))
	frameKid := func() string {
		t.Helper()
		w := e.do(httptest.NewRequest("GET", "/widget/v1/frame?k="+e.key, nil))
		if w.Code != 200 {
			t.Fatalf("frame %d: %s", w.Code, w.Body.String())
		}
		payload, _, _ := strings.Cut(attr(t, w.Body.String(), "data-challenge"), ".")
		pb, _ := base64.RawURLEncoding.DecodeString(payload)
		var c widgettoken.Challenge
		if err := json.Unmarshal(pb, &c); err != nil {
			t.Fatal(err)
		}
		return c.Kid
	}

	if got := frameKid(); got != old.Kid {
		t.Fatalf("frame kid in publish hour %q", got)
	}
	w := e.do(httptest.NewRequest("GET", "/widget/v1/jwks.json", nil))
	var jwks widgettoken.JWKS
	if err := json.Unmarshal(w.Body.Bytes(), &jwks); err != nil || len(jwks.Keys) != 2 {
		t.Fatalf("jwks %s %v", w.Body.String(), err)
	}
	ch, id := mintChallengeWith(t, e, old, "https://shop.example")
	out := postReport(t, e, widgetBody(t, e, ch, id))
	if out["verdict"] != "pass" {
		t.Fatalf("outcome %v", out)
	}
	if c := parseTestToken(t, out["token"]); c.ID != id {
		t.Fatalf("claims %+v", c)
	}

	e.now = switchAt
	if got := frameKid(); got != next.Kid {
		t.Fatalf("frame kid after publish hour %q", got)
	}
}

func TestWidgetBundleServesWorker(t *testing.T) {
	e := newEnvWidget(t, nil, widgetFS())
	w := e.do(httptest.NewRequest("GET", "/widget/v1/worker.ef012345.js", nil))
	if w.Code != 200 || w.Body.String() != "/* worker */" {
		t.Fatalf("worker %d %q", w.Code, w.Body.String())
	}
	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Fatalf("Cache-Control %q", cc)
	}
	for name, mf := range map[string]string{
		"missing":      `{"frame":"frame.abcd1234.js"}`,
		"empty":        `{"frame":"frame.abcd1234.js","worker":""}`,
		"missing file": `{"frame":"frame.abcd1234.js","worker":"nope.js"}`,
	} {
		fsys := widgetFS()
		fsys["manifest.json"] = &fstest.MapFile{Data: []byte(mf)}
		e := newEnvWidget(t, nil, fsys)
		for _, p := range []string{"/widget/v1/loader.js", "/widget/v1/frame?k=" + e.key, "/widget/v1/frame.abcd1234.js"} {
			if w := e.do(httptest.NewRequest("GET", p, nil)); w.Code != 404 {
				t.Fatalf("%s %s: %d", name, p, w.Code)
			}
		}
	}
}

func TestJWKS(t *testing.T) {
	e := newEnv(t, nil)
	w := e.do(httptest.NewRequest("GET", "/widget/v1/jwks.json", nil))
	if w.Code != 200 || w.Header().Get("Cache-Control") != "public, max-age=3600" ||
		w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("jwks %d %v", w.Code, w.Header())
	}
	var got struct {
		Keys []struct{ Kid, Kty, Crv string }
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Keys) != 1 || got.Keys[0].Kid != "test" || got.Keys[0].Kty != "EC" || got.Keys[0].Crv != "P-256" {
		t.Fatalf("keys %+v", got.Keys)
	}
	e = newEnvWidgetSigning(t, nil, nil, nil)
	wantError(t, e.do(httptest.NewRequest("GET", "/widget/v1/jwks.json", nil)), 404, "not_found")
}
