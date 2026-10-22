package httpfp

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func h12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func chromeReq() (*http.Request, []string) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Host", "x.test")
	r.Header.Set("User-Agent", "UA")
	r.Header.Set("Accept", "*/*")
	r.Header.Set("Accept-Language", "en-US,en;q=0.9")
	r.Header.Set("Referer", "https://x.test/")
	r.Header.Set("Cookie", "b=2; a=1")
	return r, []string{"Host", "User-Agent", "Accept", "Referer", "Accept-Language", "Cookie"}
}

func TestJA4HChromeLike(t *testing.T) {
	r, order := chromeReq()
	got := JA4HFull(r, order)
	parts := strings.Split(got, "_")
	if len(parts) != 4 {
		t.Fatalf("got %q", got)
	}
	if parts[0] != "ge11cr04enus" {
		t.Fatalf("prefix %q", parts[0])
	}
	if parts[1] != h12("Host,User-Agent,Accept,Accept-Language") {
		t.Fatalf("b %q", parts[1])
	}
	if parts[2] != h12("a,b") {
		t.Fatalf("c %q", parts[2])
	}
	if parts[3] != h12("a=1,b=2") {
		t.Fatalf("d %q", parts[3])
	}
}

func TestJA4HNoCookiesNoReferer(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	got := JA4HFull(r, []string{"Host", "Accept"})
	want := "po11nn02" + "0000" + "_" + h12("Host,Accept") + "_000000000000_000000000000"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestJA4HH2AndPadding(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.ProtoMajor, r.ProtoMinor = 2, 0
	r.Header.Set("Accept-Language", "fr")
	got := JA4HFull(r, []string{"accept-language", ":path"})
	if !strings.HasPrefix(got, "ge20nn01fr00_") || !strings.Contains(got, h12("accept-language")) {
		t.Fatalf("got %q", got)
	}
}

func TestJA4HFallbackDeterministic(t *testing.T) {
	r, _ := chromeReq()
	a, b := JA4HFull(r, nil), JA4HFull(r, nil)
	if a != b || !strings.Contains(a, h12("Accept,Accept-Language,Host,User-Agent")) {
		t.Fatalf("got %q", a)
	}
}

func TestComponentJA4HIsCookieFree(t *testing.T) {
	r, order := chromeReq()
	full := JA4HFull(r, order)
	parts := strings.Split(full, "_")
	if len(parts) != 4 || parts[2] == emptyHash {
		t.Fatalf("fixture must carry cookies: %s", full)
	}
	c := Component(r, order)
	stableA := parts[0][:4] + "nn" + parts[0][6:]
	if c["ja4h"] != stableA+"_"+parts[1] || JA4HStable(r, order) != c["ja4h"] {
		t.Fatalf("component ja4h %v, want %s_%s", c["ja4h"], stableA, parts[1])
	}
	r.Header.Set("Cookie", "session=rotated; _ga=other")
	if Component(r, order)["ja4h"] != c["ja4h"] {
		t.Fatal("cookie rotation changed the component ja4h")
	}
	if JA4HFull(r, order) == full {
		t.Fatal("cookie rotation should change the full ja4h")
	}
	r.Header.Set("Referer", "https://other.test/page")
	if Component(r, order)["ja4h"] != c["ja4h"] {
		t.Fatal("a different referer changed the component ja4h")
	}
}

func TestJA4HStableIgnoresCookieAndReferer(t *testing.T) {
	order := []string{"Host", "User-Agent", "Accept", "Accept-Language"}
	build := func(cookie, referer bool) (*http.Request, []string) {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Host", "x.test")
		r.Header.Set("User-Agent", "UA")
		r.Header.Set("Accept", "*/*")
		r.Header.Set("Accept-Language", "en-US,en;q=0.9")
		o := append([]string{}, order...)
		if cookie {
			r.Header.Set("Cookie", "a=1; b=2")
			o = append(o, "Cookie")
		}
		if referer {
			r.Header.Set("Referer", "https://example.com/")
			o = append(o, "Referer")
		}
		return r, o
	}
	var stables []string
	for _, f := range [][2]bool{{false, false}, {true, false}, {false, true}, {true, true}} {
		r, o := build(f[0], f[1])
		s := JA4HStable(r, o)
		if s[4:6] != "nn" {
			t.Fatalf("flags not normalized: %q", s)
		}
		stables = append(stables, s)
	}
	for _, s := range stables[1:] {
		if s != stables[0] {
			t.Fatalf("stable forms differ: %v", stables)
		}
	}
	r1, o1 := build(false, false)
	r4, o4 := build(true, true)
	f1, f4 := JA4HFull(r1, o1), JA4HFull(r4, o4)
	if f1 == f4 || f1[4:6] != "nn" || f4[4:6] != "cr" {
		t.Fatalf("full forms: %q %q", f1, f4)
	}
}

func TestAcceptLanguageQ(t *testing.T) {
	r, order := chromeReq()
	c := Component(r, order)
	al := c["acceptLanguage"].(map[string]any)
	if al["raw"] != "en-US,en;q=0.9" {
		t.Fatalf("%v", al)
	}
	want := map[string]any{"en-US": float64(1), "en": 0.9}
	if !reflect.DeepEqual(al["q"], want) {
		t.Fatalf("%#v", al["q"])
	}
	if !reflect.DeepEqual(c["order"], []string{"host", "user-agent", "accept", "referer", "accept-language", "cookie"}) {
		t.Fatalf("%v", c["order"])
	}
	if c["userAgent"] != "UA" || c["accept"] != "*/*" {
		t.Fatalf("%v", c)
	}
	if _, ok := c["acceptEncoding"]; ok {
		t.Fatal("acceptEncoding should be omitted")
	}
	if _, ok := c["clientHints"]; ok {
		t.Fatal("clientHints should be omitted")
	}
}

func TestClientHintsOmittedWhenAbsent(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	c := Component(r, nil)
	for _, k := range []string{"clientHints", "userAgent", "accept", "acceptEncoding", "acceptLanguage"} {
		if _, ok := c[k]; ok {
			t.Fatalf("%s present", k)
		}
	}
	if o, ok := c["order"].([]string); !ok || o == nil {
		t.Fatalf("order %#v", c["order"])
	}
	r.Header.Set("Sec-CH-UA", `"Chromium";v="1"`)
	r.Header.Set("Sec-CH-UA-Mobile", "?0")
	ch := Component(r, nil)["clientHints"].(map[string]any)
	if !reflect.DeepEqual(ch, map[string]any{"ua": `"Chromium";v="1"`, "mobile": "?0"}) {
		t.Fatalf("%#v", ch)
	}
}
