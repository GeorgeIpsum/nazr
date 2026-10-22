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
	if c["ja4h"] != parts[0]+"_"+parts[1] || JA4HStable(r, order) != c["ja4h"] {
		t.Fatalf("component ja4h %v, want %s_%s", c["ja4h"], parts[0], parts[1])
	}
	r.Header.Set("Cookie", "session=rotated; _ga=other")
	if Component(r, order)["ja4h"] != c["ja4h"] {
		t.Fatal("cookie rotation changed the component ja4h")
	}
	if JA4HFull(r, order) == full {
		t.Fatal("cookie rotation should change the full ja4h")
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
