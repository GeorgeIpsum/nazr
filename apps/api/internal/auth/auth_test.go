package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"
	"time"

	"nazr/api/internal/store"
)

const testKey = "nzr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestGenerateKeyFormat(t *testing.T) {
	plain, hash, prefix := GenerateKey()
	if !regexp.MustCompile(`^nzr_[a-z2-7]{52}$`).MatchString(plain) {
		t.Fatalf("bad key %q", plain)
	}
	if len(prefix) != 8 || prefix != plain[4:12] {
		t.Fatalf("bad prefix %q", prefix)
	}
	sum := sha256.Sum256([]byte(plain))
	if hash != hex.EncodeToString(sum[:]) || hash != HashKey(plain) {
		t.Fatalf("bad hash %q", hash)
	}
	p2, _, _ := GenerateKey()
	if p2 == plain {
		t.Fatal("keys must be random")
	}
}

func TestOriginAllowed(t *testing.T) {
	tests := []struct {
		name    string
		origin  string
		allowed []string
		want    bool
	}{
		{"empty list allows all", "https://x.com", nil, true},
		{"empty list allows empty origin", "", nil, true},
		{"empty origin with list", "", []string{"https://a.com"}, false},
		{"exact", "https://a.com", []string{"https://a.com"}, true},
		{"case-insensitive", "https://A.com", []string{"https://a.COM"}, true},
		{"scheme mismatch", "http://a.com", []string{"https://a.com"}, false},
		{"port mismatch", "https://a.com:8443", []string{"https://a.com"}, false},
		{"port match", "https://a.com:8443", []string{"https://a.com:8443"}, true},
		{"wildcard sub", "https://a.example.com", []string{"https://*.example.com"}, true},
		{"wildcard multi", "https://a.b.example.com", []string{"https://*.example.com"}, true},
		{"wildcard apex", "https://example.com", []string{"https://*.example.com"}, false},
		{"wildcard suffix trick", "https://evilexample.com", []string{"https://*.example.com"}, false},
		{"wildcard scheme", "http://a.example.com", []string{"https://*.example.com"}, false},
		{"wildcard port", "https://a.example.com:81", []string{"https://*.example.com"}, false},
		{"star any", "https://anything.io", []string{"*"}, true},
		{"star empty origin", "", []string{"*"}, false},
		{"null never", "null", []string{"https://a.com"}, false},
		{"null vs star", "null", []string{"*"}, false},
		{"second entry", "https://b.com", []string{"https://a.com", "https://b.com"}, true},
		{"uppercase origin", "HTTPS://EXAMPLE.COM", []string{"https://example.com"}, true},
		{"suffix host", "https://example.com.evil", []string{"https://example.com"}, false},
		{"userinfo", "https://x@example.com", []string{"https://example.com"}, false},
		{"path", "https://example.com/foo", []string{"https://example.com"}, false},
		{"query", "https://example.com?a=1", []string{"https://example.com"}, false},
		{"trailing slash origin", "https://example.com/", []string{"https://example.com"}, true},
		{"trailing slash entry", "https://a.com", []string{"https://a.com/"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := OriginAllowed(tc.origin, tc.allowed); got != tc.want {
				t.Fatalf("OriginAllowed(%q,%v)=%v want %v", tc.origin, tc.allowed, got, tc.want)
			}
		})
	}
}

func TestMemoryLimiter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 10, 0, time.UTC)
	l := NewMemoryLimiter(func() time.Time { return now })
	ctx := context.Background()
	for i := range 600 {
		ok, _, err := l.Allow(ctx, "k", 600)
		if err != nil || !ok {
			t.Fatalf("call %d denied", i)
		}
	}
	ok, retry, _ := l.Allow(ctx, "k", 600)
	if ok || retry <= 0 || retry > time.Minute {
		t.Fatalf("expected deny with retry, got ok=%v retry=%v", ok, retry)
	}
	if ok, _, _ := l.Allow(ctx, "other", 600); !ok {
		t.Fatal("other key must be independent")
	}
	now = now.Add(60 * time.Second)
	if ok, _, _ := l.Allow(ctx, "k", 600); !ok {
		t.Fatal("window should reset")
	}
}

func TestMemoryLimiterBounded(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewMemoryLimiter(func() time.Time { return now }).(*memoryLimiter)
	for i := range 50 {
		_, _, _ = l.Allow(context.Background(), "k"+strconv.Itoa(i), 5)
	}
	now = now.Add(5 * time.Minute)
	_, _, _ = l.Allow(context.Background(), "z", 5)
	if len(l.counts) != 1 {
		t.Fatalf("stale windows not pruned: %d", len(l.counts))
	}
}

type fakeResolver struct {
	key     *store.APIKey
	err     error
	touched int
}

func (f *fakeResolver) FindKeyByHash(context.Context, string) (*store.APIKey, error) {
	return f.key, f.err
}
func (f *fakeResolver) TouchKey(context.Context, string) error { f.touched++; return nil }

type denyLimiter struct{}

func (denyLimiter) Allow(context.Context, string, int) (bool, time.Duration, error) {
	return false, 17 * time.Second, nil
}

type errLimiter struct{}

func (errLimiter) Allow(context.Context, string, int) (bool, time.Duration, error) {
	return false, 0, errors.New("redis down")
}

func doReq(h http.Handler, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/x", nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func errCode(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var b struct{ Error, Message string }
	if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil || b.Message == "" {
		t.Fatalf("bad error body %q: %v", rr.Body.String(), err)
	}
	return b.Error
}

func TestMiddlewareStatuses(t *testing.T) {
	revoked := time.Now()
	good := &store.APIKey{ID: "id1", Label: "l"}
	build := func(r *fakeResolver, l Limiter) http.Handler {
		return Middleware(r, l, 600, NewKeyCache(time.Minute, nil))(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if k := KeyFromContext(req.Context()); k == nil || k.ID != "id1" {
				t.Error("key missing from context")
			}
			w.WriteHeader(200)
		}))
	}
	hk := map[string]string{"x-api-key": testKey}
	cases := []struct {
		name   string
		r      *fakeResolver
		l      Limiter
		hdr    map[string]string
		status int
		code   string
	}{
		{"missing", &fakeResolver{key: good}, NewMemoryLimiter(time.Now), nil, 403, "unauthorized"},
		{"blank", &fakeResolver{key: good}, NewMemoryLimiter(time.Now), map[string]string{"x-api-key": "  "}, 403, "unauthorized"},
		{"malformed key", &fakeResolver{key: good}, NewMemoryLimiter(time.Now), map[string]string{"x-api-key": "nzr_abc"}, 403, "unauthorized"},
		{"unknown", &fakeResolver{}, NewMemoryLimiter(time.Now), hk, 403, "unauthorized"},
		{"revoked", &fakeResolver{key: &store.APIKey{ID: "id1", RevokedAt: &revoked}}, NewMemoryLimiter(time.Now), hk, 403, "key_revoked"},
		{"origin", &fakeResolver{key: &store.APIKey{ID: "id1", AllowedOrigins: []string{"https://a.com"}}}, NewMemoryLimiter(time.Now),
			map[string]string{"x-api-key": testKey, "Origin": "https://b.com"}, 403, "origin_not_allowed"},
		{"limit", &fakeResolver{key: good}, denyLimiter{}, hk, 429, "rate_limited"},
		{"store", &fakeResolver{err: errors.New("db")}, NewMemoryLimiter(time.Now), hk, 503, "store_unavailable"},
		{"limiter error fails open", &fakeResolver{key: good}, errLimiter{}, hk, 200, ""},
		{"ok", &fakeResolver{key: good}, NewMemoryLimiter(time.Now), hk, 200, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := doReq(build(tc.r, tc.l), tc.hdr)
			if rr.Code != tc.status {
				t.Fatalf("status %d want %d (%s)", rr.Code, tc.status, rr.Body)
			}
			if tc.code != "" {
				if got := errCode(t, rr); got != tc.code {
					t.Fatalf("code %q want %q", got, tc.code)
				}
				if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
					t.Fatalf("content-type %q", ct)
				}
			}
			if tc.status == 429 && rr.Header().Get("Retry-After") != "17" {
				t.Fatalf("Retry-After %q", rr.Header().Get("Retry-After"))
			}
		})
	}
}

func TestMiddlewareTouchesAndCaches(t *testing.T) {
	revoked := time.Now()
	r := &fakeResolver{key: &store.APIKey{ID: "id1", RevokedAt: &revoked}}
	c := NewKeyCache(time.Minute, nil)
	h := Middleware(r, NewMemoryLimiter(time.Now), 1, c)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	hk := map[string]string{"x-api-key": testKey}
	for range 2 {
		if rr := doReq(h, hk); rr.Code != 403 {
			t.Fatalf("status %d", rr.Code)
		}
	}
	if r.touched != 0 {
		t.Fatal("revoked key must not be touched")
	}
	// Cache returns revoked keys, and Invalidate drops them.
	if k, ok := c.get(HashKey(testKey)); !ok || k.RevokedAt == nil {
		t.Fatal("revoked key should be cached")
	}
	c.Invalidate(HashKey(testKey))
	if _, ok := c.get(HashKey(testKey)); ok {
		t.Fatal("invalidate failed")
	}
}

func TestMiddlewareDefaultRateNilKeyRate(t *testing.T) {
	r := &fakeResolver{key: &store.APIKey{ID: "id1"}}
	h := Middleware(r, NewMemoryLimiter(time.Now), 2, NewKeyCache(time.Minute, nil))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	hk := map[string]string{"x-api-key": testKey}
	codes := []int{doReq(h, hk).Code, doReq(h, hk).Code, doReq(h, hk).Code}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != 429 {
		t.Fatalf("codes %v", codes)
	}
	if r.touched != 2 {
		t.Fatalf("touched %d", r.touched)
	}
}

func TestKeyCacheTTLAndLRU(t *testing.T) {
	now := time.Unix(1000, 0)
	c := NewKeyCache(time.Minute, nil)
	c.now = func() time.Time { return now }
	c.cap = 2
	c.put("a", &store.APIKey{ID: "a"})
	c.put("b", &store.APIKey{ID: "b"})
	c.get("a")
	c.put("c", &store.APIKey{ID: "c"})
	if _, ok := c.get("b"); ok {
		t.Fatal("b should be evicted")
	}
	if _, ok := c.get("a"); !ok {
		t.Fatal("a should remain")
	}
	now = now.Add(2 * time.Minute)
	if _, ok := c.get("a"); ok {
		t.Fatal("a should expire")
	}
}

func TestAdminMiddleware(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	if rr := doReq(AdminMiddleware("")(next), map[string]string{"Authorization": "Bearer x"}); rr.Code != 404 {
		t.Fatalf("empty token: %d", rr.Code)
	}
	h := AdminMiddleware("secret")(next)
	for _, hdr := range []map[string]string{nil, {"Authorization": "Bearer nope"}, {"Authorization": "secret"}} {
		rr := doReq(h, hdr)
		if rr.Code != 403 {
			t.Fatalf("%v: %d", hdr, rr.Code)
		}
		errCode(t, rr)
	}
	if rr := doReq(h, map[string]string{"Authorization": "Bearer secret"}); rr.Code != 200 {
		t.Fatalf("right token: %d", rr.Code)
	}
}

func TestWriteErrorDoesNotEscapeHTML(t *testing.T) {
	w := httptest.NewRecorder()
	WriteError(w, 403, "origin_not_allowed", "origin <https://a&b> not allowed")
	if got := w.Body.String(); got != `{"error":"origin_not_allowed","message":"origin <https://a&b> not allowed"}`+"\n" {
		t.Fatalf("body %q", got)
	}
}
