package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	"nazr/api/internal/auth"
	"nazr/api/internal/config"
	"nazr/api/internal/ipintel"
	"nazr/api/internal/store"
	"nazr/api/internal/widgettoken"
)

const svHostname = "https://shop.example"

var svIP = netip.MustParseAddr("203.0.113.42")

// svEnv is an env whose key has a verify secret.
type svEnv struct {
	*env
	secret string
}

// newSiteverifyEnv seeds keyID with a verify secret; a nil ring is the test key.
func newSiteverifyEnv(t *testing.T, mut func(c *config.Config, s *fakeStore), ring *widgettoken.Keyring) svEnv {
	t.Helper()
	if ring == nil {
		ring = widgettoken.NewStaticKeyring(testSigningKey)
	}
	plain, hash, prefix := auth.GenerateSecret()
	e := newEnvWidgetSigning(t, func(c *config.Config, s *fakeStore) {
		if err := s.SetKeySecret(context.Background(), keyID, hash, prefix); err != nil {
			t.Fatal(err)
		}
		if mut != nil {
			mut(c, s)
		}
	}, nil, ring)
	return svEnv{env: e, secret: plain}
}

// seedReport stores a pass report for keyID and returns its id.
func (e svEnv) seedReport(ip *netip.Addr, ipHash string) string {
	id := ulid.Make().String()
	issued := testNow.Add(-time.Minute)
	e.store.reports = append(e.store.reports, store.WidgetReport{
		ID: id, APIKeyID: keyID, Nonce: id, IP: ip, IPHash: ipHash, CreatedAt: issued,
		Hostname: svHostname, PowOK: true, Verdict: "pass", TokenIssuedAt: &issued,
		Classification: json.RawMessage(`{"tor":false,"vpn":true,"bot":false,"datacenter":false,"private_relay":false,"danger_level":2}`),
		Signals:        json.RawMessage(`{"headless":false,"vpn_ip":true}`),
	})
	return id
}

func (e svEnv) report(id string) store.WidgetReport {
	e.t.Helper()
	for _, r := range e.store.reports {
		if r.ID == id {
			return r
		}
	}
	e.t.Fatalf("no report %s", id)
	return store.WidgetReport{}
}

func svToken(t *testing.T, k widgettoken.Key, aud, id string) string {
	t.Helper()
	tok, err := widgettoken.Sign(k.Private, k.Kid, widgettoken.Claims{Issuer: "https://nazr.example", Audience: aud, ID: id,
		IssuedAt: testNow.Add(-time.Minute).Unix(), Expires: testNow.Add(4 * time.Minute).Unix(), Hostname: svHostname, Verdict: "pass"})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func svReq(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/widget/v1/siteverify", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func (e svEnv) verify(t *testing.T, fields map[string]string) (int, map[string]any) {
	t.Helper()
	w := e.do(svReq(string(marshal(t, fields))))
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body %q: %v", w.Body.String(), err)
	}
	return w.Code, got
}

func wantFailure(t *testing.T, status int, got map[string]any, wantStatus int, code string) {
	t.Helper()
	want := map[string]any{"success": false, "error_codes": []any{code}}
	if status != wantStatus || !reflect.DeepEqual(got, want) {
		t.Fatalf("status %d body %v; want %d %v", status, got, wantStatus, want)
	}
}

func TestSiteverifyMatrix(t *testing.T) {
	yes, no := true, false
	t.Run("valid then replayed", func(t *testing.T) {
		e := newSiteverifyEnv(t, nil, nil)
		e.store.correlation = store.WidgetCorrelation{Matched: true, IPMatch: &yes, UAMatch: &no}
		id := e.seedReport(&svIP, "")
		tok := svToken(t, testSigningKey, keyID, id)
		status, got := e.verify(t, map[string]string{"secret": e.secret, "token": tok})
		want := map[string]any{
			"success": true, "challenge_ts": testNow.Add(-time.Minute).Format(time.RFC3339),
			"hostname": svHostname, "verdict": "pass",
			"correlation": map[string]any{"matched": true, "ip_match": true, "ja4_match": nil, "ua_match": false},
			"classification": map[string]any{"tor": false, "vpn": true, "bot": false, "datacenter": false,
				"private_relay": false, "danger_level": float64(2)},
			"signals":     map[string]any{"headless": false, "vpn_ip": true},
			"error_codes": []any{},
		}
		if status != 200 || !reflect.DeepEqual(got, want) {
			t.Fatalf("status %d body %v", status, got)
		}
		if e.store.corrArgs != [3]string{keyID, id, widgetMatchWindow.String()} {
			t.Fatalf("correlation args %v", e.store.corrArgs)
		}
		if e.report(id).VerifiedAt == nil {
			t.Fatal("row not spent")
		}
		status, got = e.verify(t, map[string]string{"secret": e.secret, "token": tok})
		wantFailure(t, status, got, 200, "replayed")
		if e.report(id).ReplayCount != 1 {
			t.Fatalf("replay count %d", e.report(id).ReplayCount)
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		e := newSiteverifyEnv(t, nil, nil)
		id := e.seedReport(&svIP, "")
		other, _, _ := auth.GenerateSecret()
		status, got := e.verify(t, map[string]string{"secret": other, "token": svToken(t, testSigningKey, keyID, id)})
		wantFailure(t, status, got, 401, "invalid-secret")
		if e.store.markCalls != 0 {
			t.Fatal("row touched")
		}
	})

	t.Run("revoked key", func(t *testing.T) {
		e := newSiteverifyEnv(t, func(_ *config.Config, s *fakeStore) {
			now := testNow
			s.byID[keyID].RevokedAt = &now
		}, nil)
		id := e.seedReport(&svIP, "")
		status, got := e.verify(t, map[string]string{"secret": e.secret, "token": svToken(t, testSigningKey, keyID, id)})
		wantFailure(t, status, got, 401, "invalid-secret")
	})

	t.Run("rate limited", func(t *testing.T) {
		e := newSiteverifyEnv(t, func(_ *config.Config, s *fakeStore) {
			one := 1
			s.byID[keyID].RateLimitPerMinute = &one
		}, nil)
		id := e.seedReport(&svIP, "")
		tok := svToken(t, testSigningKey, keyID, id)
		if status, _ := e.verify(t, map[string]string{"secret": e.secret, "token": tok}); status != 200 {
			t.Fatalf("first %d", status)
		}
		w := e.do(svReq(string(marshal(t, map[string]string{"secret": e.secret, "token": tok}))))
		wantError(t, w, 429, "rate_limited")
		if w.Header().Get("Retry-After") == "" {
			t.Fatal("no Retry-After")
		}
	})

	t.Run("bad signature", func(t *testing.T) {
		e := newSiteverifyEnv(t, nil, nil)
		id := e.seedReport(&svIP, "")
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		forged := svToken(t, widgettoken.Key{Kid: testSigningKey.Kid, Private: priv}, keyID, id)
		status, got := e.verify(t, map[string]string{"secret": e.secret, "token": forged})
		wantFailure(t, status, got, 200, "invalid-token")
		status, got = e.verify(t, map[string]string{"secret": e.secret, "token": "not.a.token"})
		wantFailure(t, status, got, 200, "invalid-token")
		if e.store.markCalls != 0 {
			t.Fatal("row touched")
		}
	})

	t.Run("audience of another key", func(t *testing.T) {
		e := newSiteverifyEnv(t, nil, nil)
		id := e.seedReport(&svIP, "")
		status, got := e.verify(t, map[string]string{"secret": e.secret,
			"token": svToken(t, testSigningKey, "22222222-2222-4222-8222-222222222222", id)})
		wantFailure(t, status, got, 200, "invalid-token")
		if e.store.markCalls != 0 {
			t.Fatal("row touched")
		}
	})

	t.Run("expired before spending", func(t *testing.T) {
		e := newSiteverifyEnv(t, nil, nil)
		id := e.seedReport(&svIP, "")
		e.now = testNow.Add(4 * time.Minute) // == exp
		status, got := e.verify(t, map[string]string{"secret": e.secret, "token": svToken(t, testSigningKey, keyID, id)})
		wantFailure(t, status, got, 200, "token-expired")
		if e.store.markCalls != 0 || e.report(id).VerifiedAt != nil {
			t.Fatal("expired token spent the row")
		}
	})

	t.Run("unknown jti", func(t *testing.T) {
		e := newSiteverifyEnv(t, nil, nil)
		e.seedReport(&svIP, "")
		status, got := e.verify(t, map[string]string{"secret": e.secret, "token": svToken(t, testSigningKey, keyID, ulid.Make().String())})
		wantFailure(t, status, got, 200, "invalid-token")
	})

	t.Run("retired key in grace", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		retired := testNow.Add(-time.Minute)
		old := widgettoken.Key{Kid: "old", Private: priv, Secret: []byte("fedcba9876543210fedcba9876543210"),
			CreatedAt: testNow.Add(-48 * time.Hour), RetiredAt: &retired}
		e := newSiteverifyEnv(t, nil, widgettoken.NewStaticKeyring(testSigningKey, old))
		id := e.seedReport(&svIP, "")
		status, got := e.verify(t, map[string]string{"secret": e.secret, "token": svToken(t, old, keyID, id)})
		if status != 200 || got["success"] != true {
			t.Fatalf("status %d body %v", status, got)
		}
	})

	t.Run("remoteip raw", func(t *testing.T) {
		e := newSiteverifyEnv(t, nil, nil)
		e.store.correlation = store.WidgetCorrelation{Matched: false}
		id := e.seedReport(&svIP, "")
		status, got := e.verify(t, map[string]string{"secret": e.secret, "token": svToken(t, testSigningKey, keyID, id),
			"remoteip": "198.51.100.7"})
		if status != 200 || got["success"] != false || !reflect.DeepEqual(got["error_codes"], []any{"remoteip-mismatch"}) ||
			got["hostname"] != svHostname || got["verdict"] != "pass" || got["challenge_ts"] == nil ||
			!reflect.DeepEqual(got["correlation"], map[string]any{"matched": false, "ip_match": nil, "ja4_match": nil, "ua_match": nil}) ||
			got["classification"] == nil || got["signals"] == nil {
			t.Fatalf("status %d body %v", status, got)
		}
		if e.report(id).VerifiedAt == nil {
			t.Fatal("mismatch did not spend the row")
		}

		id = e.seedReport(&svIP, "")
		status, got = e.verify(t, map[string]string{"secret": e.secret, "token": svToken(t, testSigningKey, keyID, id),
			"remoteip": "not-an-ip"})
		if status != 200 || !reflect.DeepEqual(got["error_codes"], []any{"remoteip-mismatch"}) {
			t.Fatalf("invalid remoteip: %d %v", status, got)
		}

		id = e.seedReport(&svIP, "")
		status, got = e.verify(t, map[string]string{"secret": e.secret, "token": svToken(t, testSigningKey, keyID, id),
			"remoteip": "::ffff:203.0.113.42"})
		if status != 200 || got["success"] != true {
			t.Fatalf("mapped remoteip: %d %v", status, got)
		}
	})

	t.Run("remoteip hash", func(t *testing.T) {
		e := newSiteverifyEnv(t, func(c *config.Config, _ *fakeStore) { c.StoreIP = "hash" }, nil)
		id := e.seedReport(nil, ipintel.Identifier(svIP, "salt"))
		status, got := e.verify(t, map[string]string{"secret": e.secret, "token": svToken(t, testSigningKey, keyID, id),
			"remoteip": "203.0.113.42"})
		if status != 200 || got["success"] != true {
			t.Fatalf("hash match: %d %v", status, got)
		}
		id = e.seedReport(nil, ipintel.Identifier(svIP, "salt"))
		status, got = e.verify(t, map[string]string{"secret": e.secret, "token": svToken(t, testSigningKey, keyID, id),
			"remoteip": "203.0.113.43"})
		if status != 200 || !reflect.DeepEqual(got["error_codes"], []any{"remoteip-mismatch"}) {
			t.Fatalf("hash mismatch: %d %v", status, got)
		}
		id = e.seedReport(nil, "")
		status, got = e.verify(t, map[string]string{"secret": e.secret, "token": svToken(t, testSigningKey, keyID, id),
			"remoteip": "203.0.113.42"})
		if status != 200 || !reflect.DeepEqual(got["error_codes"], []any{"remoteip-mismatch"}) {
			t.Fatalf("no ip recorded: %d %v", status, got)
		}
	})

	t.Run("correlation error after spending", func(t *testing.T) {
		e := newSiteverifyEnv(t, nil, nil)
		e.store.correlationErr = errBoom
		id := e.seedReport(&svIP, "")
		status, got := e.verify(t, map[string]string{"secret": e.secret, "token": svToken(t, testSigningKey, keyID, id)})
		if status != 200 || got["success"] != true || got["hostname"] != svHostname || got["verdict"] != "pass" ||
			got["challenge_ts"] == nil || got["classification"] == nil || got["signals"] == nil ||
			!reflect.DeepEqual(got["error_codes"], []any{}) {
			t.Fatalf("status %d body %v", status, got)
		}
		if _, ok := got["correlation"]; ok {
			t.Fatalf("correlation present: %v", got)
		}
		if e.report(id).VerifiedAt == nil {
			t.Fatal("row not spent")
		}

		id = e.seedReport(&svIP, "")
		status, got = e.verify(t, map[string]string{"secret": e.secret, "token": svToken(t, testSigningKey, keyID, id),
			"remoteip": "198.51.100.7"})
		if status != 200 || !reflect.DeepEqual(got["error_codes"], []any{"remoteip-mismatch"}) || got["verdict"] != "pass" {
			t.Fatalf("mismatch: status %d body %v", status, got)
		}
		if _, ok := got["correlation"]; ok {
			t.Fatalf("mismatch correlation present: %v", got)
		}
	})

	t.Run("empty hostname and signals", func(t *testing.T) {
		e := newSiteverifyEnv(t, nil, nil)
		id := e.seedReport(&svIP, "")
		e.store.reports[len(e.store.reports)-1].Hostname = ""
		e.store.reports[len(e.store.reports)-1].Signals = nil
		w := e.do(svReq(string(marshal(t, map[string]string{"secret": e.secret, "token": svToken(t, testSigningKey, keyID, id)}))))
		body := w.Body.String()
		if w.Code != 200 || !strings.Contains(body, `"hostname":""`) || !strings.Contains(body, `"signals":{}`) {
			t.Fatalf("status %d body %s", w.Code, body)
		}

		id = e.seedReport(&svIP, "")
		e.store.reports[len(e.store.reports)-1].Hostname = ""
		e.store.reports[len(e.store.reports)-1].Signals = nil
		w = e.do(svReq(string(marshal(t, map[string]string{"secret": e.secret, "token": svToken(t, testSigningKey, keyID, id),
			"remoteip": "198.51.100.7"}))))
		body = w.Body.String()
		if !strings.Contains(body, `"remoteip-mismatch"`) || !strings.Contains(body, `"hostname":""`) || !strings.Contains(body, `"signals":{}`) {
			t.Fatalf("mismatch body %s", body)
		}

		w = e.do(svReq(string(marshal(t, map[string]string{"secret": e.secret, "token": "not.a.token"}))))
		body = w.Body.String()
		if !strings.Contains(body, `"invalid-token"`) || strings.Contains(body, "hostname") || strings.Contains(body, "signals") {
			t.Fatalf("failure body %s", body)
		}
	})

	t.Run("malformed secret skips the store", func(t *testing.T) {
		e := newSiteverifyEnv(t, nil, nil)
		id := e.seedReport(&svIP, "")
		tok := svToken(t, testSigningKey, keyID, id)
		for _, secret := range []string{"junk", "nzs_" + strings.Repeat("a", 51), "nzs_" + strings.Repeat("A", 52),
			"nzr_" + strings.Repeat("a", 52), "nzs_" + strings.Repeat("a", 51) + "1"} {
			status, got := e.verify(t, map[string]string{"secret": secret, "token": tok})
			wantFailure(t, status, got, 401, "invalid-secret")
		}
		if e.store.secretCalls != 0 || e.store.markCalls != 0 {
			t.Fatalf("store called: secret %d mark %d", e.store.secretCalls, e.store.markCalls)
		}
	})

	t.Run("store errors", func(t *testing.T) {
		e := newSiteverifyEnv(t, nil, nil)
		id := e.seedReport(&svIP, "")
		tok := svToken(t, testSigningKey, keyID, id)
		e.store.markErr = errBoom
		wantError(t, e.do(svReq(string(marshal(t, map[string]string{"secret": e.secret, "token": tok})))), 503, "store_unavailable")
		e.store.findErr = errBoom
		wantError(t, e.do(svReq(string(marshal(t, map[string]string{"secret": e.secret, "token": tok})))), 503, "store_unavailable")
	})

	t.Run("bad request", func(t *testing.T) {
		e := newSiteverifyEnv(t, nil, nil)
		id := e.seedReport(&svIP, "")
		good := string(marshal(t, map[string]string{"secret": e.secret, "token": svToken(t, testSigningKey, keyID, id)}))
		r := svReq(good)
		r.Header.Set("Content-Type", "text/plain")
		wantError(t, e.do(r), 400, "bad_request")
		r = svReq(good)
		r.Header.Del("Content-Type")
		wantError(t, e.do(r), 400, "bad_request")
		for _, body := range []string{`{`, `[]`, `{"secret":"x"}`, `{"token":"y"}`, `{"secret":"","token":""}`, `{"secret":1,"token":2}`} {
			wantError(t, e.do(svReq(body)), 400, "bad_request")
		}
		r = svReq(good)
		r.Header.Set("Content-Type", "application/json; charset=utf-8")
		if w := e.do(r); w.Code != 200 {
			t.Fatalf("json with params %d: %s", w.Code, w.Body.String())
		}
		if e.store.markCalls != 1 {
			t.Fatalf("mark calls %d", e.store.markCalls)
		}
	})

	t.Run("no signing keyring", func(t *testing.T) {
		e := newEnvWidgetSigning(t, nil, nil, nil)
		w := e.do(svReq(`{"secret":"a","token":"b"}`))
		if w.Code != 404 {
			t.Fatalf("status %d", w.Code)
		}
	})
}

func TestAdminKeySecret(t *testing.T) {
	e := newEnv(t, func(c *config.Config, _ *fakeStore) { c.AdminToken = "s3cret" })
	req := func(method, target, body, token string) *http.Request {
		r := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		return r
	}
	secretRe := regexp.MustCompile(`^nzs_[a-z2-7]{52}$`)
	w := e.do(req("POST", "/admin/keys", `{"label":"shop"}`, "s3cret"))
	if w.Code != 201 {
		t.Fatalf("create %d: %s", w.Code, w.Body.String())
	}
	var created map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	secret, _ := created["secret"].(string)
	if !secretRe.MatchString(secret) || created["secret_prefix"] != secret[4:12] {
		t.Fatalf("created %v", created)
	}
	id := created["id"].(string)
	if e.store.secretHashOf(id) != auth.HashKey(secret) {
		t.Fatal("secret hash not stored")
	}

	w = e.do(req("GET", "/admin/keys", "", "s3cret"))
	if strings.Contains(w.Body.String(), secret) || !strings.Contains(w.Body.String(), `"secret_prefix":"`+secret[4:12]+`"`) {
		t.Fatalf("list %s", w.Body.String())
	}

	w = e.do(req("POST", "/admin/keys/"+id+"/secret", "", "s3cret"))
	if w.Code != 200 {
		t.Fatalf("rotate %d: %s", w.Code, w.Body.String())
	}
	var rotated map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &rotated)
	next, _ := rotated["secret"].(string)
	if rotated["id"] != id || len(rotated) != 2 || !secretRe.MatchString(next) || next == secret {
		t.Fatalf("rotated %v", rotated)
	}
	if e.store.secretHashOf(id) != auth.HashKey(next) || e.store.byID[id].SecretPrefix != next[4:12] {
		t.Fatal("new secret hash not stored")
	}

	wantError(t, e.do(req("POST", "/admin/keys/99999999-9999-4999-8999-999999999999/secret", "", "s3cret")), 404, "not_found")
	wantError(t, e.do(req("POST", "/admin/keys/"+id+"/secret", "", "")), 403, "unauthorized")
	off := newEnv(t, nil)
	wantError(t, off.do(req("POST", "/admin/keys/"+id+"/secret", "", "s3cret")), 404, "not_found")
}

func TestSiteverifyInteractive(t *testing.T) {
	t.Run("interactive row carries the block", func(t *testing.T) {
		e := newSiteverifyEnv(t, nil, nil)
		id := e.seedReport(&svIP, "")
		for i := range e.store.reports {
			if e.store.reports[i].ID == id {
				e.store.reports[i].Verdict = "interactive"
				e.store.reports[i].Interaction = json.RawMessage(`{"shown_ms":100,"click_ms":1940,"input":"pointer","trusted":true,"moves":12,"path_px":240.5,"straightness":0.8,"pointer_type":"mouse","visible":true,"signals":{},"elapsed_ms":1840}`)
			}
		}
		status, got := e.verify(t, map[string]string{"secret": e.secret, "token": svToken(t, testSigningKey, keyID, id)})
		if status != 200 || got["success"] != true {
			t.Fatalf("status %d body %v", status, got)
		}
		in, ok := got["interaction"].(map[string]any)
		if !ok {
			t.Fatalf("no interaction in %v", got)
		}
		if in["input"] != "pointer" || in["pointer_type"] != "mouse" || in["trusted"] != true ||
			in["moves"] != float64(12) || in["path_px"] != 240.5 || in["straightness"] != 0.8 || in["elapsed_ms"] != float64(1840) {
			t.Fatalf("interaction %v", in)
		}
		if sig, ok := in["signals"].(map[string]any); !ok || len(sig) != 0 {
			t.Fatalf("signals %v", in["signals"])
		}
		if _, extra := in["shown_ms"]; extra {
			t.Fatalf("leaked stored key: %v", in)
		}
	})
	t.Run("pass row has no block", func(t *testing.T) {
		e := newSiteverifyEnv(t, nil, nil)
		id := e.seedReport(&svIP, "")
		_, got := e.verify(t, map[string]string{"secret": e.secret, "token": svToken(t, testSigningKey, keyID, id)})
		if _, has := got["interaction"]; has || got["success"] != true {
			t.Fatalf("body %v", got)
		}
	})
	t.Run("pow_failed row is not verifiable", func(t *testing.T) {
		e := newSiteverifyEnv(t, nil, nil)
		id := e.seedReport(&svIP, "")
		for i := range e.store.reports {
			if e.store.reports[i].ID == id {
				e.store.reports[i].Verdict = "pow_failed"
				e.store.reports[i].TokenIssuedAt = nil
			}
		}
		status, got := e.verify(t, map[string]string{"secret": e.secret, "token": svToken(t, testSigningKey, keyID, id)})
		wantFailure(t, status, got, 200, "invalid-token")
		if e.report(id).ReplayCount != 0 || e.report(id).VerifiedAt != nil {
			t.Fatal("row touched")
		}
	})
}
