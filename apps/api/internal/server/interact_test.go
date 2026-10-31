package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"nazr/api/internal/auth"
	"nazr/api/internal/config"
	"nazr/api/internal/interaction"
	"nazr/api/internal/store"
	"nazr/api/internal/visitor"
	"nazr/api/internal/widgettoken"
)

// interactBits is the interactive difficulty in every interact test env.
const interactBits = 8 + 4

func interactConfig(c *config.Config, _ *fakeStore) {
	c.WidgetPassMaxDanger = 0
	c.WidgetInteractive = true
	c.WidgetInteractiveExtraBits = 4
}

func cleanTrace() interaction.Trace {
	return interaction.Trace{ShownMS: 1000, ClickMS: 2840, Input: "pointer", Trusted: true, Moves: 41,
		PathPX: 512.3, Straightness: 0.71, PointerType: "mouse", Visible: true}
}

// traceMap is t as the decoded JSON object the frame posts.
func traceMap(t *testing.T, tr interaction.Trace) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(marshal(t, tr), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// seedOffer posts an eligible inconclusive report and returns the offered
// interactive challenge, its id and its difficulty.
func seedOffer(t *testing.T, e *env) (string, string, int) {
	t.Helper()
	ch, id := mintTestChallenge(t, e, "https://shop.example")
	out := postReport(t, e, widgetBody(t, e, ch, id), func(r *http.Request) { r.Header.Del("Accept-Language") })
	offer, _ := out["interactive"].(map[string]any)
	if out["verdict"] != "inconclusive" || offer == nil {
		t.Fatalf("seed outcome %v", out)
	}
	bits, err := strconv.Atoi(strings.TrimSpace(string(marshal(t, offer["bits"]))))
	if err != nil || bits != interactBits {
		t.Fatalf("offer bits %v", offer["bits"])
	}
	return offer["challenge"].(string), id, bits
}

func interactReqBody(t *testing.T, ch, id string, bits int, tr interaction.Trace) map[string]any {
	t.Helper()
	return map[string]any{"challenge": ch, "pow": widgettoken.SolvePoW(id, bits), "trace": traceMap(t, tr)}
}

func interactReq(t *testing.T, key string, body []byte) *http.Request {
	t.Helper()
	r := widgetReportReq(t, key, body)
	r.URL.Path, r.RequestURI = "/widget/interact", "/widget/interact"
	return r
}

// postInteract posts body to /widget/interact and returns the 200 JSON
// outcome.
func postInteract(t *testing.T, e *env, body map[string]any) map[string]any {
	t.Helper()
	w := e.do(interactReq(t, e.key, marshal(t, body)))
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("status %d type %q: %s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	return decodeResp(t, w)
}

func findReport(t *testing.T, e *env, id string) store.WidgetReport {
	t.Helper()
	for _, r := range e.store.reports {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no report %s", id)
	return store.WidgetReport{}
}

func TestInteractSuccess(t *testing.T) {
	e := newEnv(t, interactConfig)
	ch, id, bits := seedOffer(t, e)
	out := postInteract(t, e, interactReqBody(t, ch, id, bits, cleanTrace()))
	if out["verdict"] != "interactive" || len(out) != 2 {
		t.Fatalf("outcome %v", out)
	}
	c := parseTestToken(t, out["token"])
	if c.Verdict != "interactive" || c.ID != id || c.IssuedAt != testNow.Unix() || c.Audience != keyID ||
		c.Hostname != "https://shop.example" || c.Expires != testNow.Add(e.cfg.WidgetTokenTTL).Unix() {
		t.Fatalf("claims %+v", c)
	}
	rep := findReport(t, e, id)
	if rep.Verdict != "interactive" || rep.TokenIssuedAt == nil || !rep.TokenIssuedAt.Equal(testNow) {
		t.Fatalf("report %+v", rep)
	}
	s := string(rep.Interaction)
	for _, want := range []string{`"input":"pointer"`, `"elapsed_ms":1840`, `"signals":{}`} {
		if !strings.Contains(s, want) {
			t.Fatalf("interaction %s lacks %s", s, want)
		}
	}
	var got map[string]any
	if err := json.Unmarshal(rep.Interaction, &got); err != nil {
		t.Fatal(err)
	}
	want := traceMap(t, cleanTrace())
	want["elapsed_ms"] = float64(1840)
	want["signals"] = map[string]any{}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("interaction %v want %v", got, want)
	}
	if e.store.upgradeCalls != 1 {
		t.Fatalf("upgrade calls %d", e.store.upgradeCalls)
	}
}

func TestInteractFailedScore(t *testing.T) {
	e := newEnv(t, interactConfig)
	ch, id, bits := seedOffer(t, e)
	tr := cleanTrace()
	tr.Trusted = false
	out := postInteract(t, e, interactReqBody(t, ch, id, bits, tr))
	if out["verdict"] != "interactive_failed" || len(out) != 1 {
		t.Fatalf("outcome %v", out)
	}
	rep := findReport(t, e, id)
	if rep.Verdict != "interactive_failed" || rep.TokenIssuedAt != nil {
		t.Fatalf("report %+v", rep)
	}
	var got struct {
		Signals   map[string]bool `json:"signals"`
		ElapsedMS int             `json:"elapsed_ms"`
		Trusted   *bool           `json:"trusted"`
	}
	if err := json.Unmarshal(rep.Interaction, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Signals, map[string]bool{"untrusted_event": true}) || got.ElapsedMS != 1840 ||
		got.Trusted == nil || *got.Trusted {
		t.Fatalf("interaction %s", rep.Interaction)
	}

	// One attempt per challenge.
	before := slices.Clone(e.store.reports)
	if out := postInteract(t, e, interactReqBody(t, ch, id, bits, cleanTrace())); out["verdict"] != "invalid" || len(out) != 1 {
		t.Fatalf("second outcome %v", out)
	}
	if !reflect.DeepEqual(before, e.store.reports) {
		t.Fatalf("second attempt changed the row: %+v", e.store.reports)
	}
}

func TestInteractInvalid(t *testing.T) {
	cases := map[string]func(t *testing.T, e *env, b map[string]any, id string){
		"passive challenge": func(t *testing.T, e *env, b map[string]any, id string) {
			ch := mintStagedChallengeID(e, id, e.cfg.PowBits, "")
			b["challenge"], b["pow"] = ch, widgettoken.SolvePoW(id, e.cfg.PowBits)
		},
		"tampered mac": func(_ *testing.T, _ *env, b map[string]any, _ string) {
			payload, mac, _ := strings.Cut(b["challenge"].(string), ".")
			first := "A"
			if mac[0] == 'A' {
				first = "B"
			}
			b["challenge"] = payload + "." + first + mac[1:]
		},
		"expired": func(_ *testing.T, e *env, _ map[string]any, _ string) { e.now = testNow.Add(11 * time.Minute) },
		"wrong pow": func(_ *testing.T, e *env, b map[string]any, id string) {
			// Solves the base bits but not the interactive bits, so checking
			// the configured base difficulty instead of the challenge's fails.
			for i := 0; ; i++ {
				if c := strconv.Itoa(i); widgettoken.VerifyPoW(id, c, e.cfg.PowBits) && !widgettoken.VerifyPoW(id, c, interactBits) {
					b["pow"] = c
					return
				}
			}
		},
		"missing trace":   func(_ *testing.T, _ *env, b map[string]any, _ string) { delete(b, "trace") },
		"string trace":    func(_ *testing.T, _ *env, b map[string]any, _ string) { b["trace"] = "x" },
		"moves 201":       func(_ *testing.T, _ *env, b map[string]any, _ string) { b["trace"].(map[string]any)["moves"] = 201 },
		"bad input":       func(_ *testing.T, _ *env, b map[string]any, _ string) { b["trace"].(map[string]any)["input"] = "tap" },
		"float shown_ms":  func(_ *testing.T, _ *env, b map[string]any, _ string) { b["trace"].(map[string]any)["shown_ms"] = 1.5 },
		"string trusted":  func(_ *testing.T, _ *env, b map[string]any, _ string) { b["trace"].(map[string]any)["trusted"] = "yes" },
		"long challenge":  func(_ *testing.T, _ *env, b map[string]any, _ string) { b["challenge"] = strings.Repeat("a", 513) },
		"empty challenge": func(_ *testing.T, _ *env, b map[string]any, _ string) { b["challenge"] = "" },
		"long pow":        func(_ *testing.T, _ *env, b map[string]any, _ string) { b["pow"] = strings.Repeat("1", 33) },
		"numeric pow":     func(_ *testing.T, _ *env, b map[string]any, _ string) { b["pow"] = 12 },
		"wrong key": func(_ *testing.T, e *env, b map[string]any, id string) {
			b["challenge"] = widgettoken.MintChallenge(testSigningKey.Secret, widgettoken.Challenge{ID: id,
				Expires: e.now.Add(widgetMatchWindow).Unix(), Bits: interactBits, Kid: testSigningKey.Kid,
				Origin: "https://shop.example", Key: otherKeyID, Stage: widgettoken.StageInteractive})
		},
		"unknown id": func(t *testing.T, e *env, b map[string]any, _ string) {
			ch, other := mintTestInteractiveChallenge(t, e, "https://shop.example", interactBits)
			b["challenge"], b["pow"] = ch, widgettoken.SolvePoW(other, interactBits)
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, interactConfig)
			ch, id, bits := seedOffer(t, e)
			body := interactReqBody(t, ch, id, bits, cleanTrace())
			mut(t, e, body, id)
			wantInteractInvalid(t, e, body)
		})
	}

	t.Run("pass row", func(t *testing.T) {
		e := newEnv(t, interactConfig)
		ch, id := mintTestChallenge(t, e, "https://shop.example")
		if out := postReport(t, e, widgetBody(t, e, ch, id)); out["verdict"] != "pass" {
			t.Fatalf("seed %v", out)
		}
		staged := mintStagedChallengeID(e, id, interactBits, widgettoken.StageInteractive)
		wantInteractInvalid(t, e, interactReqBody(t, staged, id, interactBits, cleanTrace()))
		if e.store.upgradeCalls != 1 {
			t.Fatalf("upgrade calls %d", e.store.upgradeCalls)
		}
	})

	t.Run("no signing", func(t *testing.T) {
		e := newEnvWidgetSigning(t, interactConfig, nil, nil)
		ch, id := mintTestInteractiveChallenge(t, e, "https://shop.example", interactBits)
		e.store.reports = append(e.store.reports, store.WidgetReport{ID: id, APIKeyID: keyID, Verdict: "inconclusive"})
		wantInteractInvalid(t, e, interactReqBody(t, ch, id, interactBits, cleanTrace()))
		if e.store.upgradeCalls != 0 {
			t.Fatalf("upgrade calls %d", e.store.upgradeCalls)
		}
	})
}

// wantInteractInvalid posts body and requires {"verdict":"invalid"} with
// every stored report unchanged.
func wantInteractInvalid(t *testing.T, e *env, body map[string]any) {
	t.Helper()
	before := slices.Clone(e.store.reports)
	if out := postInteract(t, e, body); out["verdict"] != "invalid" || len(out) != 1 {
		t.Fatalf("outcome %v", out)
	}
	if !reflect.DeepEqual(before, e.store.reports) {
		t.Fatalf("reports changed: %+v", e.store.reports)
	}
}

// mintStagedChallengeID mints a challenge for an existing id under
// testSigningKey.
func mintStagedChallengeID(e *env, id string, bits int, stage string) string {
	ch := widgettoken.MintChallenge(testSigningKey.Secret, widgettoken.Challenge{ID: id,
		Expires: e.now.Add(widgetMatchWindow).Unix(), Bits: bits, Kid: testSigningKey.Kid,
		Origin: "https://shop.example", Stage: stage})
	return ch
}

func TestInteractDisabledAfterOffer(t *testing.T) {
	e := newEnv(t, interactConfig)
	ch, id, bits := seedOffer(t, e)
	// The operator turns the step off after the offer: same store, keys and clock.
	e.cfg.WidgetInteractive = false
	e.h = New(Deps{Cfg: e.cfg, Store: e.store, Intel: e.intel,
		Resolver: &visitor.Resolver{Repo: e.repo, Window: e.cfg.VisitorMatchWindow, Now: func() time.Time { return testNow }},
		Limiter:  auth.NewMemoryLimiter(time.Now), Signing: widgettoken.NewStaticKeyring(testSigningKey),
		Logger: slog.New(slog.DiscardHandler), Version: "test-1.0", Now: func() time.Time { return e.now },
		Rand: func() float64 { return e.rand }})
	wantInteractInvalid(t, e, interactReqBody(t, ch, id, bits, cleanTrace()))
	if e.store.upgradeCalls != 0 {
		t.Fatalf("upgrade calls %d", e.store.upgradeCalls)
	}
	if rep := findReport(t, e, id); rep.Verdict != "inconclusive" || rep.Interaction != nil {
		t.Fatalf("report %+v", rep)
	}
}

func TestInteractStoreError(t *testing.T) {
	e := newEnvLogging(t, interactConfig)
	ch, id, bits := seedOffer(t, e)
	e.store.upgradeErr = errBoom
	before := slices.Clone(e.store.reports)
	if out := postInteract(t, e, interactReqBody(t, ch, id, bits, cleanTrace())); out["verdict"] != "invalid" || len(out) != 1 {
		t.Fatalf("outcome %v", out)
	}
	if !reflect.DeepEqual(before, e.store.reports) {
		t.Fatalf("reports changed: %+v", e.store.reports)
	}
	var errs []map[string]any
	for line := range strings.Lines(e.logs.String()) {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if m["level"] == "ERROR" {
			errs = append(errs, m)
		}
	}
	if len(errs) != 1 || errs[0]["err"] != "boom" || errs[0]["request_id"] == nil {
		t.Fatalf("error logs %v", errs)
	}
}

func TestInteractMiddleware(t *testing.T) {
	e := newEnv(t, func(c *config.Config, s *fakeStore) { interactConfig(c, s); c.DefaultRateLimit = 1 })
	ch, id := mintTestInteractiveChallenge(t, e, "https://shop.example", interactBits)
	body := marshal(t, interactReqBody(t, ch, id, interactBits, cleanTrace()))
	wantError(t, e.do(interactReq(t, "", body)), 403, "unauthorized")
	if w := e.do(interactReq(t, e.key, body)); w.Code != http.StatusOK {
		t.Fatalf("first %d: %s", w.Code, w.Body.String())
	}
	if w := e.do(interactReq(t, e.key, body)); w.Code != http.StatusTooManyRequests {
		t.Fatalf("second %d, want 429", w.Code)
	}
}
