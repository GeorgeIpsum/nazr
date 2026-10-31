package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestInsertWidgetReportAndPrune(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	k, _ := s.CreateKey(ctx, NewKey{Hash: "a", Prefix: "aaaaaaaa"})
	now := time.Now().UTC()
	ip := netip.MustParseAddr("203.0.113.9")
	ages := []time.Duration{100 * time.Hour, 50 * time.Hour, time.Hour}
	ids := make([]string, len(ages))
	for i, age := range ages {
		ids[i] = newID()
		r := WidgetReport{ID: ids[i], APIKeyID: k.ID, Nonce: "n", Thumbmark: "tm", ClientHash: "ch",
			IPHash: "iph", JA4: "j", H2FP: "h2", UserAgent: "ua", CreatedAt: now.Add(-age)}
		if i == 0 {
			r.IP = &ip
			r.Components = []byte(`{"a":1}`)
		}
		if err := s.InsertWidgetReport(ctx, r); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	var gotIP *netip.Addr
	var comps *string
	var nonce, tm string
	if err := s.pool.QueryRow(ctx, `SELECT ip, components::text, nonce, thumbmark FROM widget_reports WHERE id = $1`, ids[0]).
		Scan(&gotIP, &comps, &nonce, &tm); err != nil {
		t.Fatal(err)
	}
	if gotIP == nil || *gotIP != ip || comps == nil || *comps != `{"a": 1}` || nonce != "n" || tm != "tm" {
		t.Fatalf("round trip: ip %v comps %v nonce %q tm %q", gotIP, comps, nonce, tm)
	}
	var nullIP, nullComps bool
	if err := s.pool.QueryRow(ctx, `SELECT ip IS NULL, components IS NULL FROM widget_reports WHERE id = $1`, ids[1]).
		Scan(&nullIP, &nullComps); err != nil || !nullIP || !nullComps {
		t.Fatalf("expected NULL ip/components: %v %v %v", nullIP, nullComps, err)
	}
	n, err := s.Prune(ctx, now.Add(-60*time.Hour), time.Time{}, 10)
	if err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
	var left int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM widget_reports WHERE id = $1`, ids[0]).Scan(&left); err != nil || left != 0 {
		t.Fatalf("oldest row remains: %d %v", left, err)
	}
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM widget_reports`).Scan(&left); err != nil || left != 2 {
		t.Fatalf("remaining: %d %v", left, err)
	}
}

func TestWidgetSummary(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	k, _ := s.CreateKey(ctx, NewKey{Hash: "a", Prefix: "aaaaaaaa"})
	k2, _ := s.CreateKey(ctx, NewKey{Hash: "b", Prefix: "bbbbbbbb"})
	now := time.Now().UTC().Truncate(time.Second)
	v, err := s.CreateVisitor(ctx, k.ID, newID(), now)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := s.CreateVisitor(ctx, k2.ID, newID(), now)
	if err != nil {
		t.Fatal(err)
	}
	visitors := map[string]string{k.ID: v.ID, k2.ID: v2.ID}
	report := func(keyID, nonce, ja4 string, at time.Time) {
		t.Helper()
		reportV(t, s, WidgetReport{APIKeyID: keyID, Nonce: nonce, JA4: ja4, CreatedAt: at})
	}
	keyEvent := func(keyID, nonce, ipHash, ja4, ua string, at time.Time) {
		t.Helper()
		if err := s.InsertEvent(ctx, Event{ID: newID(), APIKeyID: keyID, VisitorID: visitors[keyID], Thumbmark: "tm",
			ClientHash: "ch", IPHash: ipHash, JA4: ja4, UserAgent: ua, Nonce: nonce, CreatedAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	event := func(nonce, ipHash, ja4, ua string, at time.Time) {
		t.Helper()
		keyEvent(k.ID, nonce, ipHash, ja4, ua, at)
	}
	min := time.Minute
	report(k.ID, "n1", "j", now)
	event("n1", "iph", "j", "ua", now.Add(-2*min))
	report(k.ID, "n2", "j", now)
	event("n2", "iph", "j", "ua", now.Add(2*min))
	report(k.ID, "n3", "j", now)
	event("n3", "iph", "j", "ua", now.Add(-11*min))
	report(k.ID, "n4", "j", now)
	report(k.ID, "n5", "j", now)
	event("n5", "other", "j", "ua", now.Add(-min))
	report(k.ID, "n6", "", now)
	event("n6", "iph", "", "ua", now.Add(-min))
	report(k.ID, "n7", "j", now)
	event("n7", "iph", "k", "ua", now.Add(-min))
	report(k.ID, "n8", "j", now)
	event("n8", "iph", "j", "curl", now.Add(-min))
	report(k.ID, "n9", "j", now)
	event("n9", "iph", "j", "ua", now.Add(-3*min))
	event("n9", "other", "j", "ua", now.Add(-min))
	// A page call with no report at all.
	event("n10", "iph", "j", "ua", now.Add(-min))
	// One nonce on two reports and one event: both reports match, the event matches.
	report(k.ID, "n11", "j", now)
	report(k.ID, "n11", "j", now.Add(min))
	event("n11", "iph", "j", "ua", now.Add(-min))
	// One-sided JA4 is unknown, not a mismatch.
	report(k.ID, "n12", "", now)
	event("n12", "iph", "j", "ua", now.Add(-min))
	// Verdict counts: n1..n3 pass, n4 inconclusive, n5 pow_failed; n1 verified,
	// n2 replayed twice. Other seeds carry no verdict.
	setVerdict := func(nonce, verdict string, verified bool, replays int) {
		t.Helper()
		if _, err := s.pool.Exec(ctx, `UPDATE widget_reports SET verdict = $3,
		   verified_at = CASE WHEN $4 THEN now() END, replay_count = $5
		   WHERE api_key_id = $1::uuid AND nonce = $2`, k.ID, nonce, verdict, verified, replays); err != nil {
			t.Fatal(err)
		}
	}
	setVerdict("n1", "pass", true, 0)
	setVerdict("n2", "pass", false, 2)
	setVerdict("n3", "pass", false, 0)
	setVerdict("n4", "inconclusive", false, 0)
	setVerdict("n5", "pow_failed", false, 0)
	setVerdict("n6", "interactive", false, 0)
	setVerdict("n7", "interactive_failed", false, 0)
	// Excluded: older than since, and under another key. k2's n4 event must
	// not match k's n4 report, nor count as k's unmatched event.
	report(k.ID, "old", "j", now.Add(-3*time.Hour))
	event("old-event", "iph", "j", "ua", now.Add(-2*time.Hour))
	report(k2.ID, "n1", "j", now)
	keyEvent(k2.ID, "n4", "iph", "j", "ua", now.Add(-min))

	got, err := s.WidgetSummary(ctx, k.ID, now.Add(-time.Hour), 10*min)
	if err != nil {
		t.Fatal(err)
	}
	// Reports n1,n2,n3,n4,n5,n6,n7,n8,n9,n11,n11,n12 = 12. Unmatched reports:
	// n3 (event 11 min away, outside the 10 min window) and n4 (only k2 has an
	// n4 event) = 2. JA4Unknown: n6 (both empty) and n12 (report empty) = 2.
	// Unmatched events of k since `since`: n3 (no report within 10 min) and
	// n10 (no report) = 2; both n9 events and the n11 event have a report in
	// the window, "old-event" predates since, and k2's n4 is another key.
	want := WidgetSummary{Reports: 12, Matched: 10, Unmatched: 2, IPMismatch: 2, JA4Mismatch: 1, JA4Unknown: 2,
		UAMismatch: 1, EventsUnmatched: 2, Pass: 3, Inconclusive: 1, PowFailed: 1, Verified: 1, Replayed: 1,
		Interactive: 1, InteractiveFailed: 1, InteractionSignals: map[string]int64{}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestWidgetSummaryInteractionSignals(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	k, _ := s.CreateKey(ctx, NewKey{Hash: "a", Prefix: "aaaaaaaa"})
	k2, _ := s.CreateKey(ctx, NewKey{Hash: "b", Prefix: "bbbbbbbb"})
	now := time.Now().UTC().Truncate(time.Second)
	seed := func(keyID, verdict, interaction string, at time.Time) {
		t.Helper()
		reportV(t, s, WidgetReport{APIKeyID: keyID, Nonce: "n", Verdict: verdict, Interaction: []byte(interaction), CreatedAt: at})
	}
	seed(k.ID, "interactive_failed", `{"signals":{"untrusted_event":true}}`, now)
	seed(k.ID, "interactive_failed", `{"signals":{"untrusted_event":true,"too_fast":true,"too_slow":false}}`, now)
	// Not counted: a pass row, an interactive row, another key, and a row before since.
	seed(k.ID, "pass", `{"signals":{"untrusted_event":true}}`, now)
	seed(k.ID, "interactive", `{"signals":{"straight_path":true}}`, now)
	seed(k2.ID, "interactive_failed", `{"signals":{"untrusted_event":true}}`, now)
	seed(k.ID, "interactive_failed", `{"signals":{"untrusted_event":true}}`, now.Add(-3*time.Hour))

	got, err := s.WidgetSummary(ctx, k.ID, now.Add(-time.Hour), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"untrusted_event": 2, "too_fast": 1}
	if !reflect.DeepEqual(got.InteractionSignals, want) {
		t.Fatalf("got %v, want %v", got.InteractionSignals, want)
	}
	empty, err := s.WidgetSummary(ctx, k2.ID, now.Add(4*time.Hour), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if empty.InteractionSignals == nil || len(empty.InteractionSignals) != 0 {
		t.Fatalf("empty: %#v", empty.InteractionSignals)
	}
}

// reportV inserts r with defaults filled in for the fields tests do not care about.
func reportV(t *testing.T, s *Store, r WidgetReport) WidgetReport {
	t.Helper()
	if r.ID == "" {
		r.ID = newID()
	}
	if r.Thumbmark == "" {
		r.Thumbmark = "tm"
	}
	if r.ClientHash == "" {
		r.ClientHash = "ch"
	}
	if r.IPHash == "" {
		r.IPHash = "iph"
	}
	if r.UserAgent == "" {
		r.UserAgent = "ua"
	}
	if err := s.InsertWidgetReport(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestWidgetReportVerdictRoundTrip(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	k, _ := s.CreateKey(ctx, NewKey{Hash: "a", Prefix: "aaaaaaaa"})
	now := time.Now().UTC().Truncate(time.Second)
	issued := now.Add(-time.Minute)
	r := reportV(t, s, WidgetReport{APIKeyID: k.ID, Nonce: "n", PowOK: true, Verdict: "pass", Hostname: "host.example",
		Classification: []byte(`{"a": 1}`), Signals: []byte(`{"b": [2]}`), Interaction: []byte(`{"c": 3}`), TokenIssuedAt: &issued, CreatedAt: now})
	verified, err := s.MarkWidgetVerified(ctx, k.ID, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if verified.VerifiedAt == nil {
		t.Fatal("VerifiedAt not set")
	}
	if verified.ID != r.ID || verified.APIKeyID != k.ID || verified.Nonce != "n" || !verified.PowOK ||
		verified.Verdict != "pass" || verified.Hostname != "host.example" ||
		string(verified.Classification) != `{"a": 1}` || string(verified.Signals) != `{"b": [2]}` || string(verified.Interaction) != `{"c": 3}` ||
		verified.TokenIssuedAt == nil || !verified.TokenIssuedAt.Equal(issued) ||
		!verified.CreatedAt.Equal(now) || verified.ReplayCount != 0 || verified.JA4 != "" {
		t.Fatalf("round trip: %+v", verified)
	}
	r.ID = verified.ID
	if err := s.InsertWidgetReport(ctx, r); !errors.Is(err, ErrDuplicateReport) {
		t.Fatalf("duplicate insert: %v", err)
	}
}

func TestMarkWidgetVerified(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	k, _ := s.CreateKey(ctx, NewKey{Hash: "a", Prefix: "aaaaaaaa"})
	k2, _ := s.CreateKey(ctx, NewKey{Hash: "b", Prefix: "bbbbbbbb"})
	r := reportV(t, s, WidgetReport{APIKeyID: k.ID, Nonce: "n", Verdict: "pass", CreatedAt: time.Now().UTC()})
	got, err := s.MarkWidgetVerified(ctx, k.ID, r.ID)
	if err != nil || got.VerifiedAt == nil {
		t.Fatalf("first: %+v %v", got, err)
	}
	if _, err := s.MarkWidgetVerified(ctx, k.ID, r.ID); !errors.Is(err, ErrAlreadyVerified) {
		t.Fatalf("second: %v", err)
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT replay_count FROM widget_reports WHERE id = $1`, r.ID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("replay_count %d %v", n, err)
	}
	if _, err := s.MarkWidgetVerified(ctx, k.ID, newID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
	if _, err := s.MarkWidgetVerified(ctx, k2.ID, r.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other key: %v", err)
	}
}

func TestMarkWidgetVerifiedRequiresToken(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	k, _ := s.CreateKey(ctx, NewKey{Hash: "a", Prefix: "aaaaaaaa"})
	now := time.Now().UTC()
	bad := reportV(t, s, WidgetReport{APIKeyID: k.ID, Nonce: "a", Verdict: "pow_failed", CreatedAt: now})
	if _, err := s.MarkWidgetVerified(ctx, k.ID, bad.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pow_failed: %v", err)
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT replay_count FROM widget_reports WHERE id = $1`, bad.ID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("replay_count %d %v", n, err)
	}
	ok := reportV(t, s, WidgetReport{APIKeyID: k.ID, Nonce: "b", Verdict: "interactive", CreatedAt: now})
	if got, err := s.MarkWidgetVerified(ctx, k.ID, ok.ID); err != nil || got.VerifiedAt == nil {
		t.Fatalf("interactive: %+v %v", got, err)
	}
}

func TestUpgradeWidgetReport(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	k, _ := s.CreateKey(ctx, NewKey{Hash: "a", Prefix: "aaaaaaaa"})
	k2, _ := s.CreateKey(ctx, NewKey{Hash: "b", Prefix: "bbbbbbbb"})
	now := time.Now().UTC().Truncate(time.Second)
	mk := func(nonce, verdict string) WidgetReport {
		return reportV(t, s, WidgetReport{APIKeyID: k.ID, Nonce: nonce, Verdict: verdict, CreatedAt: now})
	}
	trace := json.RawMessage(`{"input": "pointer"}`)

	r := mk("a", "inconclusive")
	if _, err := s.UpgradeWidgetReport(ctx, k2.ID, r.ID, "interactive", trace, &now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong key: %v", err)
	}
	if _, err := s.UpgradeWidgetReport(ctx, "not-a-uuid", r.ID, "interactive", trace, &now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad key: %v", err)
	}
	got, err := s.UpgradeWidgetReport(ctx, k.ID, r.ID, "interactive", trace, &now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != "interactive" || got.TokenIssuedAt == nil || !got.TokenIssuedAt.Equal(now) ||
		string(got.Interaction) != `{"input": "pointer"}` {
		t.Fatalf("upgraded: %+v", got)
	}
	if _, err := s.UpgradeWidgetReport(ctx, k.ID, r.ID, "interactive", trace, &now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second upgrade: %v", err)
	}

	f := mk("b", "inconclusive")
	got, err = s.UpgradeWidgetReport(ctx, k.ID, f.ID, "interactive_failed", trace, nil)
	if err != nil || got.Verdict != "interactive_failed" || got.TokenIssuedAt != nil {
		t.Fatalf("failed upgrade: %+v %v", got, err)
	}
	if _, err := s.UpgradeWidgetReport(ctx, k.ID, f.ID, "interactive", trace, &now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("upgrade after failed: %v", err)
	}
	for i, v := range []string{"pass", "pow_failed"} {
		o := mk("c"+v, v)
		if _, err := s.UpgradeWidgetReport(ctx, k.ID, o.ID, "interactive", trace, &now); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%d %s: %v", i, v, err)
		}
	}
}

func TestWidgetReportCorrelation(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	k, _ := s.CreateKey(ctx, NewKey{Hash: "a", Prefix: "aaaaaaaa"})
	now := time.Now().UTC().Truncate(time.Second)
	v, err := s.CreateVisitor(ctx, k.ID, newID(), now)
	if err != nil {
		t.Fatal(err)
	}
	event := func(nonce, ja4 string, at time.Time) {
		t.Helper()
		if err := s.InsertEvent(ctx, Event{ID: newID(), APIKeyID: k.ID, VisitorID: v.ID, Thumbmark: "tm",
			ClientHash: "ch", IPHash: "iph", JA4: ja4, UserAgent: "ua", Nonce: nonce, CreatedAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	tr := true
	window := 10 * time.Minute

	r1 := reportV(t, s, WidgetReport{APIKeyID: k.ID, Nonce: "n1", JA4: "j", CreatedAt: now})
	event("n1", "j", now.Add(-time.Minute))
	got, err := s.WidgetReportCorrelation(ctx, k.ID, r1.ID, window)
	if err != nil || !got.Matched || got.IPMatch == nil || got.JA4Match == nil || got.UAMatch == nil ||
		*got.IPMatch != tr || *got.JA4Match != tr || *got.UAMatch != tr {
		t.Fatalf("all equal: %+v %v", got, err)
	}

	r2 := reportV(t, s, WidgetReport{APIKeyID: k.ID, Nonce: "n2", JA4: "", CreatedAt: now})
	event("n2", "j", now.Add(-time.Minute))
	got, err = s.WidgetReportCorrelation(ctx, k.ID, r2.ID, window)
	if err != nil || !got.Matched || got.JA4Match != nil || got.IPMatch == nil || got.UAMatch == nil {
		t.Fatalf("empty ja4: %+v %v", got, err)
	}

	r3 := reportV(t, s, WidgetReport{APIKeyID: k.ID, Nonce: "n3", JA4: "j", CreatedAt: now})
	got, err = s.WidgetReportCorrelation(ctx, k.ID, r3.ID, window)
	if err != nil || got.Matched || got.IPMatch != nil || got.JA4Match != nil || got.UAMatch != nil {
		t.Fatalf("no event: %+v %v", got, err)
	}

	if _, err := s.WidgetReportCorrelation(ctx, k.ID, newID(), window); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing report: %v", err)
	}
}

func TestUpgradeWidgetReportRejectsInvalidUpgrade(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	k, _ := s.CreateKey(ctx, NewKey{Hash: "a", Prefix: "aaaaaaaa"})
	now := time.Now().UTC().Truncate(time.Second)
	trace := json.RawMessage(`{"input": "pointer"}`)
	r := reportV(t, s, WidgetReport{APIKeyID: k.ID, Nonce: "a", Verdict: "inconclusive", CreatedAt: now})
	cases := []struct {
		verdict  string
		issuedAt *time.Time
	}{
		{"pass", &now},
		{"pass", nil},
		{"interactive", nil},
		{"interactive_failed", &now},
	}
	for _, c := range cases {
		if _, err := s.UpgradeWidgetReport(ctx, k.ID, r.ID, c.verdict, trace, c.issuedAt); !errors.Is(err, ErrInvalidUpgrade) {
			t.Fatalf("%s issued=%v: %v", c.verdict, c.issuedAt != nil, err)
		}
	}
	var verdict string
	var interaction []byte
	var issued *time.Time
	if err := s.pool.QueryRow(ctx, `SELECT verdict, interaction, token_issued_at FROM widget_reports WHERE id = $1`, r.ID).
		Scan(&verdict, &interaction, &issued); err != nil {
		t.Fatal(err)
	}
	if verdict != "inconclusive" || interaction != nil || issued != nil {
		t.Fatalf("row touched: %s %s %v", verdict, interaction, issued)
	}
}
