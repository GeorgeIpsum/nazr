package store

import (
	"context"
	"net/netip"
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
		if err := s.InsertWidgetReport(ctx, WidgetReport{ID: newID(), APIKeyID: keyID, Nonce: nonce, Thumbmark: "tm",
			ClientHash: "ch", IPHash: "iph", JA4: ja4, UserAgent: "ua", CreatedAt: at}); err != nil {
			t.Fatal(err)
		}
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
		UAMismatch: 1, EventsUnmatched: 2}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
