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
	report := func(keyID, nonce, ja4 string, at time.Time) {
		t.Helper()
		if err := s.InsertWidgetReport(ctx, WidgetReport{ID: newID(), APIKeyID: keyID, Nonce: nonce, Thumbmark: "tm",
			ClientHash: "ch", IPHash: "iph", JA4: ja4, UserAgent: "ua", CreatedAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	event := func(nonce, ipHash, ja4, ua string, at time.Time) {
		t.Helper()
		if err := s.InsertEvent(ctx, Event{ID: newID(), APIKeyID: k.ID, VisitorID: v.ID, Thumbmark: "tm",
			ClientHash: "ch", IPHash: ipHash, JA4: ja4, UserAgent: ua, Nonce: nonce, CreatedAt: at}); err != nil {
			t.Fatal(err)
		}
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
	// Excluded: older than since, and under another key.
	report(k.ID, "old", "j", now.Add(-3*time.Hour))
	report(k2.ID, "n1", "j", now)

	got, err := s.WidgetSummary(ctx, k.ID, now.Add(-time.Hour), 10*min)
	if err != nil {
		t.Fatal(err)
	}
	want := WidgetSummary{Reports: 9, Matched: 7, Unmatched: 2, IPMismatch: 2, JA4Mismatch: 1, JA4Unknown: 1, UAMismatch: 1}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
