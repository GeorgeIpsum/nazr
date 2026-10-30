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
