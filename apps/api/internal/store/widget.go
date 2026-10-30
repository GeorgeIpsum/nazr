package store

import (
	"context"
	"encoding/json"
	"net/netip"
	"time"
)

// WidgetReport is one fingerprint report posted by the widget, correlated
// with /thumbmark events by Nonce.
type WidgetReport struct {
	ID, APIKeyID, Nonce, Thumbmark, ClientHash string
	IP                                         *netip.Addr
	IPHash, JA4, H2FP, UserAgent               string
	Components                                 json.RawMessage
	CreatedAt                                  time.Time
}

// InsertWidgetReport stores a widget report.
func (s *Store) InsertWidgetReport(ctx context.Context, r WidgetReport) error {
	var ip any
	if r.IP != nil {
		ip = *r.IP
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO widget_reports (id, api_key_id, nonce, thumbmark, client_hash, ip, ip_hash,
		   ja4, h2fp, user_agent, components, created_at)
		 VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		r.ID, r.APIKeyID, r.Nonce, r.Thumbmark, r.ClientHash, ip, r.IPHash,
		r.JA4, r.H2FP, r.UserAgent, nullJSON(r.Components), r.CreatedAt)
	return err
}

// WidgetSummary counts widget reports for a key and how they correlate with
// /thumbmark events. Counts are over report rows, except EventsUnmatched,
// which counts event rows carrying a nonce that no report matches.
type WidgetSummary struct {
	Reports, Matched, Unmatched, IPMismatch, JA4Mismatch, JA4Unknown, UAMismatch int64
	EventsUnmatched                                                              int64
}

// WidgetSummary correlates each report since `since` with the most recent
// event of the same key and nonce within `window` of the report, in either
// direction. A JA4 comparison is unknown when either side is empty.
// EventsUnmatched counts the key's events since `since` that carry a nonce
// but have no report of the same key and nonce within `window`.
func (s *Store) WidgetSummary(ctx context.Context, keyID string, since time.Time, window time.Duration) (WidgetSummary, error) {
	var out WidgetSummary
	err := s.pool.QueryRow(ctx,
		`SELECT count(*),
		   count(e.id),
		   count(*) FILTER (WHERE e.id IS NOT NULL AND r.ip_hash <> e.ip_hash),
		   count(*) FILTER (WHERE e.id IS NOT NULL AND r.ja4 <> '' AND e.ja4 <> '' AND r.ja4 <> e.ja4),
		   count(*) FILTER (WHERE e.id IS NOT NULL AND (r.ja4 = '' OR e.ja4 = '')),
		   count(*) FILTER (WHERE e.id IS NOT NULL AND r.user_agent <> e.user_agent)
		 FROM widget_reports r
		 LEFT JOIN LATERAL (
		   SELECT id, ip_hash, ja4, user_agent FROM events e
		   WHERE e.api_key_id = r.api_key_id AND e.nonce = r.nonce
		     AND e.created_at BETWEEN r.created_at - $3::interval AND r.created_at + $3::interval
		   ORDER BY e.created_at DESC, e.id DESC LIMIT 1
		 ) e ON true
		 WHERE r.api_key_id = $1::uuid AND r.created_at >= $2`,
		keyID, since, window).
		Scan(&out.Reports, &out.Matched, &out.IPMismatch, &out.JA4Mismatch, &out.JA4Unknown, &out.UAMismatch)
	if err != nil {
		return out, err
	}
	out.Unmatched = out.Reports - out.Matched
	err = s.pool.QueryRow(ctx,
		`SELECT count(*) FROM events e
		 WHERE e.api_key_id = $1::uuid AND e.nonce IS NOT NULL AND e.created_at >= $2
		   AND NOT EXISTS (
		     SELECT 1 FROM widget_reports r
		     WHERE r.api_key_id = e.api_key_id AND r.nonce = e.nonce
		       AND r.created_at BETWEEN e.created_at - $3::interval AND e.created_at + $3::interval)`,
		keyID, since, window).Scan(&out.EventsUnmatched)
	return out, err
}
