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
