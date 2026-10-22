package store

import (
	"context"
	"encoding/json"
	"net/netip"
	"time"
)

// Event is one recorded request.
type Event struct {
	ID, APIKeyID, VisitorID, Thumbmark, ClientHash string
	IP                                             *netip.Addr
	IPHash                                         string
	JA4, JA4H, H2FP, UserAgent, Path               string
	JA3Hash                                        string // "" stores NULL
	Classification, Signals, Components, Metadata  json.RawMessage
	CreatedAt                                      time.Time
}

// nullJSON maps empty raw JSON to SQL NULL.
func nullJSON(m json.RawMessage) any {
	if len(m) == 0 {
		return nil
	}
	return []byte(m)
}

// InsertEvent stores an event.
func (s *Store) InsertEvent(ctx context.Context, e Event) error {
	var ip, ja3 any
	if e.IP != nil {
		ip = *e.IP
	}
	if e.JA3Hash != "" {
		ja3 = e.JA3Hash
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO events (id, api_key_id, visitor_id, thumbmark, client_hash, ip, ip_hash,
		   ja4, ja4h, h2fp, user_agent, path, classification, signals, components, metadata, created_at, ja3_hash)
		 VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
		e.ID, e.APIKeyID, e.VisitorID, e.Thumbmark, e.ClientHash, ip, e.IPHash,
		e.JA4, e.JA4H, e.H2FP, e.UserAgent, e.Path,
		nullJSON(e.Classification), nullJSON(e.Signals), nullJSON(e.Components), nullJSON(e.Metadata),
		e.CreatedAt, ja3)
	return err
}

// HasRecentEvent reports whether an event with thumbmark from the client IP
// identified by ipHash was recorded at or after since.
func (s *Store) HasRecentEvent(ctx context.Context, ipHash, thumbmark string, since time.Time) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM events WHERE thumbmark = $2 AND created_at >= $3 AND ip_hash = $1)`,
		ipHash, thumbmark, since).Scan(&ok)
	return ok, err
}

// InsertClientLog stores a client-side log body, optionally tied to a key.
func (s *Store) InsertClientLog(ctx context.Context, keyID *string, body json.RawMessage) error {
	var k any
	if keyID != nil {
		k = *keyID
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO client_logs (api_key_id, body) VALUES ($1::uuid, $2)`, k, []byte(body))
	return err
}
