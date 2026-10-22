package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Visitor is a per-key visitor identity.
type Visitor struct {
	ID, APIKeyID        string
	FirstSeen, LastSeen time.Time
	RequestCount        int64
}

const visitorCols = `id, api_key_id::text, first_seen, last_seen, request_count`

func scanVisitor(row pgx.Row) (*Visitor, error) {
	var v Visitor
	err := row.Scan(&v.ID, &v.APIKeyID, &v.FirstSeen, &v.LastSeen, &v.RequestCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// GetVisitor returns the visitor under keyID, or nil, nil.
func (s *Store) GetVisitor(ctx context.Context, keyID, visitorID string) (*Visitor, error) {
	return scanVisitor(s.pool.QueryRow(ctx,
		`SELECT `+visitorCols+` FROM visitors WHERE id = $1 AND api_key_id = $2::uuid`, visitorID, keyID))
}

// FindVisitorByThumbmark returns the most recently seen visitor under keyID
// with the thumbmark seen at or after since, or nil, nil.
func (s *Store) FindVisitorByThumbmark(ctx context.Context, keyID, thumbmark string, since time.Time) (*Visitor, error) {
	return scanVisitor(s.pool.QueryRow(ctx,
		`SELECT v.id, v.api_key_id::text, v.first_seen, v.last_seen, v.request_count
		 FROM visitor_thumbmarks t JOIN visitors v ON v.id = t.visitor_id
		 WHERE t.api_key_id = $1::uuid AND t.thumbmark = $2 AND t.last_seen >= $3
		 ORDER BY t.last_seen DESC LIMIT 1`, keyID, thumbmark, since))
}

// CreateVisitor inserts a new visitor.
func (s *Store) CreateVisitor(ctx context.Context, keyID, id string, now time.Time) (*Visitor, error) {
	return scanVisitor(s.pool.QueryRow(ctx,
		`INSERT INTO visitors (id, api_key_id, first_seen, last_seen, request_count)
		 VALUES ($1, $2::uuid, $3, $3, 0) RETURNING `+visitorCols, id, keyID, now))
}

// RecordVisit bumps the visitor, upserts its thumbmark row and recomputes the
// thumbmark's distinct-visitor count, all in one transaction. It returns the
// number of visitors sharing the thumbmark and the visitor total under the key.
func (s *Store) RecordVisit(ctx context.Context, keyID, visitorID, thumbmark string, now time.Time) (sharing, total int64, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Serialize count recomputation per (key, thumbmark); taken before the
	// visitor row lock so lock ordering is consistent.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1 || ':' || $2))`, keyID, thumbmark); err != nil {
		return 0, 0, err
	}
	// Lock the visitor row to serialize concurrent visits of the same visitor.
	var locked string
	if err := tx.QueryRow(ctx,
		`SELECT id FROM visitors WHERE id = $1 AND api_key_id = $2::uuid FOR UPDATE`,
		visitorID, keyID).Scan(&locked); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, 0, ErrNotFound
		}
		return 0, 0, err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE visitors SET last_seen = $2, request_count = request_count + 1 WHERE id = $1`,
		visitorID, now); err != nil {
		return 0, 0, err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO visitor_thumbmarks (api_key_id, visitor_id, thumbmark, first_seen, last_seen, count)
		 VALUES ($1::uuid, $2, $3, $4, $4, 1)
		 ON CONFLICT (visitor_id, thumbmark)
		 DO UPDATE SET last_seen = $4, count = visitor_thumbmarks.count + 1`,
		keyID, visitorID, thumbmark, now); err != nil {
		return 0, 0, err
	}
	if err := tx.QueryRow(ctx,
		`INSERT INTO thumbmark_counts (api_key_id, thumbmark, distinct_visitors)
		 VALUES ($1::uuid, $2, (SELECT count(*) FROM visitor_thumbmarks WHERE api_key_id = $1::uuid AND thumbmark = $2))
		 ON CONFLICT (api_key_id, thumbmark)
		 DO UPDATE SET distinct_visitors = (SELECT count(*) FROM visitor_thumbmarks WHERE api_key_id = $1::uuid AND thumbmark = $2)
		 RETURNING distinct_visitors`,
		keyID, thumbmark).Scan(&sharing); err != nil {
		return 0, 0, err
	}
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM visitors WHERE api_key_id = $1::uuid`, keyID).Scan(&total); err != nil {
		return 0, 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, 0, err
	}
	return sharing, total, nil
}
