package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// APIKey is a stored API key (the secret itself is never stored).
type APIKey struct {
	ID                 string
	Prefix, Label      string
	AllowedOrigins     []string
	RateLimitPerMinute *int
	CreatedAt          time.Time
	RevokedAt          *time.Time
	LastUsedAt         *time.Time
}

// NewKey describes a key to create; Hash is the SHA-256 hex of the secret.
type NewKey struct {
	Hash, Prefix, Label string
	AllowedOrigins      []string
	RateLimitPerMinute  *int
}

const keyCols = `id::text, prefix, label, allowed_origins, rate_limit_per_minute, created_at, revoked_at, last_used_at`

func scanKey(row pgx.Row) (APIKey, error) {
	var k APIKey
	err := row.Scan(&k.ID, &k.Prefix, &k.Label, &k.AllowedOrigins, &k.RateLimitPerMinute,
		&k.CreatedAt, &k.RevokedAt, &k.LastUsedAt)
	if k.AllowedOrigins == nil {
		k.AllowedOrigins = []string{}
	}
	return k, err
}

// CreateKey inserts a new key.
func (s *Store) CreateKey(ctx context.Context, n NewKey) (APIKey, error) {
	origins := n.AllowedOrigins
	if origins == nil {
		origins = []string{}
	}
	return scanKey(s.pool.QueryRow(ctx,
		`INSERT INTO api_keys (key_hash, prefix, label, allowed_origins, rate_limit_per_minute)
		 VALUES ($1, $2, $3, $4, $5) RETURNING `+keyCols,
		n.Hash, n.Prefix, n.Label, origins, n.RateLimitPerMinute))
}

// ListKeys returns all keys, oldest first.
func (s *Store) ListKeys(ctx context.Context) ([]APIKey, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+keyCols+` FROM api_keys ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIKey
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RevokeKey marks a key revoked. Already-revoked keys succeed; unknown IDs
// return ErrNotFound.
func (s *Store) RevokeKey(ctx context.Context, id string) error {
	if !validUUID(id) {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE api_keys SET revoked_at = COALESCE(revoked_at, now()) WHERE id = $1::uuid`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// FindKeyByHash returns the key with the given hash, including revoked keys,
// or nil, nil when absent.
func (s *Store) FindKeyByHash(ctx context.Context, hash string) (*APIKey, error) {
	k, err := scanKey(s.pool.QueryRow(ctx, `SELECT `+keyCols+` FROM api_keys WHERE key_hash = $1`, hash))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// TouchKey records last use, at most once per minute per key per process.
func (s *Store) TouchKey(ctx context.Context, id string) error {
	now := time.Now()
	if v, ok := s.touched.Load(id); ok && now.Sub(v.(time.Time)) < time.Minute {
		return nil
	}
	if !validUUID(id) {
		return ErrNotFound
	}
	if _, err := s.pool.Exec(ctx, `UPDATE api_keys SET last_used_at = $2 WHERE id = $1::uuid`, id, now); err != nil {
		return err
	}
	s.touched.Store(id, now)
	return nil
}

func validUUID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, c := range id {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
