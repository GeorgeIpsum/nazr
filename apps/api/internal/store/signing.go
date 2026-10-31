package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// SigningKey is one row of the signing_keys table: an ES256 private key
// (PKCS#8 PEM), its public JWK, and the HMAC secret that authenticates
// challenges minted under the same kid. RetiredAt is nil for the key in use.
type SigningKey struct {
	Kid           string
	PrivateKeyPEM string
	PublicJWK     json.RawMessage
	HMACSecret    []byte
	CreatedAt     time.Time
	RetiredAt     *time.Time
}

// signingKeyCols is the column list scanSigningKey reads.
const signingKeyCols = `kid, private_key_pem, public_jwk, hmac_secret, created_at, retired_at`

func scanSigningKey(row pgx.Row) (SigningKey, error) {
	var k SigningKey
	err := row.Scan(&k.Kid, &k.PrivateKeyPEM, &k.PublicJWK, &k.HMACSecret, &k.CreatedAt, &k.RetiredAt)
	return k, err
}

const insertSigningKeySQL = `INSERT INTO signing_keys (kid, private_key_pem, public_jwk, hmac_secret, created_at)
	VALUES ($1, $2, $3, $4, $5)`

// signingKeyLock is the advisory lock key ("nazrsign") that serialises
// EnsureSigningKey across processes.
const signingKeyLock int64 = 0x6e617a727369676e

// EnsureSigningKey returns the active signing key, inserting the key made by
// gen when none exists. The check and insert run under an advisory lock, so
// concurrent callers (several tasks booting together) end with one active
// key; gen is called only when this call inserts.
func (s *Store) EnsureSigningKey(ctx context.Context, gen func() (SigningKey, error)) (SigningKey, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return SigningKey{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, signingKeyLock); err != nil {
		return SigningKey{}, err
	}
	k, err := scanSigningKey(tx.QueryRow(ctx,
		`SELECT `+signingKeyCols+` FROM signing_keys WHERE retired_at IS NULL ORDER BY created_at DESC LIMIT 1`))
	if errors.Is(err, pgx.ErrNoRows) {
		k, err = gen()
		if err != nil {
			return SigningKey{}, err
		}
		if _, err = tx.Exec(ctx, insertSigningKeySQL,
			k.Kid, k.PrivateKeyPEM, []byte(k.PublicJWK), k.HMACSecret, k.CreatedAt); err != nil {
			return SigningKey{}, err
		}
	} else if err != nil {
		return SigningKey{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return SigningKey{}, err
	}
	return k, nil
}

// ListSigningKeys returns the active key and every key retired after
// retiredAfter, newest first.
func (s *Store) ListSigningKeys(ctx context.Context, retiredAfter time.Time) ([]SigningKey, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+signingKeyCols+` FROM signing_keys
		 WHERE retired_at IS NULL OR retired_at > $1 ORDER BY created_at DESC`, retiredAfter)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SigningKey
	for rows.Next() {
		k, err := scanSigningKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RotateSigningKey inserts next as the active key and retires every other
// active key, in one transaction.
func (s *Store) RotateSigningKey(ctx context.Context, next SigningKey) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, insertSigningKeySQL,
		next.Kid, next.PrivateKeyPEM, []byte(next.PublicJWK), next.HMACSecret, next.CreatedAt); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE signing_keys SET retired_at = now() WHERE retired_at IS NULL AND kid <> $1`, next.Kid); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// DeleteRetiredSigningKeys deletes keys retired before retiredBefore and
// returns how many.
func (s *Store) DeleteRetiredSigningKeys(ctx context.Context, retiredBefore time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM signing_keys WHERE retired_at < $1`, retiredBefore)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
