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
// challenges minted under the same kid. A key signs from ActivatesAt until
// RetiredAt; RetiredAt is nil for the newest key, and in the publish window
// after a rotation the outgoing key's RetiredAt is in the future.
type SigningKey struct {
	Kid           string
	PrivateKeyPEM string
	PublicJWK     json.RawMessage
	HMACSecret    []byte
	CreatedAt     time.Time
	RetiredAt     *time.Time
	ActivatesAt   time.Time
}

// signingKeyCols is the column list scanSigningKey reads.
const signingKeyCols = `kid, private_key_pem, public_jwk, hmac_secret, created_at, retired_at, activates_at`

func scanSigningKey(row pgx.Row) (SigningKey, error) {
	var k SigningKey
	err := row.Scan(&k.Kid, &k.PrivateKeyPEM, &k.PublicJWK, &k.HMACSecret, &k.CreatedAt, &k.RetiredAt, &k.ActivatesAt)
	return k, err
}

// insertSigningKeySQL inserts a key; $6 is its activates_at.
const insertSigningKeySQL = `INSERT INTO signing_keys (kid, private_key_pem, public_jwk, hmac_secret, created_at, activates_at)
	VALUES ($1, $2, $3, $4, $5, $6)`

// signingKeyLock is the advisory lock key ("nazrsign") that serialises
// EnsureSigningKey and RotateSigningKey across processes.
// firstKeyLead is how far before created_at the first key activates.
const firstKeyLead = 60 * time.Second

const signingKeyLock int64 = 0x6e617a727369676e

// EnsureSigningKey returns the newest unretired signing key, inserting the
// key made by gen when none exists. An inserted key activates 60 seconds
// before its created_at, so a fresh database never has a key that is not yet
// active: a replica whose clock lags the database by less than the refresh
// period still sees it as active.
// The check and insert run under an advisory lock, so concurrent callers
// (several tasks booting together) end with one key; gen is called only
// when this call inserts.
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
		k.ActivatesAt = k.CreatedAt.Add(-firstKeyLead)
		if _, err = tx.Exec(ctx, insertSigningKeySQL,
			k.Kid, k.PrivateKeyPEM, []byte(k.PublicJWK), k.HMACSecret, k.CreatedAt, k.ActivatesAt); err != nil {
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

// ListSigningKeys returns every unretired key and every key retired (or
// retiring) after retiredAfter, newest first.
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

// RotateSigningKey inserts next to activate `publish` from now and sets every
// other unretired key to retire at the same moment, in one transaction under
// the signing-key advisory lock. Through the publish window both keys are
// published while the outgoing one keeps signing.
func (s *Store) RotateSigningKey(ctx context.Context, next SigningKey, publish time.Duration) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, signingKeyLock); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO signing_keys (kid, private_key_pem, public_jwk, hmac_secret, created_at, activates_at)
		 VALUES ($1, $2, $3, $4, $5, now() + $6::interval)`,
		next.Kid, next.PrivateKeyPEM, []byte(next.PublicJWK), next.HMACSecret, next.CreatedAt, publish); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE signing_keys SET retired_at = now() + $2::interval WHERE retired_at IS NULL AND kid <> $1`,
		next.Kid, publish); err != nil {
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
