package store

import (
	"context"
	"time"
)

// RecordUAJA4 counts one observation of a JA4 with a user-agent family.
func (s *Store) RecordUAJA4(ctx context.Context, ja4, family string, now time.Time) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO ua_ja4_observations (ja4, ua_family, count, first_seen, last_seen)
		 VALUES ($1, $2, 1, $3, $3)
		 ON CONFLICT (ja4, ua_family)
		 DO UPDATE SET count = ua_ja4_observations.count + 1, last_seen = $3`,
		ja4, family, now)
	return err
}

// UAJA4Families returns families observed with ja4 at least min times.
func (s *Store) UAJA4Families(ctx context.Context, ja4 string, min int) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT ua_family FROM ua_ja4_observations WHERE ja4 = $1 AND count >= $2 ORDER BY count DESC, ua_family`,
		ja4, min)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var f string
		if err := rows.Scan(&f); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
