package store

import (
	"context"
	"time"
)

// Prune deletes events older than eventsBefore and client logs older than
// logsBefore in batches, returning the total rows deleted.
func (s *Store) Prune(ctx context.Context, eventsBefore, logsBefore time.Time, batch int) (int64, error) {
	if batch <= 0 {
		batch = 10000
	}
	var total int64
	for _, q := range []struct {
		sql    string
		before time.Time
	}{
		{`DELETE FROM events WHERE id IN (SELECT id FROM events WHERE created_at < $1 LIMIT $2)`, eventsBefore},
		{`DELETE FROM client_logs WHERE id IN (SELECT id FROM client_logs WHERE created_at < $1 LIMIT $2)`, logsBefore},
	} {
		for {
			tag, err := s.pool.Exec(ctx, q.sql, q.before, batch)
			if err != nil {
				return total, err
			}
			n := tag.RowsAffected()
			total += n
			if n == 0 {
				break
			}
		}
	}
	return total, nil
}
