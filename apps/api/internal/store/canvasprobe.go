package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	// ProbeNMin is the minimum number of probed events a cohort needs before
	// its dominant canvas probe counts as established.
	ProbeNMin = 50
	// ProbeWindowDays is how far back cohort statistics look.
	ProbeWindowDays = 30
)

// DominantCanvasProbe returns the modal canvas_probe for a key's cohort since
// the given time. established is true only when at least minSample probed
// events exist; otherwise value is empty.
func (s *Store) DominantCanvasProbe(ctx context.Context, keyID, cohort string, since time.Time, minSample int) (string, bool, error) {
	var value string
	var total int
	err := s.pool.QueryRow(ctx, `
		SELECT canvas_probe, sum(c) OVER ()::int FROM (
			SELECT canvas_probe, count(*) AS c FROM events
			WHERE api_key_id = $1 AND cohort = $2 AND created_at >= $3 AND canvas_probe IS NOT NULL
			GROUP BY canvas_probe
		) g ORDER BY c DESC, canvas_probe LIMIT 1`, keyID, cohort, since).Scan(&value, &total)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if total < minSample {
		return "", false, nil
	}
	return value, true, nil
}
