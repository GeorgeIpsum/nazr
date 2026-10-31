package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrDuplicateReport is returned by InsertWidgetReport when the report ID exists.
var ErrDuplicateReport = errors.New("store: duplicate widget report")

// ErrAlreadyVerified is returned by MarkWidgetVerified when the report was
// verified before; the replay is counted.
var ErrAlreadyVerified = errors.New("store: widget report already verified")

// WidgetReport is one fingerprint report posted by the widget, correlated
// with /thumbmark events by Nonce.
type WidgetReport struct {
	ID, APIKeyID, Nonce, Thumbmark, ClientHash string
	IP                                         *netip.Addr
	IPHash, JA4, H2FP, UserAgent               string
	Components                                 json.RawMessage
	CreatedAt                                  time.Time
	Hostname                                   string
	PowOK                                      bool
	Verdict                                    string
	Classification, Signals                    json.RawMessage
	TokenIssuedAt, VerifiedAt                  *time.Time
	ReplayCount                                int
	Interaction                                json.RawMessage
}

const widgetReportCols = `id, api_key_id::text, nonce, thumbmark, client_hash, ip, ip_hash, ja4, h2fp, user_agent,
	components, created_at, hostname, pow_ok, verdict, classification, signals, token_issued_at, verified_at, replay_count, interaction`

// InsertWidgetReport stores a widget report.
func (s *Store) InsertWidgetReport(ctx context.Context, r WidgetReport) error {
	var ip any
	if r.IP != nil {
		ip = *r.IP
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO widget_reports (id, api_key_id, nonce, thumbmark, client_hash, ip, ip_hash,
		   ja4, h2fp, user_agent, components, created_at, hostname, pow_ok, verdict, classification,
		   signals, token_issued_at, verified_at, replay_count, interaction)
		 VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)`,
		r.ID, r.APIKeyID, r.Nonce, r.Thumbmark, r.ClientHash, ip, r.IPHash,
		r.JA4, r.H2FP, r.UserAgent, nullJSON(r.Components), r.CreatedAt,
		r.Hostname, r.PowOK, r.Verdict, nullJSON(r.Classification), nullJSON(r.Signals),
		r.TokenIssuedAt, r.VerifiedAt, r.ReplayCount, nullJSON(r.Interaction))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrDuplicateReport
	}
	return err
}

func scanWidgetReport(row pgx.Row) (WidgetReport, error) {
	var r WidgetReport
	err := row.Scan(&r.ID, &r.APIKeyID, &r.Nonce, &r.Thumbmark, &r.ClientHash, &r.IP, &r.IPHash, &r.JA4, &r.H2FP,
		&r.UserAgent, &r.Components, &r.CreatedAt, &r.Hostname, &r.PowOK, &r.Verdict, &r.Classification,
		&r.Signals, &r.TokenIssuedAt, &r.VerifiedAt, &r.ReplayCount, &r.Interaction)
	return r, err
}

// UpgradeWidgetReport moves an inconclusive report that has no token to
// verdict (interactive or interactive_failed), storing the interaction
// summary and the token issue time (nil when no token was issued). It
// succeeds once per report; any other state, an unknown report or another
// key returns ErrNotFound.
func (s *Store) UpgradeWidgetReport(ctx context.Context, keyID, id, verdict string, interaction json.RawMessage, issuedAt *time.Time) (WidgetReport, error) {
	if !validUUID(keyID) {
		return WidgetReport{}, ErrNotFound
	}
	r, err := scanWidgetReport(s.pool.QueryRow(ctx,
		`UPDATE widget_reports SET verdict = $3, interaction = $4, token_issued_at = $5
		 WHERE id = $1 AND api_key_id = $2::uuid AND verdict = 'inconclusive' AND token_issued_at IS NULL
		 RETURNING `+widgetReportCols, id, keyID, verdict, nullJSON(interaction), issuedAt))
	if errors.Is(err, pgx.ErrNoRows) {
		return WidgetReport{}, ErrNotFound
	}
	return r, err
}

// MarkWidgetVerified stamps the key's report as verified and returns it. A
// report that was already verified counts a replay and returns
// ErrAlreadyVerified; an unknown report, or one under another key, returns
// ErrNotFound.
func (s *Store) MarkWidgetVerified(ctx context.Context, keyID, id string) (WidgetReport, error) {
	if !validUUID(keyID) {
		return WidgetReport{}, ErrNotFound
	}
	r, err := scanWidgetReport(s.pool.QueryRow(ctx,
		`UPDATE widget_reports SET verified_at = now()
		 WHERE id = $1 AND api_key_id = $2::uuid AND verified_at IS NULL
		   AND verdict IN ('pass','interactive') RETURNING `+widgetReportCols, id, keyID))
	if err == nil {
		return r, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return WidgetReport{}, err
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE widget_reports SET replay_count = replay_count + 1 WHERE id = $1 AND api_key_id = $2::uuid
		   AND verdict IN ('pass','interactive')`, id, keyID)
	if err != nil {
		return WidgetReport{}, err
	}
	if tag.RowsAffected() == 0 {
		return WidgetReport{}, ErrNotFound
	}
	return WidgetReport{}, ErrAlreadyVerified
}

// WidgetCorrelation is how one report lines up with the /thumbmark event of
// the same key and nonce. Each *Match is nil when unmatched or, for JA4, when
// either side is empty.
type WidgetCorrelation struct {
	Matched                    bool
	IPMatch, JA4Match, UAMatch *bool
}

// WidgetReportCorrelation compares one report with the most recent event of
// the same key and nonce within `window` of the report, in either direction.
// A missing report returns ErrNotFound.
func (s *Store) WidgetReportCorrelation(ctx context.Context, keyID, id string, window time.Duration) (WidgetCorrelation, error) {
	var out WidgetCorrelation
	if !validUUID(keyID) {
		return out, ErrNotFound
	}
	var ip, ja4, ua *bool
	var matched bool
	err := s.pool.QueryRow(ctx,
		`SELECT e.id IS NOT NULL,
		   r.ip_hash = e.ip_hash,
		   CASE WHEN r.ja4 = '' OR e.ja4 = '' THEN NULL ELSE r.ja4 = e.ja4 END,
		   r.user_agent = e.user_agent
		 FROM widget_reports r
		 LEFT JOIN LATERAL (
		   SELECT id, ip_hash, ja4, user_agent FROM events e
		   WHERE e.api_key_id = r.api_key_id AND e.nonce = r.nonce
		     AND e.created_at BETWEEN r.created_at - $3::interval AND r.created_at + $3::interval
		   ORDER BY e.created_at DESC, e.id DESC LIMIT 1
		 ) e ON true
		 WHERE r.id = $1 AND r.api_key_id = $2::uuid`,
		id, keyID, window).Scan(&matched, &ip, &ja4, &ua)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	out.Matched = matched
	if matched {
		out.IPMatch, out.JA4Match, out.UAMatch = ip, ja4, ua
	}
	return out, nil
}

// WidgetSummary counts widget reports for a key and how they correlate with
// /thumbmark events. Counts are over report rows, except EventsUnmatched,
// which counts event rows carrying a nonce that no report matches.
type WidgetSummary struct {
	Reports, Matched, Unmatched, IPMismatch, JA4Mismatch, JA4Unknown, UAMismatch int64
	EventsUnmatched                                                              int64
	// Verdict and verification counts over the same report rows.
	Pass, Inconclusive, PowFailed, Verified, Replayed int64
	Interactive, InteractiveFailed                    int64
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
		   count(*) FILTER (WHERE e.id IS NOT NULL AND r.user_agent <> e.user_agent),
		   count(*) FILTER (WHERE r.verdict = 'pass'),
		   count(*) FILTER (WHERE r.verdict = 'inconclusive'),
		   count(*) FILTER (WHERE r.verdict = 'pow_failed'),
		   count(*) FILTER (WHERE r.verified_at IS NOT NULL),
		   count(*) FILTER (WHERE r.replay_count > 0),
		   count(*) FILTER (WHERE r.verdict = 'interactive'),
		   count(*) FILTER (WHERE r.verdict = 'interactive_failed')
		 FROM widget_reports r
		 LEFT JOIN LATERAL (
		   SELECT id, ip_hash, ja4, user_agent FROM events e
		   WHERE e.api_key_id = r.api_key_id AND e.nonce = r.nonce
		     AND e.created_at BETWEEN r.created_at - $3::interval AND r.created_at + $3::interval
		   ORDER BY e.created_at DESC, e.id DESC LIMIT 1
		 ) e ON true
		 WHERE r.api_key_id = $1::uuid AND r.created_at >= $2`,
		keyID, since, window).
		Scan(&out.Reports, &out.Matched, &out.IPMismatch, &out.JA4Mismatch, &out.JA4Unknown, &out.UAMismatch,
			&out.Pass, &out.Inconclusive, &out.PowFailed, &out.Verified, &out.Replayed,
			&out.Interactive, &out.InteractiveFailed)
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
