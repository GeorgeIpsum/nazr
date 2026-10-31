package store

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/testcontainers/testcontainers-go"
	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	adminURL string // connection URL of the shared server
	dbErr    error  // why no database is available
	dbSeq    atomic.Int64
)

func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) (code int) {
	ctx := context.Background()
	if u := os.Getenv("NAZR_TEST_DATABASE_URL"); u != "" {
		adminURL = u
		return m.Run()
	}
	defer func() {
		if r := recover(); r != nil { // testcontainers panics without Docker
			dbErr = fmt.Errorf("docker unavailable: %v", r)
			code = m.Run()
		}
	}()
	ctr, err := tcpg.Run(ctx, "postgres:17-alpine",
		tcpg.WithDatabase("postgres"), tcpg.WithUsername("postgres"), tcpg.WithPassword("nazr"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).WithStartupTimeout(90*time.Second)))
	if err != nil {
		dbErr = fmt.Errorf("start postgres container: %w", err)
		return m.Run()
	}
	defer func() { _ = testcontainers.TerminateContainer(ctr) }()
	adminURL, err = ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		dbErr = err
		return m.Run()
	}
	return m.Run()
}

// newStore returns a migrated store on a fresh database.
func newStore(t *testing.T) *Store {
	t.Helper()
	s := newUnmigrated(t)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s
}

func newUnmigrated(t *testing.T) *Store {
	t.Helper()
	if dbErr != nil {
		if os.Getenv("NAZR_TEST_REQUIRE_DB") == "1" {
			t.Fatalf("database required but unavailable: %v", dbErr)
		}
		t.Skipf("database unavailable: %v", dbErr)
	}
	ctx := context.Background()
	admin, err := Open(ctx, adminURL, "")
	if err != nil {
		t.Fatalf("open admin: %v", err)
	}
	defer admin.Close()
	name := fmt.Sprintf("nazr_test_%d_%d", os.Getpid(), dbSeq.Add(1))
	if _, err := admin.pool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create db: %v", err)
	}
	u, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	s, err := Open(ctx, u.String(), "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() {
		s.Close()
		a, err := Open(ctx, adminURL, "")
		if err != nil {
			return
		}
		defer a.Close()
		_, _ = a.pool.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})
	return s
}

func newID() string { return ulid.Make().String() }

// latestMigration is the highest migration in migrations/ (initial schema plus
// the widget, widget-challenge, widget-interaction and signing-activation
// migrations).
const latestMigration = 5

func TestVisitorCountIncrement(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	var keyID string
	if err := s.pool.QueryRow(ctx, `INSERT INTO api_keys (key_hash, prefix, label) VALUES ('h', 'pppppppp', 'l') RETURNING id::text`).Scan(&keyID); err != nil {
		t.Fatal(err)
	}
	count := func() int64 {
		var n int64
		if err := s.pool.QueryRow(ctx, `SELECT visitor_count FROM api_keys WHERE id = $1::uuid`, keyID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for range 3 {
		if _, err := s.CreateVisitor(ctx, keyID, newID(), time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if n := count(); n != 3 {
		t.Fatalf("visitor_count after 3 CreateVisitor = %d, want 3", n)
	}
	v := newID()
	if _, err := s.CreateVisitor(ctx, keyID, v, time.Now()); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 4 {
		t.Fatalf("visitor_count after CreateVisitor = %d, want 4", n)
	}
	if _, err := s.CreateVisitor(ctx, keyID, v, time.Now()); err == nil {
		t.Fatal("duplicate visitor id accepted")
	}
	if n := count(); n != 4 {
		t.Fatalf("failed insert bumped visitor_count to %d", n)
	}
	if _, total, err := s.RecordVisit(ctx, keyID, v, "tm", time.Now()); err != nil || total != 4 {
		t.Fatalf("RecordVisit total = %d, err %v", total, err)
	}
}

func TestMigrateSchema(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for _, c := range [][2]string{
		{"events", "canvas_probe"}, {"events", "cohort"},
		{"events", "ja3_hash"}, {"api_keys", "visitor_count"},
		{"events", "nonce"},
		{"widget_reports", "id"}, {"widget_reports", "api_key_id"}, {"widget_reports", "nonce"},
		{"widget_reports", "thumbmark"}, {"widget_reports", "client_hash"}, {"widget_reports", "ip"},
		{"widget_reports", "ip_hash"}, {"widget_reports", "ja4"}, {"widget_reports", "h2fp"},
		{"widget_reports", "user_agent"}, {"widget_reports", "components"}, {"widget_reports", "created_at"},
		{"widget_reports", "pow_ok"}, {"widget_reports", "verdict"}, {"widget_reports", "hostname"},
		{"widget_reports", "classification"}, {"widget_reports", "signals"}, {"widget_reports", "token_issued_at"},
		{"widget_reports", "verified_at"}, {"widget_reports", "replay_count"}, {"widget_reports", "interaction"},
		{"api_keys", "secret_hash"}, {"api_keys", "secret_prefix"},
		{"signing_keys", "kid"}, {"signing_keys", "private_key_pem"}, {"signing_keys", "public_jwk"},
		{"signing_keys", "hmac_secret"}, {"signing_keys", "created_at"}, {"signing_keys", "retired_at"},
		{"signing_keys", "activates_at"},
	} {
		var n int
		if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2`, c[0], c[1]).Scan(&n); err != nil || n != 1 {
			t.Errorf("column %s.%s: count %d, err %v", c[0], c[1], n, err)
		}
	}
	for _, idx := range []string{"events_thumbmark_created_idx", "events_probe_cohort_idx",
		"events_nonce_idx", "widget_reports_key_nonce_idx", "widget_reports_created_idx", "api_keys_secret_hash_idx"} {
		var n int
		if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM pg_indexes WHERE schemaname = current_schema() AND indexname = $1`, idx).Scan(&n); err != nil || n != 1 {
			t.Errorf("index %s: count %d, err %v", idx, n, err)
		}
	}
}

func TestMigrateIdempotent(t *testing.T) {
	s := newUnmigrated(t)
	ctx := context.Background()
	for i := range 2 {
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("migrate #%d: %v", i+1, err)
		}
		if v, err := s.MigrationVersion(ctx); err != nil || v != latestMigration {
			t.Fatalf("version after #%d: %d %v", i+1, v, err)
		}
		var n int
		if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM api_keys`).Scan(&n); err != nil {
			t.Fatalf("api_keys: %v", err)
		}
	}
	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if s.Redis() != nil {
		t.Fatal("Redis should be nil when unset")
	}
}

// Two ECS tasks (desired_count 2) boot together and both run Migrate; the
// session lock serialises them so neither sees a half-applied schema.
func TestMigrateConcurrent(t *testing.T) {
	s := newUnmigrated(t)
	ctx := context.Background()
	const n = 4
	errs := make(chan error, n)
	for range n {
		go func() { errs <- s.Migrate(ctx) }()
	}
	for range n {
		if err := <-errs; err != nil {
			t.Errorf("concurrent migrate: %v", err)
		}
	}
	if v, err := s.MigrationVersion(ctx); err != nil || v != latestMigration {
		t.Fatalf("version %d %v, want %d", v, err, latestMigration)
	}
}

func TestKeyLifecycle(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	rl := 120
	k, err := s.CreateKey(ctx, NewKey{Hash: "h1", Prefix: "abcd1234", Label: "demo",
		AllowedOrigins: []string{"https://a.example"}, RateLimitPerMinute: &rl})
	if err != nil {
		t.Fatal(err)
	}
	if k.ID == "" || k.RevokedAt != nil || k.CreatedAt.IsZero() {
		t.Fatalf("bad key %+v", k)
	}
	k2, err := s.CreateKey(ctx, NewKey{Hash: "h2", Prefix: "zzzz9999", Label: "noorigins"})
	if err != nil {
		t.Fatal(err)
	}
	if k2.AllowedOrigins == nil || len(k2.AllowedOrigins) != 0 || k2.RateLimitPerMinute != nil {
		t.Fatalf("defaults wrong: %+v", k2)
	}
	got, err := s.FindKeyByHash(ctx, "h1")
	if err != nil || got == nil || got.ID != k.ID || got.Prefix != "abcd1234" ||
		got.RateLimitPerMinute == nil || *got.RateLimitPerMinute != 120 || len(got.AllowedOrigins) != 1 {
		t.Fatalf("find: %+v %v", got, err)
	}
	if none, err := s.FindKeyByHash(ctx, "nope"); err != nil || none != nil {
		t.Fatalf("absent: %v %v", none, err)
	}
	if err := s.TouchKey(ctx, k.ID); err != nil {
		t.Fatal(err)
	}
	got, _ = s.FindKeyByHash(ctx, "h1")
	if got.LastUsedAt == nil {
		t.Fatal("LastUsedAt not set")
	}
	if err := s.RevokeKey(ctx, k.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeKey(ctx, k.ID); err != nil {
		t.Fatalf("second revoke should be no-op: %v", err)
	}
	got, err = s.FindKeyByHash(ctx, "h1")
	if err != nil || got == nil || got.RevokedAt == nil {
		t.Fatalf("revoked find: %+v %v", got, err)
	}
	if err := s.RevokeKey(ctx, "00000000-0000-0000-0000-000000000000"); err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	list, err := s.ListKeys(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("list: %v %v", list, err)
	}
}

func TestVisitorResolutionQueries(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	k, _ := s.CreateKey(ctx, NewKey{Hash: "a", Prefix: "aaaaaaaa"})
	k2, _ := s.CreateKey(ctx, NewKey{Hash: "b", Prefix: "bbbbbbbb"})
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := newID()
	v, err := s.CreateVisitor(ctx, k.ID, id, now)
	if err != nil || v.ID != id || v.APIKeyID != k.ID {
		t.Fatalf("create: %+v %v", v, err)
	}
	if g, err := s.GetVisitor(ctx, k.ID, id); err != nil || g == nil || !g.FirstSeen.Equal(now) {
		t.Fatalf("get: %+v %v", g, err)
	}
	if g, err := s.GetVisitor(ctx, k2.ID, id); err != nil || g != nil {
		t.Fatalf("wrong key should be nil: %+v %v", g, err)
	}
	if _, _, err := s.RecordVisit(ctx, k.ID, id, "tm", now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	since := now.Add(-2 * time.Hour)
	if g, err := s.FindVisitorByThumbmark(ctx, k.ID, "tm", since); err != nil || g == nil || g.ID != id {
		t.Fatalf("inside window: %+v %v", g, err)
	}
	if g, err := s.FindVisitorByThumbmark(ctx, k.ID, "tm", now); err != nil || g != nil {
		t.Fatalf("outside window: %+v %v", g, err)
	}
	if g, err := s.FindVisitorByThumbmark(ctx, k2.ID, "tm", since); err != nil || g != nil {
		t.Fatalf("other key: %+v %v", g, err)
	}
}

func TestRecordVisitCounts(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	k, _ := s.CreateKey(ctx, NewKey{Hash: "a", Prefix: "aaaaaaaa"})
	now := time.Now().UTC()
	v1, v2 := newID(), newID()
	if _, err := s.CreateVisitor(ctx, k.ID, v1, now); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		sharing, total, err := s.RecordVisit(ctx, k.ID, v1, "tm", now)
		if err != nil || sharing != 1 || total != 1 {
			t.Fatalf("v1: sharing=%d total=%d err=%v", sharing, total, err)
		}
	}
	if _, err := s.CreateVisitor(ctx, k.ID, v2, now); err != nil {
		t.Fatal(err)
	}
	sharing, total, err := s.RecordVisit(ctx, k.ID, v2, "tm", now)
	if err != nil || sharing != 2 || total != 2 {
		t.Fatalf("v2: sharing=%d total=%d err=%v", sharing, total, err)
	}
	var distinct int64
	if err := s.pool.QueryRow(ctx, `SELECT distinct_visitors FROM thumbmark_counts WHERE api_key_id=$1::uuid AND thumbmark='tm'`, k.ID).Scan(&distinct); err != nil || distinct != 2 {
		t.Fatalf("thumbmark_counts=%d err=%v", distinct, err)
	}
	g, _ := s.GetVisitor(ctx, k.ID, v1)
	if g.RequestCount != 2 {
		t.Fatalf("request_count=%d", g.RequestCount)
	}
	var c int64
	if err := s.pool.QueryRow(ctx, `SELECT count FROM visitor_thumbmarks WHERE visitor_id=$1 AND thumbmark='tm'`, v1).Scan(&c); err != nil || c != 2 {
		t.Fatalf("thumbmark count=%d err=%v", c, err)
	}
}

func TestInsertEventAndPrune(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	k, _ := s.CreateKey(ctx, NewKey{Hash: "a", Prefix: "aaaaaaaa"})
	now := time.Now().UTC()
	vid := newID()
	if _, err := s.CreateVisitor(ctx, k.ID, vid, now); err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("203.0.113.9")
	ages := []time.Duration{100 * time.Hour, 50 * time.Hour, time.Hour}
	for i, age := range ages {
		e := Event{ID: newID(), APIKeyID: k.ID, VisitorID: vid, Thumbmark: "tm", ClientHash: "ch",
			IPHash: "iph", JA4: "j", JA4H: "jh", H2FP: "h2", UserAgent: "ua", Path: "/",
			Classification: []byte(`{"bot":false}`), Signals: []byte(`[]`), CreatedAt: now.Add(-age)}
		if i == 1 {
			e.Nonce = "abc"
		}
		if i == 0 {
			e.JA3Hash = "03117a8ed39ef02427ebbc39f121275c"
			e.IP = &ip
			e.Components = []byte(`{"a":1}`)
			e.Metadata = []byte(`{"b":2}`)
		}
		if err := s.InsertEvent(ctx, e); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	// events.ja3_hash holds the JA3 hash when known and NULL otherwise.
	var ja3s []*string
	rows, err := s.pool.Query(ctx, `SELECT ja3_hash FROM events WHERE api_key_id = $1::uuid ORDER BY created_at`, k.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var v *string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		ja3s = append(ja3s, v)
	}
	if rows.Err() != nil || len(ja3s) != 3 || ja3s[0] == nil || *ja3s[0] != "03117a8ed39ef02427ebbc39f121275c" ||
		ja3s[1] != nil || ja3s[2] != nil {
		t.Fatalf("ja3_hash rows %v (%v)", ja3s, rows.Err())
	}
	// events.nonce holds the nonce when given and NULL otherwise.
	var nonces []*string
	nrows, err := s.pool.Query(ctx, `SELECT nonce FROM events WHERE api_key_id = $1::uuid ORDER BY created_at`, k.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer nrows.Close()
	for nrows.Next() {
		var v *string
		if err := nrows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		nonces = append(nonces, v)
	}
	if nrows.Err() != nil || len(nonces) != 3 || nonces[0] != nil || nonces[1] == nil || *nonces[1] != "abc" || nonces[2] != nil {
		t.Fatalf("nonce rows %v (%v)", nonces, nrows.Err())
	}
	if err := s.InsertClientLog(ctx, &k.ID, []byte(`{"m":"x"}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertClientLog(ctx, nil, []byte(`{"m":"y"}`)); err != nil {
		t.Fatal(err)
	}
	n, err := s.Prune(ctx, now.Add(-24*time.Hour), now.Add(-24*time.Hour), 1)
	if err != nil || n != 2 {
		t.Fatalf("prune: %d %v", n, err)
	}
	n, err = s.Prune(ctx, now.Add(time.Minute), now.Add(time.Minute), 10)
	if err != nil || n != 3 { // 1 event + 2 logs
		t.Fatalf("prune2: %d %v", n, err)
	}
}

func TestHasRecentEvent(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	k, _ := s.CreateKey(ctx, NewKey{Hash: "e", Prefix: "eeeeeeee"})
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := s.InsertEvent(ctx, Event{ID: newID(), APIKeyID: k.ID, VisitorID: newID(), Thumbmark: "tm",
		IPHash: "iph", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ip, tm string
		since  time.Time
		want   bool
	}{
		{"iph", "tm", now.Add(-10 * time.Minute), true},
		{"iph", "tm", now, true},
		{"iph", "tm", now.Add(time.Second), false},
		{"other", "tm", now.Add(-time.Hour), false},
		{"iph", "other", now.Add(-time.Hour), false},
	} {
		got, err := s.HasRecentEvent(ctx, tc.ip, tc.tm, tc.since)
		if err != nil || got != tc.want {
			t.Errorf("%+v: got %v err %v", tc, got, err)
		}
	}
}

func TestUAJA4Threshold(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for range 3 {
		if err := s.RecordUAJA4(ctx, "ja4x", "chrome", now); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RecordUAJA4(ctx, "ja4x", "curl", now); err != nil {
		t.Fatal(err)
	}
	got, err := s.UAJA4Families(ctx, "ja4x", 3)
	if err != nil || len(got) != 1 || got[0] != "chrome" {
		t.Fatalf("min=3: %v %v", got, err)
	}
	got, _ = s.UAJA4Families(ctx, "ja4x", 1)
	if len(got) != 2 {
		t.Fatalf("min=1: %v", got)
	}
	got, _ = s.UAJA4Families(ctx, "other", 1)
	if len(got) != 0 {
		t.Fatalf("other: %v", got)
	}
}

func TestRecordVisitConcurrentSharedThumbmark(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	k, _ := s.CreateKey(ctx, NewKey{Hash: "a", Prefix: "aaaaaaaa"})
	now := time.Now().UTC()
	const n = 8
	ids := make([]string, n)
	for i := range ids {
		ids[i] = newID()
		if _, err := s.CreateVisitor(ctx, k.ID, ids[i], now); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	sharing := make([]int64, n)
	errs := make([]error, n)
	for i := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sharing[i], _, errs[i] = s.RecordVisit(ctx, k.ID, ids[i], "tm", now)
		}()
	}
	wg.Wait()
	var maxSharing int64
	for i := range ids {
		if errs[i] != nil {
			t.Fatalf("visit %d: %v", i, errs[i])
		}
		maxSharing = max(maxSharing, sharing[i])
	}
	var distinct int64
	if err := s.pool.QueryRow(ctx, `SELECT distinct_visitors FROM thumbmark_counts WHERE api_key_id=$1::uuid AND thumbmark='tm'`, k.ID).Scan(&distinct); err != nil || distinct != n {
		t.Fatalf("distinct=%d err=%v", distinct, err)
	}
	if maxSharing != n {
		t.Fatalf("max sharing=%d", maxSharing)
	}
}

func TestInsertEventCanvasProbeCohort(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	k, _ := s.CreateKey(ctx, NewKey{Hash: "cp", Prefix: "cpcpcpcp"})
	now := time.Now().UTC()
	withID, withoutID := newID(), newID()
	if err := s.InsertEvent(ctx, Event{ID: withID, APIKeyID: k.ID, VisitorID: newID(), Thumbmark: "tm",
		IPHash: "iph", CanvasProbe: "deadbeef", Cohort: "chrome|chrome", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertEvent(ctx, Event{ID: withoutID, APIKeyID: k.ID, VisitorID: newID(), Thumbmark: "tm",
		IPHash: "iph", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	var probe, cohort string
	if err := s.pool.QueryRow(ctx, `SELECT canvas_probe, cohort FROM events WHERE id=$1`, withID).Scan(&probe, &cohort); err != nil ||
		probe != "deadbeef" || cohort != "chrome|chrome" {
		t.Fatalf("round trip: %q %q %v", probe, cohort, err)
	}
	var isNull bool
	if err := s.pool.QueryRow(ctx, `SELECT canvas_probe IS NULL AND cohort IS NULL FROM events WHERE id=$1`, withoutID).Scan(&isNull); err != nil || !isNull {
		t.Fatalf("expected NULLs: %v %v", isNull, err)
	}
}

func seedProbes(t *testing.T, s *Store, keyID, cohort string, probe string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := s.InsertEvent(context.Background(), Event{ID: newID(), APIKeyID: keyID, VisitorID: newID(), Thumbmark: "tm",
			IPHash: "iph", CanvasProbe: probe, Cohort: cohort, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDominantCanvasProbe(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	k, _ := s.CreateKey(ctx, NewKey{Hash: "dom", Prefix: "domdomdo"})
	since := time.Now().Add(-ProbeWindowDays * 24 * time.Hour)

	seedProbes(t, s, k.ID, "big", "X", ProbeNMin)
	seedProbes(t, s, k.ID, "big", "Y", 3)
	v, ok, err := s.DominantCanvasProbe(ctx, k.ID, "big", since, ProbeNMin)
	if err != nil || !ok || v != "X" {
		t.Fatalf("established: %q %v %v", v, ok, err)
	}

	seedProbes(t, s, k.ID, "small", "X", ProbeNMin-5)
	v, ok, err = s.DominantCanvasProbe(ctx, k.ID, "small", since, ProbeNMin)
	if err != nil || ok || v != "" {
		t.Fatalf("not established: %q %v %v", v, ok, err)
	}
}

func TestCanvasProbeEntropy(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	k, _ := s.CreateKey(ctx, NewKey{Hash: "ent", Prefix: "ententxx"})
	other, _ := s.CreateKey(ctx, NewKey{Hash: "ent2", Prefix: "entent22"})
	now := time.Now().UTC()
	ins := func(keyID, visitor, probe string, at time.Time) {
		t.Helper()
		if err := s.InsertEvent(ctx, Event{ID: newID(), APIKeyID: keyID, VisitorID: visitor, Thumbmark: "tm",
			IPHash: "iph", CanvasProbe: probe, CreatedAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	// v1 twice with A; v2, v3 share B; v4 has C. -> 4 visitors, 3 probes.
	ins(k.ID, "v1", "A", now)
	ins(k.ID, "v1", "A", now)
	ins(k.ID, "v2", "B", now)
	ins(k.ID, "v3", "B", now)
	ins(k.ID, "v4", "C", now)
	// Excluded: NULL probe, old event, other key.
	ins(k.ID, "v5", "", now)
	ins(k.ID, "v6", "D", now.Add(-60*24*time.Hour))
	ins(other.ID, "v7", "E", now)

	since := now.Add(-ProbeWindowDays * 24 * time.Hour)
	visitors, distinct, err := s.CanvasProbeEntropy(ctx, k.ID, since)
	if err != nil || visitors != 4 || distinct != 3 {
		t.Fatalf("got %d %d %v", visitors, distinct, err)
	}
	visitors, distinct, err = s.CanvasProbeEntropy(ctx, "00000000-0000-0000-0000-000000000000", since)
	if err != nil || visitors != 0 || distinct != 0 {
		t.Fatalf("empty: %d %d %v", visitors, distinct, err)
	}
}
