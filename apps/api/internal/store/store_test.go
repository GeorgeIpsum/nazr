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

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/oklog/ulid/v2"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go"
	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"nazr/api/migrations"
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

// latestMigration is the highest migration in migrations/.
const latestMigration = 4

func TestVisitorCountBackfillAndIncrement(t *testing.T) {
	s := newUnmigrated(t)
	ctx := context.Background()
	db := stdlib.OpenDBFromPool(s.pool)
	defer db.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 1); err != nil {
		t.Fatal(err)
	}
	var keyID string
	if err := s.pool.QueryRow(ctx, `INSERT INTO api_keys (key_hash, prefix, label) VALUES ('h', 'pppppppp', 'l') RETURNING id::text`).Scan(&keyID); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := s.pool.Exec(ctx, `INSERT INTO visitors (id, api_key_id, first_seen, last_seen, request_count) VALUES ($1, $2::uuid, now(), now(), 0)`, newID(), keyID); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	count := func() int64 {
		var n int64
		if err := s.pool.QueryRow(ctx, `SELECT visitor_count FROM api_keys WHERE id = $1::uuid`, keyID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(); n != 3 {
		t.Fatalf("backfilled visitor_count = %d, want 3", n)
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
