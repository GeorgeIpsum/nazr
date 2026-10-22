package store

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"os"
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

func TestMigrateIdempotent(t *testing.T) {
	s := newUnmigrated(t)
	ctx := context.Background()
	for i := range 2 {
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("migrate #%d: %v", i+1, err)
		}
	}
	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if s.Redis() != nil {
		t.Fatal("Redis should be nil when unset")
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
			e.IP = &ip
			e.Components = []byte(`{"a":1}`)
			e.Metadata = []byte(`{"b":2}`)
		}
		if err := s.InsertEvent(ctx, e); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
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
