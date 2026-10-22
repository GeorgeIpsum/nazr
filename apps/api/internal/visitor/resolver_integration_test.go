package visitor

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid/v2"
	"github.com/testcontainers/testcontainers-go"
	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"nazr/api/internal/store"
)

var (
	adminURL string
	dbErr    error
	dbSeq    atomic.Int64
)

func TestMain(m *testing.M) { os.Exit(runMain(m)) }

// runMain mirrors the store package harness: NAZR_TEST_DATABASE_URL, else a
// testcontainers Postgres, else integration tests skip.
func runMain(m *testing.M) (code int) {
	ctx := context.Background()
	if u := os.Getenv("NAZR_TEST_DATABASE_URL"); u != "" {
		adminURL = u
		return m.Run()
	}
	defer func() {
		if r := recover(); r != nil {
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
	if adminURL, err = ctr.ConnectionString(ctx, "sslmode=disable"); err != nil {
		dbErr = err
	}
	return m.Run()
}

func newStore(t *testing.T) *store.Store {
	t.Helper()
	if dbErr != nil {
		if os.Getenv("NAZR_TEST_REQUIRE_DB") == "1" {
			t.Fatalf("database required but unavailable: %v", dbErr)
		}
		t.Skipf("database unavailable: %v", dbErr)
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("nazr_vtest_%d_%d", os.Getpid(), dbSeq.Add(1))
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		_ = conn.Close(ctx)
	})
	u, _ := url.Parse(adminURL)
	u.Path = "/" + name
	s, err := store.Open(ctx, u.String(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestResolveIntegration(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	k1, err := s.CreateKey(ctx, store.NewKey{Hash: "h1", Prefix: "p1", Label: "one"})
	if err != nil {
		t.Fatal(err)
	}
	k2, err := s.CreateKey(ctx, store.NewKey{Hash: "h2", Prefix: "p2", Label: "two"})
	if err != nil {
		t.Fatal(err)
	}
	r := &Resolver{Repo: s, Window: time.Hour, Now: time.Now, NewID: func() string { return ulid.Make().String() }}

	a, err := r.Resolve(ctx, k1.ID, "", "tm")
	if err != nil || !a.IsNew || a.Sharing != 1 || a.Total != 1 {
		t.Fatalf("first: %+v %v", a, err)
	}
	// Same thumbmark, no body id: matched by thumbmark.
	b, err := r.Resolve(ctx, k1.ID, "", "tm")
	if err != nil || b.IsNew || b.ID != a.ID {
		t.Fatalf("thumbmark match: %+v %v", b, err)
	}
	// Body id reuse with a changed thumbmark: sharing counts per thumbmark.
	c, err := r.Resolve(ctx, k1.ID, a.ID, "tm2")
	if err != nil || c.IsNew || c.ID != a.ID || c.Sharing != 1 {
		t.Fatalf("body id: %+v %v", c, err)
	}
	// Body id wins over a thumbmark held by a different visitor.
	bID := ulid.Make().String()
	if _, err := s.CreateVisitor(ctx, k1.ID, bID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RecordVisit(ctx, k1.ID, bID, "tmB", time.Now()); err != nil {
		t.Fatal(err)
	}
	f, err := r.Resolve(ctx, k1.ID, a.ID, "tmB")
	if err != nil || f.ID != a.ID || f.IsNew {
		t.Fatalf("body id must win over thumbmark owner %s: %+v %v", bID, f, err)
	}
	// Another key must never reuse the visitor.
	d, err := r.Resolve(ctx, k2.ID, a.ID, "tm")
	if err != nil || !d.IsNew || d.ID == a.ID || d.Total != 1 {
		t.Fatalf("foreign key: %+v %v", d, err)
	}
	// A second visitor sharing a thumbmark raises the sharing count.
	id2 := ulid.Make().String()
	if _, err := s.CreateVisitor(ctx, k1.ID, id2, time.Now()); err != nil {
		t.Fatal(err)
	}
	sharing, total, err := s.RecordVisit(ctx, k1.ID, id2, "tm", time.Now())
	if err != nil || sharing != 2 || total != 3 {
		t.Fatalf("sharing: %d %d %v", sharing, total, err)
	}
	if u := Uniqueness(sharing, total); u != 0.6667 {
		t.Fatalf("uniqueness %v", u)
	}
}
