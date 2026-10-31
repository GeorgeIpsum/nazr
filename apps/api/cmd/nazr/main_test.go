package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"nazr/api/internal/store"
)

var (
	adminURL string // connection URL of the shared server
	dbErr    error  // why no database is available
	dbSeq    atomic.Int64
)

func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

// runMain mirrors the store package's harness: NAZR_TEST_DATABASE_URL, else a
// throwaway Postgres container.
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

// newTestDB creates a migrated database, dropped on cleanup, and returns its
// URL. It skips (fails under NAZR_TEST_REQUIRE_DB=1) when no database exists.
func newTestDB(t *testing.T) string {
	t.Helper()
	if dbErr != nil {
		if os.Getenv("NAZR_TEST_REQUIRE_DB") == "1" {
			t.Fatalf("database required but unavailable: %v", dbErr)
		}
		t.Skipf("database unavailable: %v", dbErr)
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatalf("open admin: %v", err)
	}
	defer admin.Close(ctx)
	name := fmt.Sprintf("nazr_cli_%d_%d", os.Getpid(), dbSeq.Add(1))
	if err := func() error { _, err := admin.Exec(ctx, "CREATE DATABASE "+name); return err }(); err != nil {
		t.Fatalf("create db: %v", err)
	}
	t.Cleanup(func() {
		a, err := pgx.Connect(ctx, adminURL)
		if err != nil {
			return
		}
		defer a.Close(ctx)
		_, _ = a.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})
	u, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	s, err := store.Open(ctx, u.String(), "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return u.String()
}
