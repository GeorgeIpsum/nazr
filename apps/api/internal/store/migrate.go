package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"nazr/api/migrations"
)

// Migrate applies all pending embedded migrations. A Postgres session
// advisory lock serialises concurrent callers, such as several tasks booting
// at once with NAZR_AUTO_MIGRATE.
func (s *Store) Migrate(ctx context.Context) error {
	db := stdlib.OpenDBFromPool(s.pool)
	defer db.Close()
	// Poll every second (goose defaults to 5s) for up to the same 5 minutes,
	// so a waiting task starts soon after the first one finishes.
	locker, err := lock.NewPostgresSessionLocker(lock.WithLockTimeout(1, 300))
	if err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	p, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS, goose.WithSessionLocker(locker))
	if err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	return nil
}

// MigrationVersion returns the highest applied migration version.
func (s *Store) MigrationVersion(ctx context.Context) (int64, error) {
	db := stdlib.OpenDBFromPool(s.pool)
	defer db.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	if err != nil {
		return 0, fmt.Errorf("store: migration version: %w", err)
	}
	return p.GetDBVersion(ctx)
}
