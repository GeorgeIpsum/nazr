package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"nazr/api/migrations"
)

// Migrate applies all pending embedded migrations.
func (s *Store) Migrate(ctx context.Context) error {
	db := stdlib.OpenDBFromPool(s.pool)
	defer db.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
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
