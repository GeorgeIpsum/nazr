// Package store is the Postgres (pgx) and optional Redis persistence layer.
package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// ErrNotFound is returned when a referenced row does not exist.
var ErrNotFound = errors.New("store: not found")

// Store wraps the connection pool and optional Redis client.
type Store struct {
	pool    *pgxpool.Pool
	redis   *redis.Client
	touched sync.Map // key ID -> time.Time of last TouchKey UPDATE
}

// Open connects to Postgres and, when redisURL is non-empty, to Redis.
func Open(ctx context.Context, databaseURL, redisURL string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("store: parse database url: %w", err)
	}
	cfg.MaxConns = 16
	cfg.MaxConnLifetime = 30 * time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: open postgres: %w", err)
	}
	s := &Store{pool: pool}
	if err := s.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping postgres: %w", err)
	}
	if redisURL != "" {
		opt, err := redis.ParseURL(redisURL)
		if err != nil {
			pool.Close()
			return nil, fmt.Errorf("store: parse redis url: %w", err)
		}
		c := redis.NewClient(opt)
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := c.Ping(pctx).Err(); err != nil {
			_ = c.Close()
			pool.Close()
			return nil, fmt.Errorf("store: ping redis: %w", err)
		}
		s.redis = c
	}
	return s, nil
}

// Close releases all connections.
func (s *Store) Close() {
	s.pool.Close()
	if s.redis != nil {
		_ = s.redis.Close()
	}
}

// Ping checks Postgres connectivity.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Redis returns the Redis client, or nil when Redis is not configured.
func (s *Store) Redis() *redis.Client { return s.redis }
