package auth

import (
	"context"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

type redisLimiter struct {
	rdb *redis.Client
	now func() time.Time
}

// NewRedisLimiter returns a limiter shared across instances via Redis. Counters
// live under nazr:rl:<key>:<unixMinute> and expire after 60 seconds. Errors are
// returned to the caller; the middleware fails open on them.
func NewRedisLimiter(rdb *redis.Client) Limiter {
	return &redisLimiter{rdb: rdb, now: time.Now}
}

func (r *redisLimiter) Allow(ctx context.Context, key string, perMinute int) (bool, time.Duration, error) {
	t := r.now()
	rk := "nazr:rl:" + key + ":" + strconv.FormatInt(t.Unix()/60, 10)
	pipe := r.rdb.Pipeline()
	incr := pipe.Incr(ctx, rk)
	pipe.ExpireNX(ctx, rk, 60*time.Second)
	if _, err := pipe.Exec(ctx); err != nil {
		return false, 0, err
	}
	if incr.Val() > int64(perMinute) {
		return false, windowRemaining(t), nil
	}
	return true, 0, nil
}
