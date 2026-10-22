package auth

import (
	"context"
	"strconv"
	"sync"
	"time"
)

// Limiter is a per-key, per-minute request limiter.
type Limiter interface {
	// Allow counts one request for key and reports whether it is within
	// perMinute. When denied, retryAfter is the time until the next window.
	Allow(ctx context.Context, key string, perMinute int) (ok bool, retryAfter time.Duration, err error)
}

type memoryLimiter struct {
	now    func() time.Time
	mu     sync.Mutex
	counts map[string]int
}

// NewMemoryLimiter returns an in-process fixed-window (one minute) limiter.
// Stale windows are pruned on every call, so the map holds at most the keys
// seen in the current minute.
func NewMemoryLimiter(now func() time.Time) Limiter {
	if now == nil {
		now = time.Now
	}
	return &memoryLimiter{now: now, counts: map[string]int{}}
}

func (m *memoryLimiter) Allow(_ context.Context, key string, perMinute int) (bool, time.Duration, error) {
	t := m.now()
	minute := t.Unix() / 60
	suffix := ":" + strconv.FormatInt(minute, 10)
	m.mu.Lock()
	defer m.mu.Unlock()
	for k := range m.counts {
		if len(k) < len(suffix) || k[len(k)-len(suffix):] != suffix {
			delete(m.counts, k)
		}
	}
	k := key + suffix
	m.counts[k]++
	if m.counts[k] > perMinute {
		return false, windowRemaining(t), nil
	}
	return true, 0, nil
}

// windowRemaining is the time until the next minute boundary.
func windowRemaining(t time.Time) time.Duration {
	next := time.Unix((t.Unix()/60+1)*60, 0)
	d := next.Sub(t)
	if d <= 0 {
		d = time.Second
	}
	return d
}
