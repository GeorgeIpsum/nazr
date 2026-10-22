package auth

import (
	"container/list"
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"nazr/api/internal/store"
)

// WriteError writes the standard JSON error body.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "message": message})
}

// KeyResolver looks up and touches API keys.
type KeyResolver interface {
	FindKeyByHash(ctx context.Context, hash string) (*store.APIKey, error)
	TouchKey(ctx context.Context, id string) error
}

type ctxKey struct{}

// KeyFromContext returns the authenticated key, or nil. The returned
// *store.APIKey is shared with the cache and must be treated as read-only.
func KeyFromContext(ctx context.Context) *store.APIKey {
	k, _ := ctx.Value(ctxKey{}).(*store.APIKey)
	return k
}

var keyFormat = regexp.MustCompile(`^nzr_[a-z2-7]{52}$`)

const keyCacheCap = 10000

type cacheEntry struct {
	hash    string
	key     *store.APIKey
	expires time.Time
}

// KeyCache caches key lookups by hash in an in-process LRU and, when Redis is
// configured, in Redis. Revoked keys are cached too, so revocation propagates
// within the TTL. Returned *store.APIKey values are shared and read-only.
type KeyCache struct {
	ttl time.Duration
	rdb *redis.Client
	now func() time.Time
	cap int

	mu    sync.Mutex
	ll    *list.List
	items map[string]*list.Element
}

// NewKeyCache creates a cache with the given TTL; rdb may be nil.
func NewKeyCache(ttl time.Duration, rdb *redis.Client) *KeyCache {
	return &KeyCache{ttl: ttl, rdb: rdb, now: time.Now, cap: keyCacheCap,
		ll: list.New(), items: map[string]*list.Element{}}
}

func (c *KeyCache) get(hash string) (*store.APIKey, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[hash]
	if !ok {
		return nil, false
	}
	e := el.Value.(*cacheEntry)
	if !c.now().Before(e.expires) {
		c.ll.Remove(el)
		delete(c.items, hash)
		return nil, false
	}
	c.ll.MoveToFront(el)
	return e.key, true
}

func (c *KeyCache) put(hash string, k *store.APIKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp := c.now().Add(c.ttl)
	if el, ok := c.items[hash]; ok {
		e := el.Value.(*cacheEntry)
		e.key, e.expires = k, exp
		c.ll.MoveToFront(el)
		return
	}
	c.items[hash] = c.ll.PushFront(&cacheEntry{hash: hash, key: k, expires: exp})
	for c.ll.Len() > c.cap {
		last := c.ll.Back()
		c.ll.Remove(last)
		delete(c.items, last.Value.(*cacheEntry).hash)
	}
}

// Invalidate drops a key from the in-process cache and Redis.
func (c *KeyCache) Invalidate(hash string) {
	c.mu.Lock()
	if el, ok := c.items[hash]; ok {
		c.ll.Remove(el)
		delete(c.items, hash)
	}
	c.mu.Unlock()
	if c.rdb != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := c.rdb.Del(ctx, "nazr:key:"+hash).Err(); err != nil {
			slog.Warn("auth: key cache invalidate failed", "err", err)
		}
	}
}

// resolve returns the cached key for hash, falling back to Redis and then r.
// Only existing keys are cached; unknown keys always hit the resolver.
func (c *KeyCache) resolve(ctx context.Context, r KeyResolver, hash string) (*store.APIKey, error) {
	if c == nil {
		return r.FindKeyByHash(ctx, hash)
	}
	if k, ok := c.get(hash); ok {
		return k, nil
	}
	if c.rdb != nil {
		if b, err := c.rdb.Get(ctx, "nazr:key:"+hash).Bytes(); err == nil {
			var k store.APIKey
			if json.Unmarshal(b, &k) == nil {
				c.put(hash, &k)
				return &k, nil
			}
		} else if err != redis.Nil {
			slog.Warn("auth: redis key cache get failed", "err", err)
		}
	}
	k, err := r.FindKeyByHash(ctx, hash)
	if err != nil || k == nil {
		return nil, err
	}
	c.put(hash, k)
	if c.rdb != nil {
		if b, err := json.Marshal(k); err == nil {
			if err := c.rdb.Set(ctx, "nazr:key:"+hash, b, c.ttl).Err(); err != nil {
				slog.Warn("auth: redis key cache set failed", "err", err)
			}
		}
	}
	return k, nil
}

// Middleware authenticates requests by the x-api-key header, enforces origin
// scoping and rate limits, and stores the key in the request context. If the
// limiter errors (for example a Redis outage) the request is allowed and a
// warning is logged: failing open is preferred over rejecting all traffic.
func Middleware(r KeyResolver, l Limiter, defaultRate int, cache *KeyCache) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := req.Context()
			plain := strings.TrimSpace(req.Header.Get("x-api-key"))
			if plain == "" {
				WriteError(w, http.StatusForbidden, "unauthorized", "missing API key")
				return
			}
			if !keyFormat.MatchString(plain) {
				WriteError(w, http.StatusForbidden, "unauthorized", "invalid API key")
				return
			}
			hash := HashKey(plain)
			key, err := cache.resolve(ctx, r, hash)
			if err != nil {
				slog.Error("auth: key lookup failed", "err", err)
				WriteError(w, http.StatusServiceUnavailable, "store_unavailable", "key lookup unavailable")
				return
			}
			if key == nil {
				WriteError(w, http.StatusForbidden, "unauthorized", "invalid API key")
				return
			}
			if key.RevokedAt != nil {
				WriteError(w, http.StatusForbidden, "key_revoked", "API key has been revoked")
				return
			}
			if !OriginAllowed(req.Header.Get("Origin"), key.AllowedOrigins) {
				WriteError(w, http.StatusForbidden, "origin_not_allowed", "origin not allowed for this API key")
				return
			}
			rate := defaultRate
			if key.RateLimitPerMinute != nil {
				rate = *key.RateLimitPerMinute
			}
			ok, retry, err := l.Allow(ctx, key.ID, rate)
			if err != nil {
				slog.Warn("auth: rate limiter failed, allowing request", "err", err)
			} else if !ok {
				w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(retry.Seconds())))))
				WriteError(w, http.StatusTooManyRequests, "rate_limited", "rate limit exceeded")
				return
			}
			if err := r.TouchKey(ctx, key.ID); err != nil {
				slog.Warn("auth: touch key failed", "err", err)
			}
			next.ServeHTTP(w, req.WithContext(context.WithValue(ctx, ctxKey{}, key)))
		})
	}
}

// AdminMiddleware guards admin routes with a bearer token compared in constant
// time. An empty token disables the routes (404); a mismatch is 403.
func AdminMiddleware(token string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if token == "" {
				WriteError(w, http.StatusNotFound, "not_found", "not found")
				return
			}
			got, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
			if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				WriteError(w, http.StatusForbidden, "unauthorized", "invalid admin token")
				return
			}
			next.ServeHTTP(w, req)
		})
	}
}
