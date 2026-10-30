// Package server wires the nazr HTTP API: /thumbmark (which composes every
// fingerprint, intelligence, classification and visitor package), /beacon,
// /log, health, admin key management, metrics and the static demo.
package server

import (
	"context"
	"encoding/json"
	"io/fs"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"time"

	"github.com/oklog/ulid/v2"

	"nazr/api/internal/auth"
	"nazr/api/internal/config"
	"nazr/api/internal/conn"
	"nazr/api/internal/ipintel"
	"nazr/api/internal/store"
	"nazr/api/internal/visitor"
)

// StoreAPI is the subset of *store.Store the server uses.
type StoreAPI interface {
	auth.KeyResolver
	Ping(ctx context.Context) error
	InsertEvent(ctx context.Context, e store.Event) error
	HasRecentEvent(ctx context.Context, ipHash, thumbmark string, since time.Time) (bool, error)
	RecordUAJA4(ctx context.Context, ja4, family string, now time.Time) error
	UAJA4Families(ctx context.Context, ja4 string, min int) ([]string, error)
	DominantCanvasProbe(ctx context.Context, keyID, cohort string, since time.Time, minSample int) (string, bool, error)
	CanvasProbeEntropy(ctx context.Context, keyID string, since time.Time) (visitors, distinct int64, err error)
	InsertWidgetReport(ctx context.Context, r store.WidgetReport) error
	WidgetSummary(ctx context.Context, keyID string, since time.Time, window time.Duration) (store.WidgetSummary, error)
	InsertClientLog(ctx context.Context, keyID *string, body json.RawMessage) error
	CreateKey(ctx context.Context, n store.NewKey) (store.APIKey, error)
	ListKeys(ctx context.Context) ([]store.APIKey, error)
	RevokeKey(ctx context.Context, id string) error
}

// IntelAPI is the subset of *ipintel.Service the server uses.
type IntelAPI interface {
	Lookup(addr netip.Addr) ipintel.Lookup
	JA4Families(ja4 string) []string
	Status() map[string]ipintel.SourceStatus
}

var (
	_ StoreAPI = (*store.Store)(nil)
	_ IntelAPI = (*ipintel.Service)(nil)
)

// Deps are the server's collaborators. Logger, Now and Rand default to
// slog.Default, time.Now and math/rand/v2.Float64. WidgetAssets is the built
// widget (widgetassets.Open); nil leaves the widget routes unregistered (404).
type Deps struct {
	Cfg      config.Config
	Store    StoreAPI
	Intel    IntelAPI
	Resolver *visitor.Resolver
	Limiter  auth.Limiter
	KeyCache *auth.KeyCache
	Logger   *slog.Logger
	Version  string
	Now      func() time.Time
	Rand     func() float64

	WidgetAssets fs.FS
}

type server struct {
	Deps
	ready readyCache
}

// New returns the public HTTP handler. /metrics is served separately by
// NewMetricsHandler.
func New(d Deps) http.Handler {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Rand == nil {
		d.Rand = rand.Float64
	}
	setStatusSource(d.Intel)
	s := &server{Deps: d}
	mux := http.NewServeMux()

	authMW := auth.Middleware(d.Store, d.Limiter, d.Cfg.DefaultRateLimit, d.KeyCache)
	thumb := s.globalCORS(s.bodyLimit(authMW(s.keyCORS(http.HandlerFunc(s.handleThumbmark)))))
	mux.Handle("POST /thumbmark", s.route("thumbmark", thumb))
	mux.Handle("OPTIONS /thumbmark", s.route("preflight", http.HandlerFunc(s.preflight)))
	// The widget frame runs on nazr's own origin, so origin scoping is skipped.
	reportMW := auth.MiddlewareOpts(d.Store, d.Limiter, d.Cfg.DefaultRateLimit, d.KeyCache, auth.MiddlewareOptions{SkipOrigin: true})
	mux.Handle("POST /widget/report", s.route("widget_report", s.bodyLimit(reportMW(http.HandlerFunc(s.handleWidgetReport)))))
	mux.Handle("POST /beacon", s.route("beacon", s.globalCORS(http.HandlerFunc(s.handleBeacon))))
	mux.Handle("OPTIONS /beacon", s.route("preflight", http.HandlerFunc(s.preflight)))
	mux.Handle("POST /log", s.route("log", s.globalCORS(http.HandlerFunc(s.handleLog))))
	mux.Handle("OPTIONS /log", s.route("preflight", http.HandlerFunc(s.preflight)))
	// Simple GETs: the global Allow-Origin is enough (no preflight), and it
	// lets a page on another origin, such as the demo banner, read them.
	mux.Handle("GET /healthz", s.route("healthz", s.globalCORS(http.HandlerFunc(s.handleHealthz))))
	mux.Handle("GET /readyz", s.route("readyz", s.globalCORS(http.HandlerFunc(s.handleReadyz))))

	admin := auth.AdminMiddleware(d.Cfg.AdminToken)
	mux.Handle("GET /admin/keys", s.route("admin", admin(http.HandlerFunc(s.handleListKeys))))
	mux.Handle("POST /admin/keys", s.route("admin", admin(http.HandlerFunc(s.handleCreateKey))))
	mux.Handle("DELETE /admin/keys/{id}", s.route("admin", admin(http.HandlerFunc(s.handleRevokeKey))))
	mux.Handle("GET /admin/keys/{id}/canvas-probe", s.route("admin", admin(http.HandlerFunc(s.handleCanvasProbeReport))))
	mux.Handle("GET /admin/keys/{id}/widget", s.route("admin", admin(http.HandlerFunc(s.handleWidgetSummary))))

	if d.WidgetAssets != nil {
		if wa, err := newWidgetAssets(d.WidgetAssets); err != nil {
			d.Logger.Error("server: widget assets unusable; widget routes disabled", "err", err)
		} else {
			// The literal loader.js and frame patterns win over {bundle}.
			mux.Handle("GET /widget/v1/loader.js", s.route("widget", s.handleWidgetLoader(wa)))
			mux.Handle("GET /widget/v1/frame", s.route("widget", s.handleWidgetFrame(wa)))
			mux.Handle("GET /widget/v1/{bundle}", s.route("widget", s.handleWidgetBundle(wa)))
		}
	}
	if d.Cfg.DemoDir != "" {
		mux.Handle("GET /demo/", s.route("demo", demoHandler(d.Cfg.DemoDir)))
	}
	mux.Handle("GET /{$}", s.route("root", s.globalCORS(http.HandlerFunc(s.handleRoot))))
	mux.Handle("/", s.route("not_found", http.HandlerFunc(notFound)))
	return mux
}

// route applies the per-request chain shared by every route:
// recover -> request ID -> header order -> metrics.
func (s *server) route(name string, h http.Handler) http.Handler {
	return s.recoverer(s.requestID(headerOrder(withMetrics(name, h))))
}

type orderKey struct{}

// headerOrder claims the request's wire header order from the connection
// holder (conn.Holder.OrderFor) for every request, whichever route it hits,
// so a request that is rejected early or is not fingerprinted cannot leave
// its entry queued for a later request with the same header names.
func headerOrder(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order := holderFromContext(r.Context()).OrderFor(r)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), orderKey{}, order)))
	})
}

// requestOrder returns the header order claimed by headerOrder, or claims it
// now when the request did not pass through route. nil means no capture.
func requestOrder(r *http.Request) []string {
	if o, ok := r.Context().Value(orderKey{}).([]string); ok {
		return o
	}
	return holderFromContext(r.Context()).OrderFor(r)
}

type requestIDKey struct{}

func requestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

func (s *server) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := ulid.Make().String()
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

// recoverer turns a handler panic into 500 internal and logs it with the
// request ID. http.ErrAbortHandler is re-raised so net/http aborts the
// response as intended.
func (s *server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		defer func() {
			p := recover()
			if p == nil {
				return
			}
			if p == http.ErrAbortHandler {
				panic(p)
			}
			s.Logger.Error("server: handler panic", "panic", p,
				"request_id", w.Header().Get("X-Request-Id"), "method", r.Method, "path", r.URL.Path)
			if rec.status == 0 {
				writeError(w, http.StatusInternalServerError, codeInternal, "internal server error")
			}
		}()
		next.ServeHTTP(rec, r)
	})
}

type holderKey struct{}

// WithHolder attaches a connection holder to ctx. It takes precedence over
// the holder conn.ConnContext installed; tests use it to inject captures.
func WithHolder(ctx context.Context, h *conn.Holder) context.Context {
	return context.WithValue(ctx, holderKey{}, h)
}

func holderFromContext(ctx context.Context) *conn.Holder {
	if h, ok := ctx.Value(holderKey{}).(*conn.Holder); ok && h != nil {
		return h
	}
	return conn.FromContext(ctx)
}

func (s *server) clientIP(r *http.Request) (netip.Addr, conn.HolderView) {
	h := holderFromContext(r.Context())
	var view conn.HolderView
	if h != nil {
		view = h.Snapshot()
	}
	return ClientIP(r, h, s.Cfg), view
}
