// Package conn wraps a net.Listener so every accepted connection carries a
// *Holder with what was observed on the wire: the TLS ClientHello
// fingerprint, the HTTP/2 connection preface fingerprint, the order of
// request header names, and the client address (from PROXY protocol v2 when
// enabled).
//
// Wiring:
//
//	ln := conn.Listen(tcpListener, conn.Options{TLSConfig: cfg, CaptureH2: true})
//	srv := &http.Server{Handler: h, ConnContext: conn.ConnContext}
//	_ = conn.ConfigureServer(srv, 0)
//	_ = srv.Serve(ln)
//
// and in handlers conn.FromContext(r.Context()).Snapshot().
//
// When TLS is enabled, Accept returns the *tls.Conn itself (so the stock
// http.Server populates r.TLS and negotiates h2). The ClientHello is peeked
// on the raw connection underneath it. HTTP/2 frames are teed above TLS in
// the TLSNextProto["h2"] hook installed by ConfigureServer.
//
// Header order is captured per request, not per connection: every HTTP/2
// header block (HPACK-decoded with the connection's dynamic table) and every
// plain-mode HTTP/1.1 request head is queued on the holder (at most
// maxOrders, oldest dropped), and OrderFor hands each request the queued
// entry whose header names match its own.
//
// Limitation: HTTP/1.1 over TLS gets no header order. http.Server reads
// HTTP/1.1 straight from the *tls.Conn and offers no hook for "http/1.1",
// and the conn cannot be wrapped without losing the *tls.Conn type that
// r.TLS depends on. OrderFor returns nil there and httpfp falls back to
// sorted keys. Plain-mode HTTP/1.1 (behind a TLS-terminating proxy) and
// HTTP/2 get real wire order, for every keep-alive request.
package conn

import (
	"context"
	"crypto/tls"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"nazr/api/internal/h2fp"
	"nazr/api/internal/tlsfp"
)

// Holder collects per-connection observations. Fields are written by the
// connection's read path; read them through Snapshot.
type Holder struct {
	mu         sync.Mutex
	TLS        *tlsfp.Result
	H2         *h2fp.Result
	RemoteAddr netip.AddrPort
	TLSError   error
	H2Error    error

	orders []orderEntry // FIFO of request header-name orders, oldest first

	captureH2 bool
	h2Limit   int
}

// maxOrders caps the queued request header orders per connection.
const maxOrders = h2fp.MaxBlocks

type orderEntry struct {
	method string // "" matches any method
	names  []string
}

// HolderView is a lock-free copy of a Holder's exported fields.
type HolderView struct {
	TLS        *tlsfp.Result
	H2         *h2fp.Result
	RemoteAddr netip.AddrPort
	TLSError   error
	H2Error    error
}

// Snapshot copies the holder's fields under its lock.
func (h *Holder) Snapshot() HolderView {
	h.mu.Lock()
	defer h.mu.Unlock()
	return HolderView{
		TLS:        h.TLS,
		H2:         h.H2,
		RemoteAddr: h.RemoteAddr,
		TLSError:   h.TLSError,
		H2Error:    h.H2Error,
	}
}

// PushOrder queues one request's header names in wire order (lowercase, no
// pseudo headers needed) for a later OrderFor. method, when non-empty, must
// equal the request's method for the entry to match. The read path calls it
// as request heads arrive; tests use it to inject captures.
func (h *Holder) PushOrder(method string, names []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pushOrderLocked(method, names)
}

func (h *Holder) pushOrderLocked(method string, names []string) {
	if len(h.orders) >= maxOrders {
		h.orders = append(h.orders[:0], h.orders[1:]...)
	}
	h.orders = append(h.orders, orderEntry{method: method, names: names})
}

// OrderFor returns the wire header-name order of r and consumes it: the
// oldest queued entry whose method equals r.Method and whose header-name
// multiset equals r.Header's. It returns nil when nothing matches (HTTP/1.1
// over TLS, a capture that was dropped, or a holder without capture);
// callers then fall back to sorted keys. Call it once per request.
//
// The comparison ignores the names net/http and x/net/http2 move out of or
// rewrite in r.Header, so they cannot cause a mismatch: Host (moved to
// r.Host), Content-Length and Transfer-Encoding (consumed by body framing),
// Trailer and Expect (consumed by the servers), and pseudo headers. Cookie
// counts once however many fields carried it (HTTP/2 joins them).
func (h *Holder) OrderFor(r *http.Request) []string {
	if h == nil || r == nil {
		return nil
	}
	want := requestNames(r.Header)
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, e := range h.orders {
		if e.method != "" && e.method != r.Method {
			continue
		}
		if !sameNames(want, e.names) {
			continue
		}
		h.orders = append(h.orders[:i], h.orders[i+1:]...)
		return append([]string{}, e.names...)
	}
	return nil
}

// matchIgnored lists header names the Go servers strip from or rewrite in
// r.Header (see OrderFor).
var matchIgnored = map[string]bool{
	"host": true, "content-length": true, "transfer-encoding": true,
	"trailer": true, "expect": true,
}

func requestNames(hdr http.Header) map[string]int {
	m := make(map[string]int, len(hdr))
	for k, vs := range hdr {
		l := strings.ToLower(k)
		if matchIgnored[l] || strings.HasPrefix(l, ":") || len(vs) == 0 {
			continue
		}
		if l == "cookie" {
			m[l] = 1
			continue
		}
		m[l] += len(vs)
	}
	return m
}

func sameNames(want map[string]int, names []string) bool {
	got := make(map[string]int, len(want))
	for _, raw := range names {
		l := strings.ToLower(raw)
		if matchIgnored[l] || strings.HasPrefix(l, ":") {
			continue
		}
		if l == "cookie" {
			got[l] = 1
			continue
		}
		got[l]++
		if got[l] > want[l] {
			return false
		}
	}
	return maps.Equal(got, want)
}

func (h *Holder) set(f func(h *Holder)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	f(h)
}

type ctxKey struct{}

// ConnContext is meant for http.Server.ConnContext: it attaches the holder
// of a connection accepted by Listen to the connection's context.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	if h := holderOf(c); h != nil {
		return context.WithValue(ctx, ctxKey{}, h)
	}
	return ctx
}

// FromContext returns the connection's holder, or nil when absent.
func FromContext(ctx context.Context) *Holder {
	h, _ := ctx.Value(ctxKey{}).(*Holder)
	return h
}

func holderOf(c net.Conn) *Holder {
	switch c := c.(type) {
	case *rawConn:
		return c.holder
	case *tls.Conn:
		if rc, ok := c.NetConn().(*rawConn); ok {
			return rc.holder
		}
	case *h2Conn:
		return c.holder
	}
	return nil
}
