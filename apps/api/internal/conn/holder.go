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
// Limitation: HTTP/1.1 over TLS gets no header order. http.Server reads
// HTTP/1.1 straight from the *tls.Conn and offers no hook for "http/1.1",
// and the conn cannot be wrapped without losing the *tls.Conn type that
// r.TLS depends on. HeaderOrder stays nil there and httpfp falls back to
// sorted keys. Plain-mode HTTP/1.1 (behind a TLS-terminating proxy) and
// HTTP/2 get real wire order. In plain mode only the first request head on a
// connection is sniffed; later keep-alive requests report the same order.
package conn

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"sync"

	"nazr/api/internal/h2fp"
	"nazr/api/internal/tlsfp"
)

// Holder collects per-connection observations. Fields are written by the
// connection's read path; read them through Snapshot.
type Holder struct {
	mu          sync.Mutex
	TLS         *tlsfp.Result
	H2          *h2fp.Result
	HeaderOrder []string
	RemoteAddr  netip.AddrPort
	TLSError    error
	H2Error     error

	captureH2 bool
	h2Limit   int
}

// HolderView is a lock-free copy of a Holder's exported fields.
type HolderView struct {
	TLS         *tlsfp.Result
	H2          *h2fp.Result
	HeaderOrder []string
	RemoteAddr  netip.AddrPort
	TLSError    error
	H2Error     error
}

// Snapshot copies the holder's fields under its lock.
func (h *Holder) Snapshot() HolderView {
	h.mu.Lock()
	defer h.mu.Unlock()
	v := HolderView{
		TLS:        h.TLS,
		H2:         h.H2,
		RemoteAddr: h.RemoteAddr,
		TLSError:   h.TLSError,
		H2Error:    h.H2Error,
	}
	if h.HeaderOrder != nil {
		v.HeaderOrder = append([]string{}, h.HeaderOrder...)
	}
	return v
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
