//lint:file-ignore SA1019 x/net/http2.Server.ServeConn is the only way to serve HTTP/2 on a conn that tees plaintext; net/http's bundled server requires *tls.Conn.

package conn

import (
	"context"
	"crypto/tls"
	"net/http"

	"golang.org/x/net/http2"
	"nazr/api/internal/h2fp"
)

// h2Conn is the decrypted side of an h2 connection: it feeds the first bytes
// read into an h2fp.Parser. Embedding *tls.Conn keeps ConnectionState
// available, so the HTTP/2 server still populates r.TLS.
type h2Conn struct {
	*tls.Conn
	holder *Holder
	p      *h2fp.Parser // nil once finished; only the h2 read loop touches it
}

func (c *h2Conn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if c.p != nil {
		if n > 0 && feedH2(c.p, c.holder, b[:n]) {
			c.p = nil
		} else if err != nil {
			finishH2(c.p, c.holder)
			c.p = nil
		}
	}
	return n, err
}

// ConfigureServer enables HTTP/2 on srv with the h2 frame tee. It installs a
// TLSNextProto["h2"] handler that wraps the negotiated *tls.Conn and serves
// it with an x/net/http2 server. h2limit overrides Options.H2Limit when > 0.
// Call it before srv.Serve.
func ConfigureServer(srv *http.Server, h2limit int) error {
	h2srv := &http2.Server{}
	if err := http2.ConfigureServer(srv, h2srv); err != nil {
		return err
	}
	srv.TLSNextProto["h2"] = func(hs *http.Server, tc *tls.Conn, h http.Handler) {
		ctx := context.Background()
		// net/http passes a handler exposing the connection context (with
		// ConnContext applied) through BaseContext.
		if bc, ok := h.(interface{ BaseContext() context.Context }); ok {
			ctx = bc.BaseContext()
		}
		holder := FromContext(ctx)
		if holder == nil {
			holder = holderOf(tc)
		}
		c := &h2Conn{Conn: tc, holder: holder}
		if holder != nil && holder.captureH2 {
			limit := holder.h2Limit
			if h2limit > 0 {
				limit = h2limit
			}
			c.p = h2fp.NewParser(limit)
		}
		h2srv.ServeConn(c, &http2.ServeConnOpts{Context: ctx, BaseConfig: hs, Handler: h})
	}
	return nil
}
