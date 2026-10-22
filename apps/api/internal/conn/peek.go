package conn

import (
	"io"
	"net"
	"sync"

	"nazr/api/internal/tlsfp"
)

// rawConn is the accepted TCP connection. On its first Read it consumes the
// PROXY v2 header (if enabled) and, in TLS mode, the ClientHello, then
// replays the ClientHello bytes to tls.Server. In plain mode it tees the
// first request head into the HTTP/1.1 (or h2c) sniffer.
type rawConn struct {
	net.Conn
	holder *Holder
	o      Options
	tls    bool

	mu      sync.Mutex // serialises the read path
	started bool
	err     error
	pending []byte
	sniff   *sniffer
}

func (c *rawConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started {
		c.started = true
		if err := c.start(); err != nil {
			c.err = err
			_ = c.Conn.Close()
		}
	}
	if c.err != nil {
		return 0, c.err
	}
	if len(c.pending) > 0 {
		n := copy(b, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	n, err := c.Conn.Read(b)
	if c.sniff != nil && n > 0 {
		if c.sniff.feed(b[:n]) {
			c.sniff = nil
		}
	}
	return n, err
}

func (c *rawConn) start() error {
	if c.o.ProxyProtocol {
		ap, err := readProxyV2(c.Conn)
		if err != nil {
			c.holder.set(func(h *Holder) { h.TLSError = err })
			return err
		}
		if ap.IsValid() {
			c.holder.set(func(h *Holder) { h.RemoteAddr = ap })
		}
	}
	if !c.tls {
		c.sniff = newSniffer(c.holder)
		return nil
	}
	raw, hs, err := tlsfp.ReadClientHello(io.LimitReader(c.Conn, int64(c.o.HelloLimit)))
	if err == nil {
		var ch *tlsfp.ClientHello
		if ch, err = tlsfp.Parse(hs); err == nil {
			r := tlsfp.Fingerprint(ch, 't')
			c.holder.set(func(h *Holder) { h.TLS = &r })
			c.pending = raw
			return nil
		}
	}
	c.holder.set(func(h *Holder) { h.TLSError = err })
	return err
}
