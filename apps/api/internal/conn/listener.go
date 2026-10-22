package conn

import (
	"crypto/tls"
	"net"
	"net/netip"
	"slices"
)

// Options configures Listen.
type Options struct {
	// ProxyProtocol requires a PROXY protocol v2 header on every connection.
	ProxyProtocol bool
	// TLSConfig enables TLS termination; nil means plain HTTP.
	TLSConfig *tls.Config
	// CaptureH2 enables the HTTP/2 frame tee.
	CaptureH2 bool
	// H2Limit caps bytes fed to the h2 parser (default 65536).
	H2Limit int
	// HelloLimit caps bytes read for the ClientHello (default and max 16384).
	HelloLimit int
}

const (
	defaultH2Limit    = 64 * 1024
	defaultHelloLimit = 16 * 1024
	maxH1Head         = 32 * 1024
)

type listener struct {
	net.Listener
	o   Options
	cfg *tls.Config
}

// Listen wraps inner so accepted connections carry a *Holder. With
// o.TLSConfig set, Accept returns a *tls.Conn whose handshake runs lazily on
// first use; NextProtos defaults to h2 and http/1.1.
func Listen(inner net.Listener, o Options) net.Listener {
	if o.H2Limit <= 0 {
		o.H2Limit = defaultH2Limit
	}
	if o.HelloLimit <= 0 || o.HelloLimit > defaultHelloLimit {
		o.HelloLimit = defaultHelloLimit
	}
	l := &listener{Listener: inner, o: o}
	if o.TLSConfig != nil {
		l.cfg = o.TLSConfig.Clone()
		if len(l.cfg.NextProtos) == 0 {
			l.cfg.NextProtos = []string{"h2", "http/1.1"}
		} else if !slices.Contains(l.cfg.NextProtos, "http/1.1") {
			l.cfg.NextProtos = append(l.cfg.NextProtos, "http/1.1")
		}
	}
	return l
}

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	h := &Holder{
		RemoteAddr: addrPort(c.RemoteAddr()),
		captureH2:  l.o.CaptureH2,
		h2Limit:    l.o.H2Limit,
	}
	rc := &rawConn{Conn: c, holder: h, o: l.o, tls: l.cfg != nil}
	if l.cfg != nil {
		return tls.Server(rc, l.cfg), nil
	}
	return rc, nil
}

func addrPort(a net.Addr) netip.AddrPort {
	if ta, ok := a.(*net.TCPAddr); ok {
		ap := ta.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	if a == nil {
		return netip.AddrPort{}
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}
