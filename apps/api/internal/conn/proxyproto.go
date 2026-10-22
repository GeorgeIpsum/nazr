package conn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
)

var proxyV2Sig = []byte("\r\n\r\n\x00\r\nQUIT\n")

// maxProxyV2Body bounds the address+TLV block we accept.
const maxProxyV2Body = 4096

// ErrBadProxyHeader means ProxyProtocol was required but the connection did
// not start with a valid PROXY protocol v2 header.
var ErrBadProxyHeader = errors.New("conn: missing or invalid PROXY v2 header")

// readProxyV2 consumes exactly one PROXY v2 header from r. It returns the
// source address for PROXY/TCP over IPv4 or IPv6, and the zero AddrPort for
// LOCAL or other families (the socket address then stands).
func readProxyV2(r io.Reader) (netip.AddrPort, error) {
	var hdr [16]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return netip.AddrPort{}, ErrBadProxyHeader
	}
	if !bytes.Equal(hdr[:12], proxyV2Sig) || hdr[12]>>4 != 2 {
		return netip.AddrPort{}, ErrBadProxyHeader
	}
	cmd, fam := hdr[12]&0x0f, hdr[13]
	n := int(binary.BigEndian.Uint16(hdr[14:]))
	if cmd > 1 || n > maxProxyV2Body {
		return netip.AddrPort{}, ErrBadProxyHeader
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return netip.AddrPort{}, ErrBadProxyHeader
	}
	if cmd == 0 { // LOCAL: health check from the proxy itself
		return netip.AddrPort{}, nil
	}
	switch fam {
	case 0x11, 0x12: // TCP/UDP over IPv4
		if n < 12 {
			return netip.AddrPort{}, ErrBadProxyHeader
		}
		a := netip.AddrFrom4([4]byte(body[0:4]))
		return netip.AddrPortFrom(a, binary.BigEndian.Uint16(body[8:])), nil
	case 0x21, 0x22: // TCP/UDP over IPv6
		if n < 36 {
			return netip.AddrPort{}, ErrBadProxyHeader
		}
		a := netip.AddrFrom16([16]byte(body[0:16])).Unmap()
		return netip.AddrPortFrom(a, binary.BigEndian.Uint16(body[32:])), nil
	}
	return netip.AddrPort{}, nil
}
