package server

import (
	"net"
	"net/http"
	"net/netip"
	"strings"

	"nazr/api/internal/config"
	"nazr/api/internal/conn"
)

// ClientIP returns the client address for r. In terminate and plain modes it
// is the connection's address (from PROXY protocol when enabled, via the
// holder) or r.RemoteAddr. In proxied mode the values of cfg.ClientIPHeader
// are walked right to left, skipping addresses inside cfg.TrustedProxies; the
// first untrusted address wins. When every entry is trusted the leftmost is
// used; an unparseable entry stops the walk and the connection address is
// used. The result is unmapped (IPv4-in-IPv6 becomes IPv4) and may be the
// zero Addr when nothing parses.
func ClientIP(r *http.Request, holder *conn.Holder, cfg config.Config) netip.Addr {
	var peer netip.Addr
	if holder != nil {
		if ap := holder.Snapshot().RemoteAddr; ap.IsValid() {
			peer = ap.Addr().Unmap()
		}
	}
	if !peer.IsValid() {
		peer = parseHostAddr(r.RemoteAddr)
	}
	if cfg.TLSMode != "proxied" || cfg.ClientIPHeader == "" {
		return peer
	}
	var entries []string
	for _, line := range r.Header.Values(cfg.ClientIPHeader) {
		for _, e := range strings.Split(line, ",") {
			if e = strings.TrimSpace(e); e != "" {
				entries = append(entries, e)
			}
		}
	}
	if len(entries) == 0 {
		return peer
	}
	trusted := parsePrefixes(cfg.TrustedProxies)
	var last netip.Addr
	for i := len(entries) - 1; i >= 0; i-- {
		a := parseHostAddr(entries[i])
		if !a.IsValid() {
			return peer
		}
		if !inPrefixes(a, trusted) {
			return a
		}
		last = a
	}
	return last
}

// parseHostAddr parses "ip", "ip:port" or "[ipv6]:port".
func parseHostAddr(s string) netip.Addr {
	s = strings.TrimSpace(s)
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap()
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	if a, err := netip.ParseAddr(s); err == nil {
		return a.WithZone("").Unmap()
	}
	return netip.Addr{}
}

func parsePrefixes(list []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		s = strings.TrimSpace(s)
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

func inPrefixes(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
