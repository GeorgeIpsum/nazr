package ipintel

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
)

// Component returns the `ip` fingerprint component. Value types are fixed:
// strings, bool and uint32.
func Component(addr netip.Addr, l Lookup) map[string]any {
	addr = addr.Unmap()
	version := "v6"
	if addr.Is4() {
		version = "v4"
	}
	return map[string]any{
		"address":       addr.String(),
		"version":       version,
		"asn":           l.ASN,
		"as_org":        l.ASOrg,
		"country":       l.Country,
		"region":        l.Region,
		"city":          l.City,
		"tor":           l.Tor,
		"vpn":           l.VPN,
		"datacenter":    l.Datacenter,
		"private_relay": l.PrivateRelay,
	}
}

// Identifier is the first 16 hex characters of sha256(salt + addr), a
// stable pseudonymous handle for an address.
func Identifier(addr netip.Addr, salt string) string {
	sum := sha256.Sum256([]byte(salt + addr.String()))
	return hex.EncodeToString(sum[:])[:16]
}
