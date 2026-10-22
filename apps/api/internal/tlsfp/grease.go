// Package tlsfp parses TLS ClientHello messages and derives JA4 and JA3
// fingerprints from them.
package tlsfp

// IsGrease reports whether v is a GREASE value (RFC 8701).
func IsGrease(v uint16) bool { return v&0x0f0f == 0x0a0a }
