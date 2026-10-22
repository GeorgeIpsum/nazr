package tlsfp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Result holds the fingerprints derived from a ClientHello.
type Result struct {
	JA4 string
	// JA4Raw is the unhashed sorted form (FoxIO ja4_r).
	JA4Raw string
	// JA4Orig is the hashed original-order form (FoxIO ja4_o).
	JA4Orig string
	// JA4RawOrig is the unhashed original-order form (FoxIO ja4_ro).
	JA4RawOrig string
	JA3        string
	JA3Hash    string
	Hello      *ClientHello
}

// Fingerprint computes JA4 and JA3 for ch. transport is 't' (TCP) or 'q' (QUIC).
func Fingerprint(ch *ClientHello, transport byte) Result {
	r := Result{Hello: ch}
	ciphers := nonGrease(ch.CipherSuites)
	exts := nonGrease(ch.Extensions)
	a := ja4A(ch, transport, len(ciphers), len(exts))

	sortedC := sorted(ciphers)
	sortedE := sorted(withoutSNIALPN(exts))
	sigs := hexJoin(nonGrease(ch.SignatureAlgorithms)) // original order

	cStr, eStr := hexJoin(sortedC), hexJoin(sortedE)
	suffix := func(e string) string {
		if sigs == "" {
			return e
		}
		return e + "_" + sigs
	}
	r.JA4 = a + "_" + trunc(cStr) + "_" + truncE(suffix(eStr), len(sortedE))
	r.JA4Raw = a + "_" + cStr + "_" + suffix(eStr)

	oc := hexJoin(ciphers)
	oeAll := hexJoin(exts)
	// FoxIO defines the original-order variants as "less GREASE" only, so
	// SNI/ALPN stay in the list and the empty rule uses len(exts), not the
	// count after SNI/ALPN removal.
	r.JA4Orig = a + "_" + trunc(oc) + "_" + truncE(suffix(oeAll), len(exts))
	r.JA4RawOrig = a + "_" + oc + "_" + suffix(oeAll)

	r.JA3, r.JA3Hash = ja3(ch)
	return r
}

func ja4A(ch *ClientHello, transport byte, nc, ne int) string {
	sni := byte('i')
	if ch.SNI {
		sni = 'd'
	}
	return fmt.Sprintf("%c%s%c%02d%02d%s", transport, versionCode(ch), sni, min(nc, 99), min(ne, 99), alpnCode(ch.ALPN))
}

func highestVersion(ch *ClientHello) uint16 {
	var best uint16
	for _, v := range ch.SupportedVersions {
		if !IsGrease(v) && v > best {
			best = v
		}
	}
	if best == 0 {
		return ch.LegacyVersion
	}
	return best
}

func versionCode(ch *ClientHello) string {
	switch highestVersion(ch) {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	}
	return "00"
}

func isAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func alpnCode(alpn []string) string {
	if len(alpn) == 0 || alpn[0] == "" {
		return "00"
	}
	v := alpn[0]
	f, l := v[0], v[len(v)-1]
	if isAlnum(f) && isAlnum(l) {
		return string([]byte{f, l})
	}
	h := hex.EncodeToString([]byte{f, l}) // first byte hex, last byte hex
	return string([]byte{h[0], h[3]})
}

func nonGrease(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !IsGrease(v) {
			out = append(out, v)
		}
	}
	return out
}

func withoutSNIALPN(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if v != 0x0000 && v != 0x0010 {
			out = append(out, v)
		}
	}
	return out
}

func sorted(in []uint16) []uint16 {
	out := append([]uint16(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func hexJoin(in []uint16) string {
	parts := make([]string, len(in))
	for i, v := range in {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

const zeroHash = "000000000000"

// trunc hashes s, returning zeroHash when s is empty.
func trunc(s string) string {
	if s == "" {
		return zeroHash
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// truncE hashes the extension part; an empty extension list yields zeroHash
// regardless of signature algorithms.
func truncE(s string, nExt int) string {
	if nExt == 0 {
		return zeroHash
	}
	return trunc(s)
}
