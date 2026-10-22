package fingerprint

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

// Go's json decoder turns lone surrogate escapes (and any invalid UTF-8) into
// U+FFFD, but the client hashes the lone surrogate. protectSurrogates rewrites
// each lone \uD800-\uDFFF escape to a marker sequence (U+F8FF, 'x', four hex
// digits); a genuine U+F8FF is doubled so markers stay unambiguous.
// restoreSurrogates then turns markers into WTF-8 bytes (ED xx xx), which
// writeString re-emits as \udxxx.
const marker = '\uF8FF'

var markerBytes = []byte(string(marker))

func hexVal(b byte) int {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0')
	case b >= 'a' && b <= 'f':
		return int(b-'a') + 10
	case b >= 'A' && b <= 'F':
		return int(b-'A') + 10
	}
	return -1
}

// unit parses a \uXXXX escape at b[i:].
func unit(b []byte, i int) (uint16, bool) {
	if i+6 > len(b) || b[i] != '\\' || b[i+1] != 'u' {
		return 0, false
	}
	var u int
	for _, c := range b[i+2 : i+6] {
		h := hexVal(c)
		if h < 0 {
			return 0, false
		}
		u = u<<4 | h
	}
	return uint16(u), true
}

func protectSurrogates(b []byte) ([]byte, bool) {
	var out bytes.Buffer
	changed := false
	for i := 0; i < len(b); {
		switch {
		case b[i] == '\\':
			u, ok := unit(b, i)
			switch {
			case !ok:
				n := 2
				if i+1 >= len(b) {
					n = 1
				}
				out.Write(b[i : i+n])
				i += n
			case u == marker:
				out.Write(markerBytes)
				out.Write(markerBytes)
				changed = true
				i += 6
			case u >= 0xD800 && u <= 0xDBFF:
				if lo, ok2 := unit(b, i+6); ok2 && lo >= 0xDC00 && lo <= 0xDFFF {
					out.Write(b[i : i+12])
					i += 12
				} else {
					writeMarker(&out, u)
					changed = true
					i += 6
				}
			case u >= 0xDC00 && u <= 0xDFFF:
				writeMarker(&out, u)
				changed = true
				i += 6
			default:
				out.Write(b[i : i+6])
				i += 6
			}
		case bytes.HasPrefix(b[i:], markerBytes):
			out.Write(markerBytes)
			out.Write(markerBytes)
			changed = true
			i += len(markerBytes)
		default:
			out.WriteByte(b[i])
			i++
		}
	}
	if !changed {
		return b, false
	}
	return out.Bytes(), true
}

func writeMarker(out *bytes.Buffer, u uint16) {
	const hex = "0123456789abcdef"
	out.Write(markerBytes)
	out.WriteByte('x')
	out.WriteByte(hex[u>>12])
	out.WriteByte(hex[u>>8&0xf])
	out.WriteByte(hex[u>>4&0xf])
	out.WriteByte(hex[u&0xf])
}

func restoreString(s string) string {
	if !strings.ContainsRune(s, marker) {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r != marker {
			sb.WriteString(s[i : i+size])
			i += size
			continue
		}
		i += size
		if strings.HasPrefix(s[i:], string(marker)) {
			sb.WriteRune(marker)
			i += size
			continue
		}
		// 'x' followed by four hex digits, always produced by protectSurrogates.
		u := 0
		for _, c := range []byte(s[i+1 : i+5]) {
			u = u<<4 | hexVal(c)
		}
		i += 5
		sb.Write([]byte{0xE0 | byte(u>>12), 0x80 | byte(u>>6&0x3F), 0x80 | byte(u&0x3F)})
	}
	return sb.String()
}

func restoreSurrogates(v any) any {
	switch x := v.(type) {
	case string:
		return restoreString(x)
	case []any:
		for i, e := range x {
			x[i] = restoreSurrogates(e)
		}
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[restoreString(k)] = restoreSurrogates(e)
		}
		return out
	}
	return v
}
