package fingerprint

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"nazr/api/internal/jsnum"
)

// StableStringify mirrors the client's stableStringify: object keys sorted by
// UTF-16 code units, numbers formatted like JavaScript, strings escaped like
// JSON.stringify.
func StableStringify(v any) string {
	var sb strings.Builder
	write(&sb, v)
	return sb.String()
}

func write(sb *strings.Builder, v any) {
	switch x := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		sb.WriteString(strconv.FormatBool(x))
	case string:
		writeString(sb, x)
	case json.Number:
		f, err := strconv.ParseFloat(x.String(), 64)
		if err != nil && !isRange(err) {
			sb.WriteString("null")
			return
		}
		sb.WriteString(jsnum.Format(f)) // +-Inf (overflow) formats as null
	case float64:
		sb.WriteString(jsnum.Format(x))
	case float32:
		sb.WriteString(jsnum.Format(float64(x)))
	case int:
		sb.WriteString(jsnum.Format(float64(x)))
	case int64:
		sb.WriteString(jsnum.Format(float64(x)))
	case []string:
		sb.WriteByte('[')
		for i, s := range x {
			if i > 0 {
				sb.WriteByte(',')
			}
			writeString(sb, s)
		}
		sb.WriteByte(']')
	case []any:
		sb.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				sb.WriteByte(',')
			}
			write(sb, e)
		}
		sb.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		units := make(map[string][]uint16, len(keys))
		for _, k := range keys {
			units[k] = utf16.Encode([]rune(k))
		}
		sort.Slice(keys, func(i, j int) bool { return lessUnits(units[keys[i]], units[keys[j]]) })
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			writeString(sb, k)
			sb.WriteByte(':')
			write(sb, x[k])
		}
		sb.WriteByte('}')
	default:
		sb.WriteString("null")
	}
}

func isRange(err error) bool {
	ne, ok := err.(*strconv.NumError)
	return ok && ne.Err == strconv.ErrRange
}

func lessUnits(a, b []uint16) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

const hexDigits = "0123456789abcdef"

// writeString escapes s like JavaScript's JSON.stringify: no HTML escaping,
// U+007F/U+2028/U+2029 left alone, control characters as \u00xx. A lone
// surrogate (only representable in Go as the invalid UTF-8 form ED A0..BF xx)
// becomes \udxxx; JSON decoding replaces them with U+FFFD, so this cannot
// occur for decoded input.
func writeString(sb *strings.Builder, s string) {
	sb.WriteByte('"')
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			switch c {
			case '"':
				sb.WriteString(`\"`)
			case '\\':
				sb.WriteString(`\\`)
			case '\b':
				sb.WriteString(`\b`)
			case '\f':
				sb.WriteString(`\f`)
			case '\n':
				sb.WriteString(`\n`)
			case '\r':
				sb.WriteString(`\r`)
			case '\t':
				sb.WriteString(`\t`)
			default:
				if c < 0x20 {
					sb.WriteString(`\u00`)
					sb.WriteByte(hexDigits[c>>4])
					sb.WriteByte(hexDigits[c&0xf])
				} else {
					sb.WriteByte(c)
				}
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			if c == 0xED && i+2 < len(s) && s[i+1] >= 0xA0 && s[i+1] <= 0xBF && s[i+2]&0xC0 == 0x80 {
				u := 0xD000 | uint16(s[i+1]&0x3F)<<6 | uint16(s[i+2]&0x3F)
				sb.WriteString(`\u`)
				for shift := 12; shift >= 0; shift -= 4 {
					sb.WriteByte(hexDigits[(u>>uint(shift))&0xf])
				}
				i += 3
				continue
			}
			sb.WriteRune(utf8.RuneError)
			i++
			continue
		}
		sb.WriteString(s[i : i+size])
		i += size
	}
	sb.WriteByte('"')
}
