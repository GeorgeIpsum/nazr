package tlsfp

import "fmt"

func hex4(in []uint16) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !IsGrease(v) {
			out = append(out, fmt.Sprintf("%04x", v))
		}
	}
	return out
}

func versionString(v uint16) string {
	switch v {
	case 0x0304:
		return "1.3"
	case 0x0303:
		return "1.2"
	case 0x0302:
		return "1.1"
	case 0x0301:
		return "1.0"
	case 0x0300:
		return "3.0"
	}
	return fmt.Sprintf("0x%04x", v)
}

// Component returns the `tls` fingerprint component. Value types are fixed:
// strings, bool, and non-nil []string.
func (r Result) Component() map[string]any {
	ch := r.Hello
	if ch == nil {
		ch = &ClientHello{}
	}
	alpn := append([]string{}, ch.ALPN...)
	return map[string]any{
		"version":    versionString(highestVersion(ch)),
		"ja4":        r.JA4,
		"ja4_r":      r.JA4Raw,
		"ja3":        r.JA3,
		"ja3_hash":   r.JA3Hash,
		"ciphers":    hex4(ch.CipherSuites),
		"extensions": hex4(ch.Extensions),
		"sig_algs":   hex4(ch.SignatureAlgorithms),
		"groups":     hex4(ch.SupportedGroups),
		"sni":        ch.SNI,
		"alpn":       alpn,
	}
}
