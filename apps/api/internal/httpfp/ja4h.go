// Package httpfp computes the JA4H HTTP client fingerprint and the `header`
// fingerprint component.
package httpfp

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
)

const emptyHash = "000000000000"

func hash12(items []string) string {
	sum := sha256.Sum256([]byte(strings.Join(items, ",")))
	return hex.EncodeToString(sum[:])[:12]
}

func httpVersion(r *http.Request) string {
	switch {
	case r.ProtoMajor == 2:
		return "20"
	case r.ProtoMajor == 3:
		return "30"
	case r.ProtoMajor == 1 && r.ProtoMinor == 0:
		return "10"
	}
	return "11"
}

// effectiveOrder returns the header names in wire order without pseudo
// headers. When no capture is available (headerOrder empty) it falls back to
// the sorted canonical keys of r.Header so output stays deterministic.
func effectiveOrder(r *http.Request, headerOrder []string) []string {
	out := make([]string, 0, len(headerOrder))
	for _, h := range headerOrder {
		if h != "" && !strings.HasPrefix(h, ":") {
			out = append(out, h)
		}
	}
	if len(headerOrder) == 0 {
		for k := range r.Header {
			out = append(out, k)
		}
		sort.Strings(out)
	}
	return out
}

func language(r *http.Request) string {
	v := r.Header.Get("Accept-Language")
	if v == "" {
		return "0000"
	}
	// Matches the FoxIO reference implementation: drop '-', treat ';' as a
	// separator, lowercase, take the first element, truncate to 4 chars.
	v = strings.ToLower(strings.ReplaceAll(v, "-", ""))
	v = strings.ReplaceAll(v, ";", ",")
	v = strings.TrimSpace(strings.SplitN(v, ",", 2)[0])
	if len(v) > 4 {
		v = v[:4]
	}
	return v + strings.Repeat("0", 4-len(v))
}

type cookiePair struct{ name, pair string }

func cookiePairs(r *http.Request) []cookiePair {
	var out []cookiePair
	for _, line := range r.Header.Values("Cookie") {
		for _, part := range strings.Split(line, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			name, _, _ := strings.Cut(part, "=")
			out = append(out, cookiePair{strings.TrimSpace(name), part})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// JA4H returns the FoxIO JA4H fingerprint. Header names are hashed exactly as
// sent (the reference implementation does not change their case), excluding
// pseudo headers, Cookie and Referer.
func JA4H(r *http.Request, headerOrder []string) string {
	method := strings.ToLower(r.Method)
	if len(method) > 2 {
		method = method[:2]
	}
	hasCookie := len(r.Header.Values("Cookie")) > 0
	cookie, referer := "n", "n"
	if hasCookie {
		cookie = "c"
	}
	names := []string{}
	for _, h := range effectiveOrder(r, headerOrder) {
		l := strings.ToLower(h)
		if l == "referer" {
			referer = "r"
			continue
		}
		if strings.HasPrefix(l, "cookie") {
			continue
		}
		names = append(names, h)
	}
	if r.Header.Get("Referer") != "" {
		referer = "r"
	}
	count := len(names)
	if count > 99 {
		count = 99
	}
	a := method + httpVersion(r) + cookie + referer +
		string([]byte{byte('0' + count/10), byte('0' + count%10)}) + language(r)

	c, d := emptyHash, emptyHash
	if pairs := cookiePairs(r); len(pairs) > 0 {
		ns := make([]string, len(pairs))
		ps := make([]string, len(pairs))
		for i, p := range pairs {
			ns[i], ps[i] = p.name, p.pair
		}
		c, d = hash12(ns), hash12(ps)
	}
	return a + "_" + hash12(names) + "_" + c + "_" + d
}
