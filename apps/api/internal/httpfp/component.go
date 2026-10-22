package httpfp

import (
	"net/http"
	"strconv"
	"strings"
)

var clientHintHeaders = []struct{ key, header string }{
	{"ua", "Sec-CH-UA"},
	{"mobile", "Sec-CH-UA-Mobile"},
	{"platform", "Sec-CH-UA-Platform"},
	{"arch", "Sec-CH-UA-Arch"},
	{"bitness", "Sec-CH-UA-Bitness"},
	{"model", "Sec-CH-UA-Model"},
	{"platformVersion", "Sec-CH-UA-Platform-Version"},
	{"fullVersionList", "Sec-CH-UA-Full-Version-List"},
}

func parseAcceptLanguage(raw string) map[string]any {
	q := map[string]any{}
	for _, item := range strings.Split(raw, ",") {
		tag, params, _ := strings.Cut(item, ";")
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		w := float64(1)
		for _, p := range strings.Split(params, ";") {
			k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
			if ok && strings.EqualFold(strings.TrimSpace(k), "q") {
				if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
					w = f
				}
			}
		}
		q[tag] = w
	}
	return q
}

// Component returns the `header` fingerprint component. Absent headers are
// omitted rather than emitted as empty strings.
func Component(r *http.Request, headerOrder []string) map[string]any {
	order := []string{}
	for _, h := range effectiveOrder(r, headerOrder) {
		order = append(order, strings.ToLower(h))
	}
	c := map[string]any{
		"ja4h":  JA4H(r, headerOrder),
		"order": order,
	}
	for key, h := range map[string]string{
		"userAgent": "User-Agent", "accept": "Accept", "acceptEncoding": "Accept-Encoding",
	} {
		if v := r.Header.Get(h); v != "" {
			c[key] = v
		}
	}
	if raw := r.Header.Get("Accept-Language"); raw != "" {
		c["acceptLanguage"] = map[string]any{"raw": raw, "q": parseAcceptLanguage(raw)}
	}
	hints := map[string]any{}
	for _, ch := range clientHintHeaders {
		if v := r.Header.Get(ch.header); v != "" {
			hints[ch.key] = v
		}
	}
	if len(hints) > 0 {
		c["clientHints"] = hints
	}
	return c
}
