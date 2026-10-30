package auth

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// OriginAllowed reports whether origin is permitted by allowed. An empty list
// allows everything; otherwise an empty or "null" origin never matches. Entries
// are compared by scheme, host and port, case-insensitively. An entry
// "https://*.example.com" matches any subdomain depth but not the apex, and a
// literal "*" matches any (non-empty, non-null) origin.
func OriginAllowed(origin string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	origin = strings.TrimSpace(origin)
	if origin == "" || strings.EqualFold(origin, "null") {
		return false
	}
	ou, err := url.Parse(origin)
	if err != nil || ou.Scheme == "" || ou.Hostname() == "" ||
		ou.User != nil || (ou.Path != "" && ou.Path != "/") || ou.RawQuery != "" {
		return false
	}
	oScheme, oHost, oPort := strings.ToLower(ou.Scheme), strings.ToLower(ou.Hostname()), ou.Port()
	for _, entry := range allowed {
		entry = strings.TrimSpace(entry)
		if entry == "*" {
			return true
		}
		eu, err := url.Parse(entry)
		if err != nil || eu.Scheme == "" || eu.Hostname() == "" {
			continue
		}
		if strings.ToLower(eu.Scheme) != oScheme || eu.Port() != oPort {
			continue
		}
		eHost := strings.ToLower(eu.Hostname())
		if suffix, ok := strings.CutPrefix(eHost, "*."); ok {
			if strings.HasSuffix(oHost, "."+suffix) && len(oHost) > len(suffix)+1 {
				return true
			}
			continue
		}
		if eHost == oHost {
			return true
		}
	}
	return false
}

// ValidateOrigins checks allowed_origins entries for a new key. Each entry
// (blank ones are ignored) must be "*" or an origin with a scheme and host,
// such as "https://shop.example" or "http://localhost:3000"; the host may
// start with a "*." wildcard label. Paths, queries, fragments and userinfo
// are rejected. The error names the first bad entry.
func ValidateOrigins(origins []string) error {
	for _, raw := range origins {
		o := strings.TrimSpace(raw)
		if o == "" || o == "*" {
			continue
		}
		if !validOrigin(o) {
			return fmt.Errorf("invalid origin %q: want \"*\" or scheme://host[:port], optionally with a \"*.\" host prefix", raw)
		}
	}
	return nil
}

func validOrigin(o string) bool {
	u, err := url.Parse(o)
	if err != nil || u.Scheme == "" || u.Opaque != "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(o, "#") || strings.HasSuffix(o, "?") {
		return false
	}
	host := u.Hostname()
	if rest, ok := strings.CutPrefix(host, "*."); ok {
		host = rest
	}
	// ';', ',' and "'" would split or quote a CSP frame-ancestors source list.
	if host == "" || strings.ContainsAny(host, "*;,'") || strings.HasPrefix(host, ".") {
		return false
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return false
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return false
	}
	return true
}
