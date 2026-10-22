package auth

import (
	"net/url"
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
	if err != nil || ou.Scheme == "" || ou.Hostname() == "" {
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
