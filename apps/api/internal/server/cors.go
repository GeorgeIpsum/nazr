package server

import (
	"net/http"
	"slices"
	"strings"

	"nazr/api/internal/auth"
)

// globalWildcard reports whether NAZR_CORS_ORIGINS allows every origin
// ("*", or an empty list).
func (s *server) globalWildcard() bool {
	return len(s.Cfg.CORSOrigins) == 0 || slices.Contains(s.Cfg.CORSOrigins, "*")
}

// setGlobalAllowOrigin applies the global NAZR_CORS_ORIGINS policy: "*" when
// the list is a wildcard, otherwise the request Origin when it is listed.
func (s *server) setGlobalAllowOrigin(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	if s.globalWildcard() {
		h.Set("Access-Control-Allow-Origin", "*")
		return
	}
	h.Add("Vary", "Origin")
	if o := r.Header.Get("Origin"); o != "" && auth.OriginAllowed(o, s.Cfg.CORSOrigins) {
		h.Set("Access-Control-Allow-Origin", o)
	}
}

// preflight answers OPTIONS from the global list; it cannot see the key.
func (s *server) preflight(w http.ResponseWriter, r *http.Request) {
	s.setGlobalAllowOrigin(w, r)
	h := w.Header()
	h.Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "content-type, x-api-key, authorization")
	h.Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusNoContent)
}

// globalCORS sets the global Allow-Origin on real requests, so error
// responses produced before authentication (403, 413, 429) stay readable by
// the browser.
func (s *server) globalCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.setGlobalAllowOrigin(w, r)
		next.ServeHTTP(w, r)
	})
}

// keyCORS runs after auth.Middleware, which has already rejected origins the
// key does not allow. A key with an origin list echoes the request Origin.
func (s *server) keyCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k := auth.KeyFromContext(r.Context())
		if o := r.Header.Get("Origin"); k != nil && len(k.AllowedOrigins) > 0 && o != "" {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", o)
			if !slices.ContainsFunc(h.Values("Vary"), func(v string) bool { return strings.EqualFold(v, "Origin") }) {
				h.Add("Vary", "Origin")
			}
		}
		next.ServeHTTP(w, r)
	})
}
