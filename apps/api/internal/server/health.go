package server

import (
	"context"
	"net/http"
	"time"
)

type sourceStatusJSON struct {
	Loaded       bool       `json:"loaded"`
	Rows         int        `json:"rows"`
	FetchedAt    *time.Time `json:"fetched_at"`
	LastModified *time.Time `json:"last_modified,omitempty"`
	LastError    string     `json:"last_error,omitempty"`
	Interval     string     `json:"interval,omitempty"`
}

type readyzResponse struct {
	Version string                      `json:"version"`
	TLSMode string                      `json:"tls_mode"`
	Store   string                      `json:"store"`
	Sources map[string]sourceStatusJSON `json:"sources"`
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func (s *server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok"))
}

// handleReadyz is 200 whenever the store pings, whatever the state of the
// intelligence sources (which are reported, not gating), and 503 otherwise.
func (s *server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	resp := readyzResponse{Version: s.Version, TLSMode: s.Cfg.TLSMode, Store: "ok",
		Sources: map[string]sourceStatusJSON{}}
	if s.Intel != nil {
		for name, st := range s.Intel.Status() {
			j := sourceStatusJSON{Loaded: st.Loaded, Rows: st.Rows, FetchedAt: timePtr(st.FetchedAt),
				LastModified: timePtr(st.LastModified), LastError: st.LastError}
			if st.Interval > 0 {
				j.Interval = st.Interval.String()
			}
			resp.Sources[name] = j
		}
	}
	status := http.StatusOK
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.Store.Ping(ctx); err != nil {
		s.Logger.Warn("server: readiness store ping failed", "err", err)
		resp.Store = "error"
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, resp)
}

func (s *server) handleRoot(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("nazr " + s.Version + "\n"))
}
