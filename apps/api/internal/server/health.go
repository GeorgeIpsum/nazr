package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// readyTTL is how long a computed /readyz answer is reused, so probes and
// scrapers cannot turn it into a store-ping amplifier.
const readyTTL = time.Second

// readyPingTimeout bounds the store ping, which ignores the request's own
// cancellation.
const readyPingTimeout = 2 * time.Second

type readyCache struct {
	mu      sync.Mutex
	expires time.Time
	status  int
	body    []byte
}

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
// The answer is computed at most once per second and reused in between.
func (s *server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	s.ready.mu.Lock()
	defer s.ready.mu.Unlock()
	if now := s.Now(); s.ready.body == nil || !now.Before(s.ready.expires) {
		// The answer is cached for every prober, so a prober that
		// disconnects must not cancel the ping and cache its 503.
		s.ready.status, s.ready.body = s.computeReadyz(context.WithoutCancel(r.Context()))
		s.ready.expires = now.Add(readyTTL)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(s.ready.status)
	_, _ = w.Write(s.ready.body)
}

func (s *server) computeReadyz(ctx context.Context) (int, []byte) {
	resp := readyzResponse{Version: s.Version, TLSMode: s.Cfg.TLSMode, Store: "ok",
		Sources: map[string]sourceStatusJSON{}}
	if s.Intel != nil {
		for name, st := range s.Intel.Status() {
			j := sourceStatusJSON{Loaded: st.Loaded, Rows: st.Rows, FetchedAt: timePtr(st.FetchedAt),
				LastModified: timePtr(st.LastModified), LastError: publicError(st.LastError, s.Cfg.DataDir)}
			if st.Interval > 0 {
				j.Interval = st.Interval.String()
			}
			resp.Sources[name] = j
		}
	}
	status := http.StatusOK
	pctx, cancel := context.WithTimeout(ctx, readyPingTimeout)
	defer cancel()
	if err := s.Store.Ping(pctx); err != nil {
		s.Logger.Warn("server: readiness store ping failed", "err", err)
		resp.Store = "error"
		status = http.StatusServiceUnavailable
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(resp)
	return status, buf.Bytes()
}

// publicError trims a source error for the unauthenticated /readyz: first
// line only, with the data directory replaced by "<data>".
func publicError(msg, dataDir string) string {
	msg, _, _ = strings.Cut(msg, "\n")
	msg = strings.TrimSpace(msg)
	if dataDir != "" {
		if d := filepath.Clean(dataDir); d != "/" && d != "." {
			msg = strings.ReplaceAll(msg, d, "<data>")
		}
	}
	return msg
}

func (s *server) handleRoot(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("nazr " + s.Version + "\n"))
}
