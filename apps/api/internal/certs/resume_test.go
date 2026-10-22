package certs

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"reflect"
	"slices"
	"testing"
	"time"

	"nazr/api/internal/config"
	"nazr/api/internal/conn"
)

// pskExtension is pre_shared_key, which a resuming ClientHello carries.
const pskExtension = 0x0029

type helloSummary struct {
	Component map[string]any `json:"component"`
	PSK       bool           `json:"psk"`
	Resumed   bool           `json:"resumed"`
}

// TestNoSessionResumption: a returning client with a session cache must send
// the same ClientHello as on its first visit. Resumption would add
// pre_shared_key (changing the JA4 extension count and hash) and so the
// thumbmark, so Setup disables session tickets.
func TestNoSessionResumption(t *testing.T) {
	cp, kp := genPair(t, "resume")
	tc, _, err := Setup(context.Background(), config.Config{TLSMode: "terminate",
		TLSCertPEM: string(cp), TLSKeyPEM: string(kp)}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		ConnContext: conn.ConnContext,
		ErrorLog:    log.New(io.Discard, "", 0),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			v := conn.FromContext(r.Context()).Snapshot()
			if v.TLS == nil || v.TLS.Hello == nil {
				http.Error(w, "no hello", http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(helloSummary{
				Component: v.TLS.Component(),
				PSK:       slices.Contains(v.TLS.Hello.Extensions, pskExtension),
				Resumed:   r.TLS.DidResume,
			})
		}),
	}
	ln := conn.Listen(tcp, conn.Options{TLSConfig: tc})
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close(); <-done })

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ClientSessionCache: tls.NewLRUClientSessionCache(8)},
		// one connection per request, as a browser returning later would open
		DisableKeepAlives: true,
		TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	fetch := func() helloSummary {
		t.Helper()
		resp, err := c.Get("https://" + tcp.Addr().String() + "/")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var s helloSummary
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status %d: %s", resp.StatusCode, b)
		}
		if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	first, second := fetch(), fetch()
	if second.PSK || second.Resumed {
		t.Fatalf("second connection resumed (psk=%v resumed=%v)", second.PSK, second.Resumed)
	}
	if !reflect.DeepEqual(first.Component, second.Component) {
		t.Fatalf("tls component changed on the returning connection:\n%v\n%v", first.Component, second.Component)
	}
}

func TestSetupDisablesSessionTickets(t *testing.T) {
	cp, kp := genPair(t, "t")
	dir := t.TempDir()
	cfgs := []config.Config{
		{TLSMode: "terminate", TLSCertPEM: string(cp), TLSKeyPEM: string(kp)},
		{TLSMode: "terminate", ACMEDomains: []string{"example.com"}, ACMEDir: dir},
	}
	for _, cfg := range cfgs {
		tc, _, err := Setup(context.Background(), cfg, slog.Default())
		if err != nil {
			t.Fatal(err)
		}
		if !tc.SessionTicketsDisabled {
			t.Fatalf("session tickets enabled (acme=%v)", len(cfg.ACMEDomains) > 0)
		}
	}
}
