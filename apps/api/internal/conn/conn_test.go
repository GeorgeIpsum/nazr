package conn

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

type summary struct {
	TLS         bool     `json:"tls"`
	JA4         string   `json:"ja4"`
	TLSError    string   `json:"tls_error"`
	H2          *h2sum   `json:"h2"`
	HeaderOrder []string `json:"header_order"`
	RemoteAddr  string   `json:"remote_addr"`
	ReqTLS      bool     `json:"req_tls"`
	Proto       string   `json:"proto"`
}

type h2sum struct {
	Fingerprint       string   `json:"fingerprint"`
	PseudoHeaderOrder []string `json:"pseudo_header_order"`
}

func summaryHandler(w http.ResponseWriter, r *http.Request) {
	h := FromContext(r.Context())
	if h == nil {
		http.Error(w, "no holder", http.StatusInternalServerError)
		return
	}
	v := h.Snapshot()
	s := summary{
		TLS:         v.TLS != nil,
		HeaderOrder: v.HeaderOrder,
		RemoteAddr:  v.RemoteAddr.String(),
		ReqTLS:      r.TLS != nil,
		Proto:       r.Proto,
	}
	if v.TLS != nil {
		s.JA4 = v.TLS.JA4
	}
	if v.TLSError != nil {
		s.TLSError = v.TLSError.Error()
	}
	if v.H2 != nil {
		s.H2 = &h2sum{Fingerprint: v.H2.Fingerprint, PseudoHeaderOrder: v.H2.PseudoHeaderOrder}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s)
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "nazr-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startServer runs a real http.Server on 127.0.0.1:0 behind Listen and
// returns its address.
func startServer(t *testing.T, o Options) string {
	t.Helper()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:     http.HandlerFunc(summaryHandler),
		ConnContext: ConnContext,
		ErrorLog:    log.New(io.Discard, "", 0),
	}
	if err := ConfigureServer(srv, 0); err != nil {
		t.Fatal(err)
	}
	ln := Listen(tcp, o)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ln)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		<-done
	})
	return tcp.Addr().String()
}

func tlsOptions(t *testing.T) Options {
	return Options{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}},
		CaptureH2: true,
	}
}

func newClient(t *testing.T, h2 bool, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Client {
	t.Helper()
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: h2,
		DialContext:       dial,
	}
	if !h2 {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

func get(t *testing.T, c *http.Client, url string, hdr map[string]string) summary {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var s summary
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestH2ClientGetsTLSAndH2(t *testing.T) {
	addr := startServer(t, tlsOptions(t))
	s := get(t, newClient(t, true, nil), "https://"+addr+"/", nil)
	if s.Proto != "HTTP/2.0" {
		t.Fatalf("proto = %q, want HTTP/2.0", s.Proto)
	}
	if !s.ReqTLS {
		t.Fatal("r.TLS is nil")
	}
	if s.JA4 == "" || !strings.HasPrefix(s.JA4, "t13") {
		t.Fatalf("ja4 = %q", s.JA4)
	}
	if s.H2 == nil {
		t.Fatal("h2 missing")
	}
	t.Logf("h2 = %+v, header order = %v", *s.H2, s.HeaderOrder)
	// Go's transport sends SETTINGS, so the S field is non-empty id:value pairs.
	if !regexp.MustCompile(`^\d+:\d+(;\d+:\d+)*\|`).MatchString(s.H2.Fingerprint) {
		t.Fatalf("h2 fingerprint = %q", s.H2.Fingerprint)
	}
	if len(s.H2.PseudoHeaderOrder) == 0 {
		t.Fatal("pseudo_header_order empty")
	}
	if len(s.HeaderOrder) == 0 {
		t.Fatal("header order not taken from h2 HEADERS")
	}
}

func TestH1ClientGetsHeaderOrder(t *testing.T) {
	// Plain mode: Go's client sorts headers, so write the request by hand
	// to control the wire order.
	addr := startServer(t, Options{})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\nX-B: 1\r\nX-A: 2\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var s summary
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		t.Fatal(err)
	}
	want := []string{"host", "x-b", "x-a", "connection"}
	if !slices.Equal(s.HeaderOrder, want) {
		t.Fatalf("header order = %v, want %v", s.HeaderOrder, want)
	}
	if s.H2 != nil {
		t.Fatal("h2 set on HTTP/1.1")
	}
}

func TestTLSHTTP1HasNoHeaderOrder(t *testing.T) {
	addr := startServer(t, tlsOptions(t))
	s := get(t, newClient(t, false, nil), "https://"+addr+"/", map[string]string{"X-B": "1", "X-A": "2"})
	if s.Proto != "HTTP/1.1" {
		t.Fatalf("proto = %q", s.Proto)
	}
	if !s.TLS || !s.ReqTLS || s.JA4 == "" {
		t.Fatalf("tls not captured: %+v", s)
	}
	if s.H2 != nil {
		t.Fatal("h2 set on HTTP/1.1")
	}
	if s.HeaderOrder != nil {
		t.Fatalf("header order = %v, want nil (documented limitation)", s.HeaderOrder)
	}
}

func expectClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	for {
		_, err := c.Read(buf)
		if err == nil {
			continue
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatal("connection not closed within 2s")
		}
		return // EOF or reset
	}
}

func TestPlaintextOnTLSListenerDoesNotPanic(t *testing.T) {
	addr := startServer(t, tlsOptions(t))
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\n\r\n")
	expectClosed(t, c)
	s := get(t, newClient(t, true, nil), "https://"+addr+"/", nil)
	if s.JA4 == "" {
		t.Fatal("server stopped serving TLS")
	}
}

func TestGarbageBytesClosed(t *testing.T) {
	addr := startServer(t, tlsOptions(t))
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	garbage := make([]byte, 20*1024)
	for i := range garbage {
		garbage[i] = 0xff
	}
	_, _ = c.Write(garbage) // may fail with reset once the server closes
	expectClosed(t, c)
	s := get(t, newClient(t, true, nil), "https://"+addr+"/", nil)
	if s.JA4 == "" {
		t.Fatal("server stopped serving TLS")
	}
}

func TestOversizedHelloClosed(t *testing.T) {
	addr := startServer(t, tlsOptions(t))
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Handshake record claiming 0x4000 bytes: exceeds the 16 KiB cap.
	_, _ = c.Write([]byte{0x16, 0x03, 0x01, 0x40, 0x00})
	expectClosed(t, c)
}

func proxyV2Header(src, dst netip.AddrPort) []byte {
	b := []byte("\r\n\r\n\x00\r\nQUIT\n")
	b = append(b, 0x21, 0x11)
	b = binary.BigEndian.AppendUint16(b, 12)
	s4, d4 := src.Addr().As4(), dst.Addr().As4()
	b = append(b, s4[:]...)
	b = append(b, d4[:]...)
	b = binary.BigEndian.AppendUint16(b, src.Port())
	b = binary.BigEndian.AppendUint16(b, dst.Port())
	return b
}

func TestProxyProtocolSetsRemoteAddr(t *testing.T) {
	o := tlsOptions(t)
	o.ProxyProtocol = true
	addr := startServer(t, o)
	src := netip.MustParseAddrPort("203.0.113.9:4444")
	dial := func(ctx context.Context, network, a string) (net.Conn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, network, a)
		if err != nil {
			return nil, err
		}
		if _, err := c.Write(proxyV2Header(src, netip.MustParseAddrPort("192.0.2.1:443"))); err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	}
	s := get(t, newClient(t, true, dial), "https://"+addr+"/", nil)
	if s.RemoteAddr != src.String() {
		t.Fatalf("remote addr = %q, want %q", s.RemoteAddr, src)
	}
	if s.JA4 == "" || s.H2 == nil {
		t.Fatalf("fingerprints lost behind PROXY header: %+v", s)
	}
}

func TestProxyProtocolMissingHeaderClosed(t *testing.T) {
	o := tlsOptions(t)
	o.ProxyProtocol = true
	addr := startServer(t, o)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	expectClosed(t, c)
}

func TestNoTLSMode(t *testing.T) {
	addr := startServer(t, Options{})
	s := get(t, newClient(t, false, nil), "http://"+addr+"/", map[string]string{"X-A": "1"})
	if s.TLS || s.ReqTLS || s.JA4 != "" {
		t.Fatalf("tls present in plain mode: %+v", s)
	}
	if !slices.Contains(s.HeaderOrder, "x-a") || !slices.Contains(s.HeaderOrder, "user-agent") {
		t.Fatalf("header order = %v", s.HeaderOrder)
	}
	ap, err := netip.ParseAddrPort(s.RemoteAddr)
	if err != nil || ap.Addr() != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("remote addr = %q", s.RemoteAddr)
	}
}

func TestFromContextAbsent(t *testing.T) {
	if FromContext(context.Background()) != nil {
		t.Fatal("expected nil holder")
	}
}

func TestParseHeaderOrder(t *testing.T) {
	head := "GET / HTTP/1.1\r\nHost: a\r\nX-Folded: a\r\n b\r\nUser-Agent: z\r\n\r\n"
	got := parseHeaderOrder([]byte(head))
	want := []string{"host", "x-folded", "user-agent"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
