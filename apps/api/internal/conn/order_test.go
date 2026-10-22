package conn

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"slices"
	"strings"
	"testing"
)

// do sends one request and reports whether it reused a connection.
func do(t *testing.T, c *http.Client, method, url, body string, hdr map[string]string) (summary, bool) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	reused := false
	trace := &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { reused = i.Reused }}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), method, url, rd)
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
	var s summary
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		t.Fatal(err)
	}
	return s, reused
}

func TestH2EachRequestGetsItsOwnOrder(t *testing.T) {
	addr := startServer(t, tlsOptions(t))
	c := newClient(t, true, nil)
	shared := map[string]string{"User-Agent": "nazr-test/1", "Accept-Language": "en"}
	first := map[string]string{"X-First": "1"}
	second := map[string]string{"X-Second": "2", "Content-Type": "text/plain"}
	for k, v := range shared {
		first[k], second[k] = v, v
	}
	s1, _ := do(t, c, http.MethodGet, "https://"+addr+"/", "", first)
	s2, reused := do(t, c, http.MethodPost, "https://"+addr+"/", "body", second)
	if !reused || s2.Proto != "HTTP/2.0" {
		t.Fatalf("second request did not reuse the h2 connection (reused=%v proto=%s)", reused, s2.Proto)
	}
	if !slices.Contains(s1.HeaderOrder, "x-first") || slices.Contains(s1.HeaderOrder, "x-second") {
		t.Fatalf("first order %v", s1.HeaderOrder)
	}
	if !slices.Contains(s2.HeaderOrder, "x-second") || slices.Contains(s2.HeaderOrder, "x-first") {
		t.Fatalf("second order %v", s2.HeaderOrder)
	}
	// user-agent is a dynamic-table reference in the second block.
	if !slices.Contains(s2.HeaderOrder, "user-agent") || !slices.Contains(s2.HeaderOrder, "content-length") {
		t.Fatalf("second order %v", s2.HeaderOrder)
	}
	t.Logf("first %v / second %v; r.Header keys %v", s1.HeaderOrder, s2.HeaderOrder, s2.HeaderKeys)
}

func TestH2PreflightThenPostOnOneConnection(t *testing.T) {
	addr := startServer(t, tlsOptions(t))
	c := newClient(t, true, nil)
	pre, _ := do(t, c, http.MethodOptions, "https://"+addr+"/thumbmark", "", map[string]string{
		"Origin": "https://shop.test", "Access-Control-Request-Method": "POST",
		"Access-Control-Request-Headers": "content-type,x-api-key", "User-Agent": "nazr-test/1",
	})
	post, reused := do(t, c, http.MethodPost, "https://"+addr+"/thumbmark", `{"components":{}}`, map[string]string{
		"Origin": "https://shop.test", "Content-Type": "application/json", "X-Api-Key": "k",
		"User-Agent": "nazr-test/1", "Cookie": "a=1; b=2",
	})
	if !reused {
		t.Fatal("connection not reused")
	}
	if !slices.Contains(pre.HeaderOrder, "access-control-request-method") {
		t.Fatalf("preflight order %v", pre.HeaderOrder)
	}
	want := []string{"accept-encoding", "content-length", "content-type", "cookie", "origin", "user-agent", "x-api-key"} // the transport adds accept-encoding
	got := slices.Clone(post.HeaderOrder)
	slices.Sort(got)
	got = slices.Compact(got) // Go's h2 transport splits Cookie into crumbs
	if !slices.Equal(got, want) {
		t.Fatalf("POST order %v, want the POST's own names %v", post.HeaderOrder, want)
	}
}

func TestH2ExpectContinueAndTrailerStillMatch(t *testing.T) {
	addr := startServer(t, tlsOptions(t))
	c := newClient(t, true, nil)
	s, _ := do(t, c, http.MethodPost, "https://"+addr+"/", "x", map[string]string{
		"Expect": "100-continue", "X-A": "1",
	})
	if !slices.Contains(s.HeaderOrder, "x-a") {
		t.Fatalf("order %v (r.Header %v)", s.HeaderOrder, s.HeaderKeys)
	}
}

// rawExchange writes reqs on one plain TCP connection, one at a time, and
// returns each response's summary.
func rawExchange(t *testing.T, addr string, reqs ...string) []summary {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	br := bufio.NewReader(c)
	var out []summary
	for _, r := range reqs {
		if _, err := io.WriteString(c, r); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		var s summary
		err = json.NewDecoder(resp.Body).Decode(&s)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func TestPlainKeepAliveEachRequestGetsItsOwnOrder(t *testing.T) {
	addr := startServer(t, Options{})
	got := rawExchange(t, addr,
		"OPTIONS /thumbmark HTTP/1.1\r\nHost: x\r\nOrigin: https://a\r\nAccess-Control-Request-Method: POST\r\n\r\n",
		"POST /thumbmark HTTP/1.1\r\nHost: x\r\nX-Api-Key: k\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nOrigin: https://a\r\n\r\nhello",
		"\r\nGET / HTTP/1.1\r\nUser-Agent: z\r\nHost: x\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n",
	)
	want := [][]string{
		{"host", "origin", "access-control-request-method"},
		{"host", "x-api-key", "content-type", "content-length", "origin"},
		{"user-agent", "host", "cookie", "cookie"},
	}
	for i := range want {
		if !slices.Equal(got[i].HeaderOrder, want[i]) {
			t.Fatalf("request %d order %v, want %v", i, got[i].HeaderOrder, want[i])
		}
	}
}

func TestPlainPipelinedRequestsGetTheirOwnOrder(t *testing.T) {
	addr := startServer(t, Options{})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Both heads arrive in one write: the sniffer queues both before the
	// first handler runs, and each request still gets its own entry.
	_, _ = io.WriteString(c, "POST / HTTP/1.1\r\nHost: x\r\nX-One: 1\r\nContent-Length: 3\r\n\r\nabc"+
		"GET / HTTP/1.1\r\nX-Two: 2\r\nHost: x\r\n\r\n")
	br := bufio.NewReader(c)
	for i, want := range [][]string{{"host", "x-one", "content-length"}, {"x-two", "host"}} {
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		var s summary
		_ = json.NewDecoder(resp.Body).Decode(&s)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if !slices.Equal(s.HeaderOrder, want) {
			t.Fatalf("request %d order %v, want %v", i, s.HeaderOrder, want)
		}
	}
}

func TestPlainChunkedBodyStopsSniffing(t *testing.T) {
	addr := startServer(t, Options{})
	got := rawExchange(t, addr,
		"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nX-A: 1\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: x\r\nX-B: 1\r\n\r\n",
	)
	if !slices.Equal(got[0].HeaderOrder, []string{"host", "transfer-encoding", "x-a"}) {
		t.Fatalf("chunked request order %v", got[0].HeaderOrder)
	}
	if got[1].HeaderOrder != nil {
		t.Fatalf("order after a chunked body = %v, want nil (sniffing stops)", got[1].HeaderOrder)
	}
}

func TestOrderForMatching(t *testing.T) {
	h := &Holder{}
	h.PushOrder("POST", []string{"host", "x-a", "content-length"})
	h.PushOrder("GET", []string{"host", "x-b", "cookie", "cookie"})
	r := &http.Request{Method: http.MethodGet, Header: http.Header{"X-B": {"1"}, "Cookie": {"a=1; b=2"}}}
	if got := h.OrderFor(r); !slices.Equal(got, []string{"host", "x-b", "cookie", "cookie"}) {
		t.Fatalf("got %v", got)
	}
	if h.OrderFor(r) != nil {
		t.Fatal("entry not consumed")
	}
	if h.OrderFor(&http.Request{Method: http.MethodGet, Header: http.Header{"X-A": {"1"}}}) != nil {
		t.Fatal("method ignored")
	}
	if h.OrderFor(&http.Request{Method: http.MethodPost, Header: http.Header{"X-A": {"1"}, "X-C": {"1"}}}) != nil {
		t.Fatal("extra request header ignored")
	}
	if h.OrderFor(&http.Request{Method: http.MethodPost, Header: http.Header{"X-A": {"1"}}}) == nil {
		t.Fatal("POST entry did not match")
	}
	for range maxOrders + 5 {
		h.PushOrder("", []string{"x"})
	}
	if len(h.orders) != maxOrders {
		t.Fatalf("queue %d, want cap %d", len(h.orders), maxOrders)
	}
	var nilHolder *Holder
	if nilHolder.OrderFor(r) != nil {
		t.Fatal("nil holder")
	}
}
