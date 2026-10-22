package h2fp

import (
	"bytes"
	"reflect"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type hdr struct{ k, v string }

func encodeHeaders(t *testing.T, hs []hdr) []byte {
	t.Helper()
	var b bytes.Buffer
	enc := hpack.NewEncoder(&b)
	for _, h := range hs {
		if err := enc.WriteField(hpack.HeaderField{Name: h.k, Value: h.v}); err != nil {
			t.Fatal(err)
		}
	}
	return b.Bytes()
}

func writeHeaders(t *testing.T, fr *http2.Framer, hs []hdr) {
	t.Helper()
	err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1, BlockFragment: encodeHeaders(t, hs), EndHeaders: true, EndStream: true,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func chromeBytes(t *testing.T, extra ...hdr) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString(http2.ClientPreface)
	fr := http2.NewFramer(&buf, nil)
	must(t, fr.WriteSettings(
		http2.Setting{ID: 1, Val: 65536}, http2.Setting{ID: 2, Val: 0},
		http2.Setting{ID: 4, Val: 6291456}, http2.Setting{ID: 6, Val: 262144}))
	must(t, fr.WriteWindowUpdate(0, 15663105))
	hs := []hdr{{":method", "GET"}, {":authority", "x.test"}, {":scheme", "https"}, {":path", "/"}}
	writeHeaders(t, fr, append(hs, extra...))
	return buf.Bytes()
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestChromeLikePreface(t *testing.T) {
	p := NewParser(65536)
	if !p.Feed(chromeBytes(t)) {
		t.Fatal("expected done")
	}
	r, ok := p.Result()
	if !ok {
		t.Fatal("no result")
	}
	want := "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	if r.Fingerprint != want {
		t.Fatalf("got %q want %q", r.Fingerprint, want)
	}
}

func TestFirefoxLikePreface(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(http2.ClientPreface)
	fr := http2.NewFramer(&buf, nil)
	must(t, fr.WriteSettings(http2.Setting{ID: 1, Val: 65536}, http2.Setting{ID: 4, Val: 131072}, http2.Setting{ID: 5, Val: 16384}))
	must(t, fr.WriteWindowUpdate(0, 12517377))
	ws := []uint8{200, 100, 0, 0, 0, 240}
	deps := []uint32{0, 0, 0, 7, 3, 0}
	for i, s := range []uint32{3, 5, 7, 9, 11, 13} {
		must(t, fr.WritePriority(s, http2.PriorityParam{StreamDep: deps[i], Weight: ws[i]}))
	}
	writeHeaders(t, fr, []hdr{{":method", "GET"}, {":path", "/"}, {":authority", "x.test"}, {":scheme", "https"}})
	p := NewParser(65536)
	if !p.Feed(buf.Bytes()) {
		t.Fatal("expected done")
	}
	r, ok := p.Result()
	if !ok {
		t.Fatal("no result")
	}
	want := "1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s"
	if r.Fingerprint != want {
		t.Fatalf("got %q want %q", r.Fingerprint, want)
	}
}

func TestFeedInChunks(t *testing.T) {
	data := chromeBytes(t, hdr{"user-agent", "x"})
	whole := NewParser(65536)
	whole.Feed(data)
	rw, _ := whole.Result()

	p := NewParser(65536)
	done := false
	for i := range data {
		if done {
			t.Fatal("done before final byte")
		}
		done = p.Feed(data[i : i+1])
	}
	if !done {
		t.Fatal("not done")
	}
	r, ok := p.Result()
	if !ok || !reflect.DeepEqual(r, rw) {
		t.Fatalf("chunked %+v != whole %+v", r, rw)
	}
	if r.Fingerprint != "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p" {
		t.Fatalf("got %q", r.Fingerprint)
	}
}

func TestLimitStopsParsing(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(http2.ClientPreface)
	fr := http2.NewFramer(&buf, nil)
	// A 100-byte unknown frame ahead of SETTINGS pushes SETTINGS past the limit.
	must(t, fr.WriteRawFrame(0xfa, 0, 0, bytes.Repeat([]byte{1}, 100)))
	must(t, fr.WriteSettings(http2.Setting{ID: 1, Val: 1}))
	p := NewParser(64)
	if !p.Feed(buf.Bytes()) {
		t.Fatal("expected done")
	}
	if _, ok := p.Result(); ok {
		t.Fatal("expected no result")
	}
	// Further input is ignored.
	if !p.Feed([]byte{1}) {
		t.Fatal("still done")
	}
}

func TestHeaderOrderCaptured(t *testing.T) {
	p := NewParser(65536)
	p.Feed(chromeBytes(t, hdr{"user-agent", "x"}, hdr{"accept", "*/*"}))
	r, ok := p.Result()
	if !ok {
		t.Fatal("no result")
	}
	if !reflect.DeepEqual(r.HeaderOrder, []string{"user-agent", "accept"}) {
		t.Fatalf("got %v", r.HeaderOrder)
	}
}

func TestContinuationAndComponent(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(http2.ClientPreface)
	fr := http2.NewFramer(&buf, nil)
	must(t, fr.WriteSettings(http2.Setting{ID: 1, Val: 65536}))
	blk := encodeHeaders(t, []hdr{{":method", "GET"}, {":path", "/"}, {"accept", "*/*"}})
	must(t, fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: blk[:3]}))
	must(t, fr.WriteContinuation(1, true, blk[3:]))
	p := NewParser(65536)
	if !p.Feed(buf.Bytes()) {
		t.Fatal("expected done")
	}
	r, _ := p.Result()
	c := r.Component()
	if c["fingerprint"] != "1:65536|0|0|m,p" || c["window_update"] != uint32(0) {
		t.Fatalf("%v", c)
	}
	if c["settings"].(map[string]any)["1"] != uint32(65536) {
		t.Fatalf("%v", c["settings"])
	}
	if pr := c["priorities"].([]string); pr == nil || len(pr) != 0 {
		t.Fatalf("%#v", c["priorities"])
	}
	if c["pseudo_header_order"] != "m,p" {
		t.Fatalf("%v", c)
	}
}

func TestBadPrefaceStops(t *testing.T) {
	p := NewParser(65536)
	if !p.Feed([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")) {
		t.Fatal("expected done")
	}
	if _, ok := p.Result(); ok {
		t.Fatal("unexpected result")
	}
}
