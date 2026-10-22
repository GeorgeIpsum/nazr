package h2fp

import (
	"bytes"
	"reflect"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// h2conn writes a client connection with one persistent HPACK encoder, as a
// real client does, so later blocks reference the dynamic table.
type h2conn struct {
	t   *testing.T
	buf bytes.Buffer
	fr  *http2.Framer
	hb  bytes.Buffer
	enc *hpack.Encoder
}

func newH2Conn(t *testing.T) *h2conn {
	c := &h2conn{t: t}
	c.buf.WriteString(http2.ClientPreface)
	c.fr = http2.NewFramer(&c.buf, nil)
	c.enc = hpack.NewEncoder(&c.hb)
	must(t, c.fr.WriteSettings(http2.Setting{ID: 1, Val: 65536}, http2.Setting{ID: 4, Val: 6291456}))
	must(t, c.fr.WriteWindowUpdate(0, 15663105))
	return c
}

func (c *h2conn) block(hs []hdr) []byte {
	c.hb.Reset()
	for _, h := range hs {
		must(c.t, c.enc.WriteField(hpack.HeaderField{Name: h.k, Value: h.v}))
	}
	return append([]byte(nil), c.hb.Bytes()...)
}

func (c *h2conn) headers(stream uint32, hs []hdr, endStream bool) {
	must(c.t, c.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: stream, BlockFragment: c.block(hs), EndHeaders: true, EndStream: endStream,
	}))
}

func req(method string, extra ...hdr) []hdr {
	hs := []hdr{{":method", method}, {":authority", "x.test"}, {":scheme", "https"}, {":path", "/thumbmark"}}
	return append(hs, extra...)
}

func names(bs []HeaderBlock) [][]string {
	out := [][]string{}
	for _, b := range bs {
		out = append(out, b.Names)
	}
	return out
}

func TestEveryHeaderBlockDecodedWithDynamicTable(t *testing.T) {
	c := newH2Conn(t)
	first := req("OPTIONS", hdr{"access-control-request-method", "POST"}, hdr{"origin", "https://a.test"}, hdr{"user-agent", "UA/1"})
	c.headers(1, first, true)
	// The second block repeats origin and user-agent: the encoder emits them
	// as dynamic-table indices, which only a persistent decoder resolves.
	second := req("POST", hdr{"content-type", "text/plain"}, hdr{"origin", "https://a.test"}, hdr{"user-agent", "UA/1"}, hdr{"x-api-key", "k"})
	c.headers(3, second, false)
	must(t, c.fr.WriteData(3, true, bytes.Repeat([]byte("d"), 5000)))

	p := NewParser(65536)
	if !p.Feed(c.buf.Bytes()) {
		t.Fatal("fingerprint phase not done")
	}
	if p.Stopped() {
		t.Fatal("parser stopped")
	}
	got := p.TakeBlocks()
	want := [][]string{
		{"access-control-request-method", "origin", "user-agent"},
		{"content-type", "origin", "user-agent", "x-api-key"},
	}
	if !reflect.DeepEqual(names(got), want) {
		t.Fatalf("blocks %v, want %v", names(got), want)
	}
	if got[0].StreamID != 1 || got[1].StreamID != 3 || got[0].Method != "OPTIONS" || got[1].Method != "POST" {
		t.Fatalf("stream/method %+v", got)
	}
	if !reflect.DeepEqual(got[1].Pseudo, []string{":method", ":authority", ":scheme", ":path"}) {
		t.Fatalf("pseudo %v", got[1].Pseudo)
	}
	r, _ := p.Result()
	if !reflect.DeepEqual(r.HeaderOrder, want[0]) {
		t.Fatalf("fingerprint header order %v, want first block", r.HeaderOrder)
	}
	if p.TakeBlocks() != nil {
		t.Fatal("queue not cleared")
	}
}

func TestSecondBlockUsesDynamicTableIndex(t *testing.T) {
	// Pin that the encoder really references the dynamic table, so the test
	// above exercises a persistent decoder: a fresh decoder must fail.
	c := newH2Conn(t)
	c.block(req("GET", hdr{"x-custom", "v"}))
	second := c.block(req("GET", hdr{"x-custom", "v"}))
	fresh := hpack.NewDecoder(4096, nil)
	if _, err := fresh.DecodeFull(second); err == nil {
		t.Fatal("second block decodes without the dynamic table: test is not exercising it")
	}
}

func TestBlocksAcrossChunksAndContinuation(t *testing.T) {
	c := newH2Conn(t)
	c.headers(1, req("GET", hdr{"accept", "*/*"}), true)
	blk := c.block(req("GET", hdr{"accept", "*/*"}, hdr{"x-two", "2"}))
	must(t, c.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: blk[:2], EndStream: true}))
	must(t, c.fr.WriteContinuation(3, true, blk[2:]))
	data := c.buf.Bytes()
	p := NewParser(65536)
	var got []HeaderBlock
	for i := range data {
		p.Feed(data[i : i+1])
		got = append(got, p.TakeBlocks()...)
	}
	want := [][]string{{"accept"}, {"accept", "x-two"}}
	if !reflect.DeepEqual(names(got), want) {
		t.Fatalf("blocks %v, want %v", names(got), want)
	}
}

func TestTrailersNotReported(t *testing.T) {
	c := newH2Conn(t)
	c.headers(1, req("POST", hdr{"te", "trailers"}), false)
	c.headers(1, []hdr{{"x-checksum", "abc"}}, true)
	p := NewParser(65536)
	p.Feed(c.buf.Bytes())
	if got := names(p.TakeBlocks()); !reflect.DeepEqual(got, [][]string{{"te"}}) {
		t.Fatalf("blocks %v", got)
	}
}

func TestBlockQueueBounded(t *testing.T) {
	c := newH2Conn(t)
	for i := range MaxBlocks + 10 {
		c.headers(uint32(2*i+1), req("GET", hdr{"x-n", string(rune('a' + i%26))}), true)
	}
	p := NewParser(65536)
	p.Feed(c.buf.Bytes())
	got := p.TakeBlocks()
	if len(got) != MaxBlocks {
		t.Fatalf("queued %d, want %d", len(got), MaxBlocks)
	}
	if got[0].StreamID != 21 { // the 10 oldest were dropped
		t.Fatalf("oldest stream %d", got[0].StreamID)
	}
}

func TestLimitOnlyBoundsFingerprintPhase(t *testing.T) {
	c := newH2Conn(t)
	c.headers(1, req("GET"), false)
	must(t, c.fr.WriteData(1, true, bytes.Repeat([]byte("d"), 20000)))
	c.headers(3, req("GET", hdr{"x-late", "1"}), true)
	p := NewParser(256)
	if !p.Feed(c.buf.Bytes()) {
		t.Fatal("not done")
	}
	got := names(p.TakeBlocks())
	if !reflect.DeepEqual(got, [][]string{{}, {"x-late"}}) {
		t.Fatalf("blocks %v", got)
	}
	if len(p.buf) > 64 {
		t.Fatalf("DATA payload buffered: %d bytes", len(p.buf))
	}
}

func TestHPACKErrorStopsWithoutPanic(t *testing.T) {
	c := newH2Conn(t)
	c.headers(1, req("GET"), true)
	// Index 200 is outside the static and (empty-ish) dynamic tables.
	must(t, c.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: []byte{0x80 | 0x7f, 0x49}, EndHeaders: true}))
	c.headers(5, req("GET"), true)
	p := NewParser(65536)
	p.Feed(c.buf.Bytes())
	if !p.Stopped() {
		t.Fatal("expected stopped")
	}
	if p.TakeBlocks() != nil {
		t.Fatal("blocks reported after an HPACK error")
	}
	if _, ok := p.Result(); !ok {
		t.Fatal("fingerprint lost")
	}
	if !p.Feed([]byte{1, 2, 3}) {
		t.Fatal("feed after stop")
	}
}

func TestTableSizeHonoured(t *testing.T) {
	// The client's encoder may only use the table size the server
	// advertised; a size update above it is a decoding error.
	c := newH2Conn(t)
	c.enc.SetMaxDynamicTableSizeLimit(8192)
	c.enc.SetMaxDynamicTableSize(8192)
	c.headers(1, req("GET"), true)
	small := NewParserSize(65536, 4096)
	small.Feed(c.buf.Bytes())
	if !small.Stopped() {
		t.Fatal("size update over the advertised table accepted")
	}
	big := NewParserSize(65536, 8192)
	big.Feed(c.buf.Bytes())
	if big.Stopped() || len(big.TakeBlocks()) != 1 {
		t.Fatal("block not decoded with an 8192 table")
	}
}
