// Package h2fp passively fingerprints an HTTP/2 client from the first bytes it
// sends after the TLS handshake (Akamai format), and recovers the header name
// order of every request header block on the connection.
package h2fp

import (
	"bytes"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Setting is one SETTINGS entry, in wire order.
type Setting struct {
	ID    uint16
	Value uint32
}

// Priority is one PRIORITY frame. Weight is the wire value (0..255).
type Priority struct {
	StreamID  uint32
	Exclusive bool
	DependsOn uint32
	Weight    uint8
}

// Result is what the parser recovered for the connection fingerprint. The
// header orders are those of the connection's first HEADERS block.
type Result struct {
	Settings          []Setting
	WindowUpdate      uint32
	Priorities        []Priority
	PseudoHeaderOrder []string
	HeaderOrder       []string
	Fingerprint       string
}

// HeaderBlock is the decoded name order of one request header block
// (HEADERS plus any CONTINUATION frames). Pseudo and Names are lowercase and
// in wire order; Method is the :method value.
type HeaderBlock struct {
	StreamID uint32
	Method   string
	Pseudo   []string
	Names    []string
}

const (
	// maxFrame bounds the payload buffered for a single frame and the size of
	// one reassembled header block.
	maxFrame = 1 << 20
	// MaxBlocks caps the header blocks queued between TakeBlocks calls.
	MaxBlocks = 64
	// maxNames caps the field names recorded per header block; a block with
	// more is decoded (to keep the HPACK table in sync) but not reported.
	maxNames = 256
	// DefaultHeaderTableSize is the HPACK dynamic table size a server
	// advertises unless configured otherwise (RFC 9113 section 6.5.2, and
	// x/net/http2's default MaxDecoderHeaderTableSize).
	DefaultHeaderTableSize = 4096
)

// Parser is an incremental HTTP/2 client-side parser. It has two phases:
//
//   - the fingerprint phase ends at the first HEADERS block, when the byte
//     limit is reached, or on a parse error; Feed then reports true and
//     Result is final.
//   - header decoding continues for the connection's lifetime: every request
//     header block is HPACK-decoded with one persistent decoder (the dynamic
//     table spans the connection) and queued for TakeBlocks. Frames other
//     than HEADERS/CONTINUATION are skipped without buffering their payload.
//
// Any framing or HPACK error stops the parser for good (Stopped). The parser
// never panics on malformed input and never affects the connection.
type Parser struct {
	limit int
	total int

	buf  []byte // preface, frame header, or interesting frame being read
	want int    // full frame size being read into buf (0 = reading header)
	skip int    // payload bytes of an uninteresting frame still to discard

	fpDone  bool
	stopped bool

	prefaceOK  bool
	gotSetting bool
	gotWU      bool
	gotHeaders bool
	res        Result

	dec         *hpack.Decoder
	inHeaders   bool
	block       []byte
	blockStream uint32
	cur         HeaderBlock
	curOverflow bool
	out         []HeaderBlock
}

// NewParser returns a parser whose fingerprint phase gives up after limit
// bytes, decoding header blocks with the default 4096-byte HPACK table.
func NewParser(limit int) *Parser { return NewParserSize(limit, DefaultHeaderTableSize) }

// NewParserSize is NewParser with the HPACK dynamic table size the server
// advertised in its SETTINGS_HEADER_TABLE_SIZE. That setting (the decoder's,
// i.e. the server's) bounds the client's encoder; the client's own
// SETTINGS_HEADER_TABLE_SIZE governs the opposite direction and is ignored.
// Table size updates inside header blocks are applied by the decoder.
func NewParserSize(limit int, headerTableSize uint32) *Parser {
	p := &Parser{limit: limit}
	p.dec = hpack.NewDecoder(headerTableSize, p.emit)
	p.dec.SetMaxStringLength(maxFrame)
	return p
}

// Feed consumes bytes and reports whether the fingerprint phase has finished.
// Keep feeding afterwards to decode later header blocks, until Stopped.
func (p *Parser) Feed(b []byte) bool {
	if p.stopped {
		return true
	}
	if !p.fpDone && p.limit > 0 && p.total+len(b) >= p.limit {
		k := p.limit - p.total
		p.total = p.limit
		p.consume(b[:k])
		p.finishFP()
		b = b[k:]
	} else if !p.fpDone {
		p.total += len(b)
	}
	p.consume(b)
	return p.fpDone
}

// Stopped reports that the parser will produce nothing more (bad preface,
// framing or HPACK error); callers can stop feeding it.
func (p *Parser) Stopped() bool { return p.stopped }

// TakeBlocks returns the header blocks decoded since the last call (oldest
// first, at most MaxBlocks) and clears the queue.
func (p *Parser) TakeBlocks() []HeaderBlock {
	out := p.out
	p.out = nil
	return out
}

func (p *Parser) finishFP() { p.fpDone = true }

func (p *Parser) stop() {
	p.stopped = true
	p.fpDone = true
	p.buf, p.block, p.out = nil, nil, nil
}

func (p *Parser) consume(b []byte) {
	for len(b) > 0 && !p.stopped {
		switch {
		case p.skip > 0:
			n := min(p.skip, len(b))
			p.skip -= n
			b = b[n:]
			continue
		case !p.prefaceOK:
			n := min(len(http2.ClientPreface)-len(p.buf), len(b))
			p.buf = append(p.buf, b[:n]...)
			b = b[n:]
			if !strings.HasPrefix(http2.ClientPreface, string(p.buf)) {
				p.stop()
				return
			}
			if len(p.buf) == len(http2.ClientPreface) {
				p.prefaceOK = true
				p.buf = p.buf[:0]
			}
			continue
		case p.want == 0:
			n := min(9-len(p.buf), len(b))
			p.buf = append(p.buf, b[:n]...)
			b = b[n:]
			if len(p.buf) < 9 {
				continue
			}
			length := int(p.buf[0])<<16 | int(p.buf[1])<<8 | int(p.buf[2])
			if length > maxFrame {
				p.stop()
				return
			}
			if !p.interesting(http2.FrameType(p.buf[3])) {
				p.skip = length
				p.buf = p.buf[:0]
				continue
			}
			p.want = 9 + length // a zero-length frame completes below
		default:
			n := min(p.want-len(p.buf), len(b))
			p.buf = append(p.buf, b[:n]...)
			b = b[n:]
		}
		if p.want > 0 && len(p.buf) == p.want {
			p.handle(p.buf)
			p.want = 0
			if cap(p.buf) > 64<<10 {
				p.buf = nil
			} else {
				p.buf = p.buf[:0]
			}
		}
	}
}

// interesting reports whether a frame of type t must be buffered and parsed.
func (p *Parser) interesting(t http2.FrameType) bool {
	if p.inHeaders {
		return true // anything but CONTINUATION is a protocol error: handle stops
	}
	switch t {
	case http2.FrameHeaders, http2.FrameContinuation:
		return true
	case http2.FrameSettings, http2.FrameWindowUpdate, http2.FramePriority:
		return !p.fpDone
	}
	return false
}

func (p *Parser) handle(raw []byte) {
	if p.inHeaders {
		// CONTINUATION is handled by hand: a fresh Framer per frame has no
		// preceding HEADERS and would reject it.
		if http2.FrameType(raw[3]) != http2.FrameContinuation {
			p.stop()
			return
		}
		if len(p.block)+len(raw)-9 > maxFrame {
			p.stop() // the HPACK table would desync if the block were dropped
			return
		}
		p.block = append(p.block, raw[9:]...)
		if http2.Flags(raw[4])&http2.FlagContinuationEndHeaders != 0 {
			p.inHeaders = false
			p.decode()
		}
		return
	}
	fr := http2.NewFramer(nil, bytes.NewReader(raw))
	fr.SetMaxReadFrameSize(maxFrame)
	f, err := fr.ReadFrame()
	if err != nil {
		if http2.FrameType(raw[3]) == http2.FrameHeaders {
			p.stop() // an undecoded block would desync the HPACK table
		} else if !p.fpDone {
			p.finishFP()
		}
		return
	}
	switch f := f.(type) {
	case *http2.SettingsFrame:
		if f.IsAck() || p.gotSetting || p.fpDone {
			return
		}
		p.gotSetting = true
		_ = f.ForeachSetting(func(s http2.Setting) error {
			p.res.Settings = append(p.res.Settings, Setting{ID: uint16(s.ID), Value: s.Val})
			return nil
		})
	case *http2.WindowUpdateFrame:
		if f.StreamID == 0 && !p.gotWU && !p.fpDone {
			p.gotWU = true
			p.res.WindowUpdate = f.Increment
		}
	case *http2.PriorityFrame:
		if p.fpDone {
			return
		}
		p.res.Priorities = append(p.res.Priorities, Priority{
			StreamID:  f.StreamID,
			Exclusive: f.Exclusive,
			DependsOn: f.StreamDep,
			Weight:    f.Weight,
		})
	case *http2.HeadersFrame:
		// A HEADERS frame's own PRIORITY flag contributes nothing to the P
		// field, matching Akamai's convention (only PRIORITY frames count).
		p.block = append(p.block[:0], f.HeaderBlockFragment()...)
		p.blockStream = f.StreamID
		if f.HeadersEnded() {
			p.decode()
		} else {
			p.inHeaders = true
		}
	}
}

func (p *Parser) emit(hf hpack.HeaderField) {
	if p.curOverflow {
		return
	}
	if len(p.cur.Pseudo)+len(p.cur.Names) >= maxNames {
		p.curOverflow = true
		return
	}
	name := strings.ToLower(hf.Name)
	if strings.HasPrefix(name, ":") {
		p.cur.Pseudo = append(p.cur.Pseudo, name)
		if name == ":method" {
			p.cur.Method = hf.Value
		}
	} else {
		p.cur.Names = append(p.cur.Names, name)
	}
}

func (p *Parser) decode() {
	p.cur = HeaderBlock{StreamID: p.blockStream, Pseudo: []string{}, Names: []string{}}
	p.curOverflow = false
	_, werr := p.dec.Write(p.block)
	cerr := p.dec.Close()
	p.block = p.block[:0]
	if cap(p.block) > 64<<10 {
		p.block = nil
	}
	blk := p.cur
	p.cur = HeaderBlock{}
	if !p.gotHeaders && !p.fpDone {
		p.gotHeaders = true
		p.res.PseudoHeaderOrder = append([]string{}, blk.Pseudo...)
		p.res.HeaderOrder = append([]string{}, blk.Names...)
		p.finishFP()
	}
	if werr != nil || cerr != nil {
		p.stop()
		return
	}
	// Only request heads carry :method; trailers and overflowing blocks are
	// not reported.
	if p.curOverflow || blk.Method == "" {
		return
	}
	if len(p.out) >= MaxBlocks {
		p.out = append(p.out[:0], p.out[1:]...)
	}
	p.out = append(p.out, blk)
}

// Result returns the recovered fingerprint data once SETTINGS has been seen.
func (p *Parser) Result() (*Result, bool) {
	if !p.gotSetting {
		return nil, false
	}
	r := p.res
	r.Settings = append([]Setting{}, p.res.Settings...)
	r.Priorities = append([]Priority{}, p.res.Priorities...)
	r.PseudoHeaderOrder = append([]string{}, p.res.PseudoHeaderOrder...)
	r.HeaderOrder = append([]string{}, p.res.HeaderOrder...)
	r.Fingerprint = Akamai(&r)
	return &r, true
}
