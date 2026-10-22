// Package h2fp passively fingerprints an HTTP/2 client from the first bytes it
// sends after the TLS handshake (Akamai format).
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

// Result is what the parser recovered.
type Result struct {
	Settings          []Setting
	WindowUpdate      uint32
	Priorities        []Priority
	PseudoHeaderOrder []string
	HeaderOrder       []string
	Fingerprint       string
}

// maxFrame bounds the payload we are willing to buffer for a single frame.
const maxFrame = 1 << 20

// Parser is an incremental HTTP/2 client-side parser.
type Parser struct {
	limit int
	total int
	buf   []byte
	done  bool

	prefaceOK  bool
	gotSetting bool
	gotWU      bool
	res        Result

	inHeaders bool
	block     []byte
}

// NewParser returns a parser that gives up after limit bytes.
func NewParser(limit int) *Parser { return &Parser{limit: limit} }

// Feed consumes bytes and reports whether parsing has finished (first
// HEADERS block complete, limit reached, or a parse error).
func (p *Parser) Feed(b []byte) bool {
	if p.done {
		return true
	}
	if p.limit > 0 && p.total+len(b) > p.limit {
		b = b[:p.limit-p.total]
	}
	p.total += len(b)
	p.buf = append(p.buf, b...)
	p.drain()
	if !p.done && p.limit > 0 && p.total >= p.limit {
		p.finish()
	}
	return p.done
}

func (p *Parser) finish() {
	p.done = true
	p.buf = nil
}

func (p *Parser) drain() {
	if !p.prefaceOK {
		n := len(http2.ClientPreface)
		have := len(p.buf)
		if have > n {
			have = n
		}
		if !strings.HasPrefix(http2.ClientPreface, string(p.buf[:have])) {
			p.finish()
			return
		}
		if len(p.buf) < n {
			return
		}
		p.buf = p.buf[n:]
		p.prefaceOK = true
	}
	for !p.done && len(p.buf) >= 9 {
		length := int(p.buf[0])<<16 | int(p.buf[1])<<8 | int(p.buf[2])
		if length > maxFrame {
			p.finish()
			return
		}
		if len(p.buf) < 9+length {
			return
		}
		raw := p.buf[:9+length]
		p.handle(raw)
		if p.done {
			return
		}
		p.buf = p.buf[9+length:]
	}
}

func (p *Parser) handle(raw []byte) {
	if p.inHeaders {
		// CONTINUATION is handled by hand: a fresh Framer per frame has no
		// preceding HEADERS and would reject it.
		if http2.FrameType(raw[3]) != http2.FrameContinuation {
			p.finish()
			return
		}
		p.block = append(p.block, raw[9:]...)
		if http2.Flags(raw[4])&http2.FlagContinuationEndHeaders != 0 {
			p.decode()
		}
		return
	}
	fr := http2.NewFramer(nil, bytes.NewReader(raw))
	fr.SetMaxReadFrameSize(maxFrame)
	f, err := fr.ReadFrame()
	if err != nil {
		p.finish()
		return
	}
	switch f := f.(type) {
	case *http2.SettingsFrame:
		if f.IsAck() || p.gotSetting {
			return
		}
		p.gotSetting = true
		_ = f.ForeachSetting(func(s http2.Setting) error {
			p.res.Settings = append(p.res.Settings, Setting{ID: uint16(s.ID), Value: s.Val})
			return nil
		})
	case *http2.WindowUpdateFrame:
		if f.StreamID == 0 && !p.gotWU {
			p.gotWU = true
			p.res.WindowUpdate = f.Increment
		}
	case *http2.PriorityFrame:
		p.res.Priorities = append(p.res.Priorities, Priority{
			StreamID:  f.StreamID,
			Exclusive: f.Exclusive,
			DependsOn: f.StreamDep,
			Weight:    f.Weight,
		})
	case *http2.MetaHeadersFrame:
		// not produced: ReadMetaHeaders is off
	case *http2.HeadersFrame:
		// A HEADERS frame's own PRIORITY flag contributes nothing to the P
		// field, matching Akamai's convention (only PRIORITY frames count).
		p.block = append([]byte(nil), f.HeaderBlockFragment()...)
		if f.HeadersEnded() {
			p.decode()
		} else {
			p.inHeaders = true
		}
	}
}

func (p *Parser) decode() {
	p.res.PseudoHeaderOrder = []string{}
	p.res.HeaderOrder = []string{}
	dec := hpack.NewDecoder(4096, func(hf hpack.HeaderField) {
		name := strings.ToLower(hf.Name)
		if strings.HasPrefix(name, ":") {
			p.res.PseudoHeaderOrder = append(p.res.PseudoHeaderOrder, name)
		} else {
			p.res.HeaderOrder = append(p.res.HeaderOrder, name)
		}
	})
	_, _ = dec.Write(p.block)
	_ = dec.Close()
	p.block = nil
	p.finish()
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
