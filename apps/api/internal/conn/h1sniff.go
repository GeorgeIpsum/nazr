package conn

import (
	"bytes"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/net/http2"
	"nazr/api/internal/h2fp"
)

var errNoH2Settings = errors.New("conn: h2 parser finished without SETTINGS")

// sniffer watches plaintext bytes as they pass through. It records the header
// name order of every HTTP/1.1 request head on the connection (skipping
// Content-Length bodies between keep-alive requests), or feeds the h2 parser
// when the h2c prior-knowledge preface appears.
//
// It gives up (and later requests get no order) on a head over maxH1Head, a
// chunked or otherwise unframed body, a protocol upgrade or CONNECT, since
// it can no longer tell where the next request head starts.
type sniffer struct {
	holder  *Holder
	buf     []byte
	decided bool
	skip    int64 // body bytes of the current request still to pass over
	h2      *h2fp.Parser
	h2fp    bool // the h2 fingerprint has been reported
}

func newSniffer(h *Holder) *sniffer { return &sniffer{holder: h} }

// feed reports true once the sniffer is finished and can be dropped.
func (s *sniffer) feed(b []byte) bool {
	if s.h2 != nil {
		return feedH2(s.h2, s.holder, &s.h2fp, b)
	}
	if !s.decided {
		s.buf = append(s.buf, b...)
		preface := []byte(http2.ClientPreface)
		if len(s.buf) < len(preface) && bytes.HasPrefix(preface, s.buf) {
			return false // undecided: could still be the h2c preface
		}
		s.decided = true
		b, s.buf = s.buf, nil
		if bytes.HasPrefix(b, preface) {
			if !s.holder.captureH2 {
				return true
			}
			s.h2 = h2fp.NewParser(s.holder.h2Limit) // net/http's h2c uses the default table
			return feedH2(s.h2, s.holder, &s.h2fp, b)
		}
	}
	return s.feedH1(b)
}

var crlfcrlf = []byte("\r\n\r\n")

func (s *sniffer) feedH1(b []byte) bool {
	for {
		if s.skip > 0 {
			n := min(int64(len(b)), s.skip)
			s.skip -= n
			b = b[n:]
			if s.skip > 0 {
				return false
			}
		}
		if len(s.buf) == 0 {
			// net/http tolerates CR/LF ahead of a request line; so do we.
			b = bytes.TrimLeft(b, "\r\n")
		}
		if len(b) == 0 {
			return false
		}
		start := max(0, len(s.buf)-3)
		s.buf = append(s.buf, b...)
		end := bytes.Index(s.buf[start:], crlfcrlf)
		if end < 0 {
			if len(s.buf) >= maxH1Head {
				s.buf = nil
				return true
			}
			return false
		}
		end += start
		if end+4 > maxH1Head {
			s.buf = nil
			return true
		}
		method, order, bodyLen, ok := parseHead(s.buf[:end+4])
		if !ok {
			s.buf = nil
			return true
		}
		s.holder.PushOrder(method, order)
		b = s.buf[end+4:]
		s.buf = nil
		if bodyLen < 0 {
			return true
		}
		s.skip = bodyLen
	}
}

// parseHead returns the method, the lowercase header names in wire order,
// and the body length of an HTTP/1.x request head. bodyLen is -1 when the
// next request head cannot be located (chunked or invalid framing, Upgrade,
// CONNECT); ok is false for a head that is not a request.
func parseHead(head []byte) (method string, order []string, bodyLen int64, ok bool) {
	line, _, _ := bytes.Cut(head, []byte("\r\n"))
	method, _, ok = strings.Cut(string(line), " ")
	if !ok || method == "" {
		return "", nil, 0, false
	}
	order = parseHeaderOrder(head)
	bodyLen = 0
	cl := ""
	for _, l := range strings.Split(string(head), "\r\n")[1:] {
		name, value, found := strings.Cut(l, ":")
		if !found || l[0] == ' ' || l[0] == '\t' {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "transfer-encoding", "upgrade":
			return method, order, -1, true
		case "content-length":
			if cl != "" && cl != value {
				return method, order, -1, true
			}
			cl = value
		}
	}
	if method == "CONNECT" {
		return method, order, -1, true
	}
	if cl != "" {
		n, err := strconv.ParseInt(cl, 10, 64)
		if err != nil || n < 0 {
			return method, order, -1, true
		}
		bodyLen = n
	}
	return method, order, bodyLen, true
}

// feedH2 feeds p, queues its decoded header blocks on h and stores the
// fingerprint once the fingerprint phase is over (reported tracks that). It
// reports true when p has stopped and can be dropped.
func feedH2(p *h2fp.Parser, h *Holder, reported *bool, b []byte) bool {
	fpDone := p.Feed(b)
	if blocks := p.TakeBlocks(); len(blocks) > 0 {
		h.mu.Lock()
		for _, blk := range blocks {
			h.pushOrderLocked(blk.Method, blk.Names)
		}
		h.mu.Unlock()
	}
	if fpDone && !*reported {
		*reported = true
		finishH2(p, h)
	}
	return p.Stopped()
}

func finishH2(p *h2fp.Parser, h *Holder) {
	res, ok := p.Result()
	h.set(func(h *Holder) {
		if !ok {
			h.H2Error = errNoH2Settings
			return
		}
		h.H2 = res
	})
}

// parseHeaderOrder returns lowercase header names in wire order from an
// HTTP/1.x request head, skipping the request line and obs-fold lines.
func parseHeaderOrder(head []byte) []string {
	lines := strings.Split(string(head), "\r\n")
	order := []string{}
	for _, l := range lines[1:] {
		if l == "" {
			break
		}
		if l[0] == ' ' || l[0] == '\t' {
			continue
		}
		name, _, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		order = append(order, strings.ToLower(strings.TrimSpace(name)))
	}
	return order
}
