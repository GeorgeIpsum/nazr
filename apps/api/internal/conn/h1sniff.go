package conn

import (
	"bytes"
	"errors"
	"strings"

	"golang.org/x/net/http2"
	"nazr/api/internal/h2fp"
)

var errNoH2Settings = errors.New("conn: h2 parser finished without SETTINGS")

// sniffer watches plaintext bytes as they pass through, recording the header
// name order of the first HTTP/1.1 request head, or feeding the h2 parser
// when the h2c prior-knowledge preface appears.
type sniffer struct {
	holder *Holder
	buf    []byte
	h2     *h2fp.Parser
}

func newSniffer(h *Holder) *sniffer { return &sniffer{holder: h} }

// feed reports true once the sniffer is finished and can be dropped.
func (s *sniffer) feed(b []byte) bool {
	if s.h2 != nil {
		return feedH2(s.h2, s.holder, b)
	}
	s.buf = append(s.buf, b...)
	preface := []byte(http2.ClientPreface)
	if len(s.buf) < len(preface) && bytes.HasPrefix(preface, s.buf) {
		return false // undecided: could still be the h2c preface
	}
	if bytes.HasPrefix(s.buf, preface) {
		if !s.holder.captureH2 {
			return true
		}
		s.h2 = h2fp.NewParser(s.holder.h2Limit)
		buf := s.buf
		s.buf = nil
		return feedH2(s.h2, s.holder, buf)
	}
	end := bytes.Index(s.buf, []byte("\r\n\r\n"))
	if end < 0 {
		if len(s.buf) >= maxH1Head {
			s.buf = nil
			return true
		}
		return false
	}
	if end+4 > maxH1Head {
		s.buf = nil
		return true
	}
	order := parseHeaderOrder(s.buf[:end+4])
	s.holder.set(func(h *Holder) { h.HeaderOrder = order })
	s.buf = nil
	return true
}

// feedH2 feeds p and, once it is done, stores the result on h.
func feedH2(p *h2fp.Parser, h *Holder, b []byte) bool {
	if !p.Feed(b) {
		return false
	}
	finishH2(p, h)
	return true
}

func finishH2(p *h2fp.Parser, h *Holder) {
	res, ok := p.Result()
	h.set(func(h *Holder) {
		if !ok {
			h.H2Error = errNoH2Settings
			return
		}
		h.H2 = res
		if res.HeaderOrder != nil {
			h.HeaderOrder = res.HeaderOrder
		}
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
