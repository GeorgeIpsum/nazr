package tlsfp

import (
	"errors"
	"fmt"
	"io"
)

// MaxClientHello is the cap on total bytes consumed by ReadClientHello.
const MaxClientHello = 16 * 1024

var (
	// ErrNotTLS means the first byte was not a TLS handshake record.
	ErrNotTLS = errors.New("tlsfp: not a TLS handshake record")
	// ErrTooLarge means the ClientHello exceeded MaxClientHello bytes.
	ErrTooLarge = errors.New("tlsfp: client hello too large")
)

// ClientHello holds the fields relevant to fingerprinting. GREASE values are
// retained in the lists.
type ClientHello struct {
	LegacyVersion       uint16
	SupportedVersions   []uint16
	CipherSuites        []uint16
	Extensions          []uint16
	SNI                 bool
	ALPN                []string
	SignatureAlgorithms []uint16
	SupportedGroups     []uint16
	PointFormats        []uint8
}

// ReadClientHello reads whole TLS records from r until one ClientHello
// handshake message is assembled. raw is every byte consumed; hs is the
// reassembled handshake message. It never reads past the final record.
func ReadClientHello(r io.Reader) (raw []byte, hs []byte, err error) {
	for {
		var hdr [5]byte
		if _, err := io.ReadFull(r, hdr[:1]); err != nil {
			return raw, nil, fmt.Errorf("tlsfp: read record header: %w", err)
		}
		raw = append(raw, hdr[0])
		if hdr[0] != 0x16 {
			if len(hs) == 0 && len(raw) == 1 {
				return raw, nil, ErrNotTLS
			}
			return raw, nil, fmt.Errorf("tlsfp: unexpected record type 0x%02x", hdr[0])
		}
		if _, err := io.ReadFull(r, hdr[1:]); err != nil {
			return raw, nil, fmt.Errorf("tlsfp: read record header: %w", err)
		}
		raw = append(raw, hdr[1:]...)
		if hdr[1] != 3 {
			return raw, nil, fmt.Errorf("tlsfp: bad record version %02x%02x", hdr[1], hdr[2])
		}
		n := int(hdr[3])<<8 | int(hdr[4])
		if n == 0 {
			return raw, nil, errors.New("tlsfp: empty handshake record")
		}
		if len(raw)+n > MaxClientHello {
			return raw, nil, ErrTooLarge
		}
		start := len(raw)
		raw = append(raw, make([]byte, n)...)
		if _, err := io.ReadFull(r, raw[start:]); err != nil {
			return raw[:start], nil, fmt.Errorf("tlsfp: read record body: %w", err)
		}
		hs = append(hs, raw[start:]...)
		if len(hs) >= 4 {
			if hs[0] != 0x01 {
				return raw, nil, fmt.Errorf("tlsfp: not a ClientHello (handshake type %d)", hs[0])
			}
			need := 4 + (int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3]))
			if need > MaxClientHello {
				return raw, nil, ErrTooLarge
			}
			if len(hs) >= need {
				return raw, hs[:need], nil
			}
		}
	}
}

type reader struct{ b []byte }

var errTrunc = errors.New("truncated")

func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || n > len(r.b) {
		return nil, errTrunc
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v, nil
}

func (r *reader) u8() (int, error) {
	b, err := r.take(1)
	if err != nil {
		return 0, err
	}
	return int(b[0]), nil
}

func (r *reader) u16() (int, error) {
	b, err := r.take(2)
	if err != nil {
		return 0, err
	}
	return int(b[0])<<8 | int(b[1]), nil
}

// prefixed8/16 read a length-prefixed sub-slice.
func (r *reader) prefixed8() ([]byte, error) {
	n, err := r.u8()
	if err != nil {
		return nil, err
	}
	return r.take(n)
}

func (r *reader) prefixed16() ([]byte, error) {
	n, err := r.u16()
	if err != nil {
		return nil, err
	}
	return r.take(n)
}

func u16s(b []byte) ([]uint16, error) {
	if len(b)%2 != 0 {
		return nil, errors.New("odd length in uint16 list")
	}
	out := make([]uint16, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		out = append(out, uint16(b[i])<<8|uint16(b[i+1]))
	}
	return out, nil
}

// Parse parses a ClientHello handshake message starting at the handshake type
// byte (0x01) and 3-byte length.
func Parse(hs []byte) (*ClientHello, error) {
	ch, err := parse(hs)
	if err != nil {
		return nil, fmt.Errorf("tlsfp: parse client hello: %w", err)
	}
	return ch, nil
}

func parse(hs []byte) (*ClientHello, error) {
	if len(hs) < 4 {
		return nil, errTrunc
	}
	if hs[0] != 0x01 {
		return nil, fmt.Errorf("handshake type %d is not ClientHello", hs[0])
	}
	n := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if n > len(hs)-4 {
		return nil, errTrunc
	}
	r := &reader{b: hs[4 : 4+n]}
	ch := &ClientHello{}
	v, err := r.u16()
	if err != nil {
		return nil, err
	}
	ch.LegacyVersion = uint16(v)
	if _, err := r.take(32); err != nil {
		return nil, err
	}
	if _, err := r.prefixed8(); err != nil { // session id
		return nil, err
	}
	cs, err := r.prefixed16()
	if err != nil {
		return nil, err
	}
	if ch.CipherSuites, err = u16s(cs); err != nil {
		return nil, err
	}
	if _, err := r.prefixed8(); err != nil { // compression methods
		return nil, err
	}
	if len(r.b) == 0 {
		return ch, nil
	}
	eb, err := r.prefixed16()
	if err != nil {
		return nil, err
	}
	// Bytes after the extensions block (padding, garbage) are tolerated.
	er := &reader{b: eb}
	for len(er.b) > 0 {
		t, err := er.u16()
		if err != nil {
			return nil, err
		}
		data, err := er.prefixed16()
		if err != nil {
			return nil, err
		}
		ch.Extensions = append(ch.Extensions, uint16(t))
		if err := ch.extension(uint16(t), data); err != nil {
			return nil, fmt.Errorf("extension 0x%04x: %w", t, err)
		}
	}
	return ch, nil
}

func (ch *ClientHello) extension(t uint16, data []byte) error {
	r := &reader{b: data}
	switch t {
	case 0x0000: // server_name
		// JA4 'd' means the SNI extension is present, whatever it contains.
		ch.SNI = true
		if len(data) == 0 {
			return nil
		}
		l, err := r.prefixed16()
		if err != nil {
			return err
		}
		lr := &reader{b: l}
		for len(lr.b) > 0 {
			_, err := lr.u8()
			if err != nil {
				return err
			}
			if _, err := lr.prefixed16(); err != nil {
				return err
			}
		}
	case 0x0010: // ALPN
		l, err := r.prefixed16()
		if err != nil {
			return err
		}
		lr := &reader{b: l}
		for len(lr.b) > 0 {
			p, err := lr.prefixed8()
			if err != nil {
				return err
			}
			ch.ALPN = append(ch.ALPN, string(p))
		}
	case 0x002b: // supported_versions
		l, err := r.prefixed8()
		if err != nil {
			return err
		}
		if ch.SupportedVersions, err = u16s(l); err != nil {
			return err
		}
	case 0x000d: // signature_algorithms
		l, err := r.prefixed16()
		if err != nil {
			return err
		}
		if ch.SignatureAlgorithms, err = u16s(l); err != nil {
			return err
		}
	case 0x000a: // supported_groups
		l, err := r.prefixed16()
		if err != nil {
			return err
		}
		if ch.SupportedGroups, err = u16s(l); err != nil {
			return err
		}
	case 0x000b: // ec_point_formats
		l, err := r.prefixed8()
		if err != nil {
			return err
		}
		ch.PointFormats = append([]uint8(nil), l...)
	}
	return nil
}
