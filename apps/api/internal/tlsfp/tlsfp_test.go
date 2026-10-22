package tlsfp

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

func hexList(t *testing.T, s string) []uint16 {
	t.Helper()
	var out []uint16
	for _, p := range strings.Split(s, ",") {
		b, err := hex.DecodeString(p)
		if err != nil || len(b) != 2 {
			t.Fatalf("bad hex %q", p)
		}
		out = append(out, uint16(b[0])<<8|uint16(b[1]))
	}
	return out
}

// Worked example from FoxIO JA4.md ("JA4 Algorithm and Worked Example"):
// https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
func TestJA4SpecExample(t *testing.T) {
	ch := &ClientHello{
		LegacyVersion:       0x0303,
		SupportedVersions:   []uint16{0x0304, 0x0303},
		CipherSuites:        hexList(t, "1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035"),
		Extensions:          hexList(t, "001b,0000,0033,0010,4469,0017,002d,000d,0005,0023,0012,002b,ff01,000b,000a,0015"),
		SNI:                 true,
		ALPN:                []string{"h2"},
		SignatureAlgorithms: hexList(t, "0403,0804,0401,0503,0805,0501,0806,0601"),
	}
	r := Fingerprint(ch, 't')
	const want = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	if r.JA4 != want {
		t.Fatalf("JA4 = %q want %q", r.JA4, want)
	}
	wantR := "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601"
	if r.JA4Raw != wantR {
		t.Fatalf("JA4Raw = %q", r.JA4Raw)
	}
	if r.JA4Orig != "t13d1516h2_acb858a92679_18f69afefd3d" {
		t.Fatalf("JA4Orig = %q", r.JA4Orig)
	}
	wantRO := "t13d1516h2_1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035_001b,0000,0033,0010,4469,0017,002d,000d,0005,0023,0012,002b,ff01,000b,000a,0015_0403,0804,0401,0503,0805,0501,0806,0601"
	if r.JA4RawOrig != wantRO {
		t.Fatalf("JA4RawOrig = %q", r.JA4RawOrig)
	}
}

func TestJA4GreaseIgnored(t *testing.T) {
	base := &ClientHello{LegacyVersion: 0x0303, CipherSuites: []uint16{0x1301}, Extensions: []uint16{0x000d}, SignatureAlgorithms: []uint16{0x0403}}
	g := &ClientHello{LegacyVersion: 0x0303, SupportedVersions: []uint16{0x0a0a, 0x0304}, CipherSuites: []uint16{0x2a2a, 0x1301}, Extensions: []uint16{0x0a0a, 0x000d, 0xfafa}, SignatureAlgorithms: []uint16{0x0403}}
	a, b := Fingerprint(base, 't'), Fingerprint(g, 't')
	if a.JA4[:3] != "t12" || b.JA4[:3] != "t13" {
		t.Fatalf("versions %q %q", a.JA4, b.JA4)
	}
	if a.JA4[3:] != b.JA4[3:] {
		t.Fatalf("grease changed ja4: %q vs %q", a.JA4, b.JA4)
	}
}

func TestJA4NoCiphersNoExtensions(t *testing.T) {
	r := Fingerprint(&ClientHello{LegacyVersion: 0x0303}, 't')
	if r.JA4 != "t12i000000_000000000000_000000000000" {
		t.Fatalf("got %q", r.JA4)
	}
	r = Fingerprint(&ClientHello{LegacyVersion: 0x0303}, 'q')
	if r.JA4[0] != 'q' {
		t.Fatalf("got %q", r.JA4)
	}
}

func TestJA4NoSigAlgs(t *testing.T) {
	ch := &ClientHello{LegacyVersion: 0x0303, CipherSuites: []uint16{0x1301}, Extensions: []uint16{0x000a}}
	r := Fingerprint(ch, 't')
	if strings.Count(r.JA4Raw, "_") != 2 || !strings.HasSuffix(r.JA4Raw, "_000a") {
		t.Fatalf("raw %q", r.JA4Raw)
	}
}

func TestJA4ALPNNonAlnum(t *testing.T) {
	ch := &ClientHello{LegacyVersion: 0x0303, ALPN: []string{"\x01\x02"}}
	if got := Fingerprint(ch, 't').JA4[:10]; got != "t12i000002" {
		t.Fatalf("got %q", got)
	}
	ch.ALPN = []string{"http/1.1"}
	if got := Fingerprint(ch, 't').JA4[:10]; got != "t12i0000h1" {
		t.Fatalf("got %q", got)
	}
}

func TestJA4CountsCapped(t *testing.T) {
	ch := &ClientHello{LegacyVersion: 0x0303}
	for i := 0; i < 150; i++ {
		ch.CipherSuites = append(ch.CipherSuites, uint16(0x1000+i))
		ch.Extensions = append(ch.Extensions, uint16(0x2000+i))
	}
	if got := Fingerprint(ch, 't').JA4[:10]; got != "t12i999900" {
		t.Fatalf("got %q", got)
	}
}

func TestJA3KnownVector(t *testing.T) {
	ch := &ClientHello{
		LegacyVersion:   0x0303,
		CipherSuites:    []uint16{0x0a0a, 0x1301, 0x1302},
		Extensions:      []uint16{0x0a0a, 0, 23, 65281},
		SupportedGroups: []uint16{0x1a1a, 29, 23},
		PointFormats:    []uint8{0},
	}
	r := Fingerprint(ch, 't')
	const want = "771,4865-4866,0-23-65281,29-23,0"
	if r.JA3 != want {
		t.Fatalf("JA3 = %q", r.JA3)
	}
	sum := md5.Sum([]byte(want))
	if r.JA3Hash != hex.EncodeToString(sum[:]) {
		t.Fatalf("hash %q", r.JA3Hash)
	}
}

func TestIsGrease(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0xfafa} {
		if !IsGrease(v) {
			t.Errorf("%04x", v)
		}
	}
	for _, v := range []uint16{0x0000, 0x1301, 0x0a0b, 0x0b0a} {
		if IsGrease(v) {
			t.Errorf("%04x", v)
		}
	}
}

// goClientHello captures the raw bytes of a real Go ClientHello.
func goClientHello(t *testing.T) (raw, hs []byte) {
	t.Helper()
	c, s := net.Pipe()
	defer s.Close()
	go func() {
		cl := tls.Client(c, &tls.Config{ServerName: "example.com", NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: true})
		_ = cl.Handshake()
	}()
	_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
	raw, hs, err := ReadClientHello(s)
	_ = c.Close()
	if err != nil {
		t.Fatal(err)
	}
	return raw, hs
}

func TestParseGoClientHello(t *testing.T) {
	raw, hs := goClientHello(t)
	if len(raw) != len(hs)+5 {
		t.Fatalf("raw %d hs %d", len(raw), len(hs))
	}
	ch, err := Parse(hs)
	if err != nil {
		t.Fatal(err)
	}
	if !ch.SNI {
		t.Error("no SNI")
	}
	if !reflect.DeepEqual(ch.ALPN, []string{"h2", "http/1.1"}) {
		t.Errorf("alpn %v", ch.ALPN)
	}
	found := false
	for _, v := range ch.SupportedVersions {
		if v == 0x0304 {
			found = true
		}
	}
	if !found {
		t.Errorf("versions %v", ch.SupportedVersions)
	}
	r := Fingerprint(ch, 't')
	if !regexp.MustCompile(`^t1[0-3][di]\d{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`).MatchString(r.JA4) {
		t.Errorf("ja4 %q", r.JA4)
	}
	if r.JA4[3] != 'd' || !strings.HasPrefix(r.JA4[8:], "h2_") {
		t.Errorf("ja4 %q", r.JA4)
	}
}

func TestComponentTypes(t *testing.T) {
	_, hs := goClientHello(t)
	ch, _ := Parse(hs)
	m := Fingerprint(ch, 't').Component()
	want := map[string]any{
		"version": "", "ja4": "", "ja4_r": "", "ja3": "", "ja3_hash": "",
		"ciphers": []string{}, "extensions": []string{}, "sig_algs": []string{}, "groups": []string{},
		"sni": false, "alpn": []string{},
	}
	if len(m) != len(want) {
		t.Fatalf("keys %v", m)
	}
	for k, w := range want {
		v, ok := m[k]
		if !ok || reflect.TypeOf(v) != reflect.TypeOf(w) {
			t.Errorf("%s: %T", k, v)
		}
	}
	if m["version"] != "1.3" {
		t.Errorf("version %v", m["version"])
	}
	for _, s := range m["ciphers"].([]string) {
		if !regexp.MustCompile(`^[0-9a-f]{4}$`).MatchString(s) {
			t.Errorf("cipher %q", s)
		}
	}
	e := Fingerprint(&ClientHello{LegacyVersion: 0x0303}, 't').Component()
	for _, k := range []string{"ciphers", "extensions", "sig_algs", "groups", "alpn"} {
		if e[k] == nil || len(e[k].([]string)) != 0 {
			t.Errorf("%s not empty slice", k)
		}
	}
}

func TestReadClientHelloNotTLS(t *testing.T) {
	r := strings.NewReader("GET / HTTP/1.1\r\n")
	raw, _, err := ReadClientHello(r)
	if !errors.Is(err, ErrNotTLS) {
		t.Fatalf("err %v", err)
	}
	if string(raw) != "G" {
		t.Errorf("raw %q", raw)
	}
}

func TestReadClientHelloTooLarge(t *testing.T) {
	hdr := []byte{0x16, 3, 1, 0x40, 0x00}
	var buf bytes.Buffer
	for i := 0; i < 3; i++ {
		buf.Write(hdr)
		buf.Write(make([]byte, 0x4000))
	}
	// handshake header claiming a big ClientHello
	b := buf.Bytes()
	copy(b[5:], []byte{1, 0x00, 0xff, 0xff})
	_, _, err := ReadClientHello(bytes.NewReader(b))
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err %v", err)
	}
}

func TestReadClientHelloSplitRecords(t *testing.T) {
	_, hs := goClientHello(t)
	cut := 50
	rec := func(p []byte) []byte {
		return append([]byte{0x16, 3, 1, byte(len(p) >> 8), byte(len(p))}, p...)
	}
	stream := append(rec(hs[:cut]), rec(hs[cut:])...)
	trailer := []byte("EXTRA")
	in := bytes.NewReader(append(append([]byte{}, stream...), trailer...))
	raw, got, err := ReadClientHello(in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, hs) || !bytes.Equal(raw, stream) {
		t.Fatal("mismatch")
	}
	rest, _ := io.ReadAll(in)
	if string(rest) != "EXTRA" {
		t.Errorf("over-read: %q", rest)
	}
	// one-byte records
	var one []byte
	for i := range hs {
		one = append(one, rec(hs[i:i+1])...)
	}
	if _, got, err := ReadClientHello(bytes.NewReader(one)); err != nil || !bytes.Equal(got, hs) {
		t.Fatalf("one-byte records: %v", err)
	}
}

func TestParseTruncated(t *testing.T) {
	_, hs := goClientHello(t)
	for i := 0; i < len(hs); i++ {
		if _, err := Parse(hs[:i]); err == nil {
			t.Fatalf("no error at %d", i)
		}
	}
	if _, err := Parse(hs); err != nil {
		t.Fatal(err)
	}
}

func FuzzParse(f *testing.F) {
	c, s := net.Pipe()
	go func() {
		cl := tls.Client(c, &tls.Config{ServerName: "example.com", NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: true})
		_ = cl.Handshake()
	}()
	_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, hs, err := ReadClientHello(s)
	_ = c.Close()
	_ = s.Close()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(hs)
	f.Fuzz(func(t *testing.T, b []byte) {
		ch, err := Parse(b)
		if err == nil {
			_ = Fingerprint(ch, 't').Component()
		}
	})
}
