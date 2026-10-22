package ipintel

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const (
	testCityIP = "2.125.160.216" // Boxford, GB in GeoLite2-City-Test
	testASNIP  = "1.128.0.1"     // inside 1.128.0.0/11 in GeoLite2-ASN-Test
)

func td(name string) string { return filepath.Join("..", "..", "testdata", "ipintel", name) }

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func copyTD(t *testing.T, dst, from, to string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dst, to), mustRead(t, td(from)), 0o644); err != nil {
		t.Fatal(err)
	}
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// noNetwork fails any request that is not served by an httptest server.
type noNetwork struct{}

func (noNetwork) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, errors.New("network access in test: " + r.URL.String())
}

func noNetClient() *http.Client { return &http.Client{Transport: noNetwork{}} }

// seededService returns a service with every sample file already cached in
// a temp dir and loaded, using a client that refuses network access.
func seededService(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	copyTD(t, dir, "GeoLite2-City-Test.mmdb", "GeoLite2-City.mmdb")
	copyTD(t, dir, "GeoLite2-ASN-Test.mmdb", "GeoLite2-ASN.mmdb")
	copyTD(t, dir, "apple.csv", "apple.csv")
	copyTD(t, dir, "tor.txt", "tor.txt")
	copyTD(t, dir, "dc-v4.txt", "datacenter.txt")
	copyTD(t, dir, "vpn-v4.txt", "vpn.txt")
	copyTD(t, dir, "ja4db.json", "ja4db.json")
	s, err := New(Config{
		DataDir: dir, HTTPClient: noNetClient(), JA4DBURL: "http://ja4db.invalid/",
		MaxMindAccountID: "1", MaxMindLicenseKey: "k",
		MaxMindEditions: []string{"GeoLite2-City", "GeoLite2-ASN"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s.loadAllCached()
	return s
}

func tarGz(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	tw.Write(body)
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

// mmServer emulates download.maxmind.com for one edition.
type mmServer struct {
	*httptest.Server
	mu           sync.Mutex
	lastModified string
	tarball      []byte
	sha          string
	status       int // non-zero forces every response status
	truncate     bool
	heads, gets  int
	user, pass   string
}

func newMMServer(t *testing.T, edition string, mmdb []byte, lastModified time.Time) *mmServer {
	t.Helper()
	m := &mmServer{lastModified: lastModified.UTC().Format(http.TimeFormat)}
	m.tarball = tarGz(t, edition+"_20260101/"+edition+".mmdb", mmdb)
	m.sha = sum(m.tarball)
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.user, m.pass, _ = r.BasicAuth()
		if m.status != 0 {
			w.WriteHeader(m.status)
			return
		}
		switch {
		case r.Method == http.MethodHead:
			m.heads++
			w.Header().Set("Last-Modified", m.lastModified)
		case r.URL.Query().Get("suffix") == "tar.gz.sha256":
			io.WriteString(w, m.sha+"  "+edition+"_20260101.tar.gz\n")
		default:
			m.gets++
			w.Header().Set("Last-Modified", m.lastModified)
			if m.truncate {
				w.Header().Set("Content-Length", "1000000")
				w.Write(m.tarball[:len(m.tarball)/2])
				return
			}
			w.Write(m.tarball)
		}
	}))
	t.Cleanup(m.Close)
	return m
}

func newMMSource(m *mmServer, edition string, now func() time.Time) *maxmindSource {
	return &maxmindSource{
		fetcher: fetcher{client: m.Client(), now: now}, edition: edition, base: m.URL,
		accountID: "acct", licenseKey: "lic",
	}
}

func stringsReader(s string) io.Reader { return bytes.NewReader([]byte(s)) }

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
