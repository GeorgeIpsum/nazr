package ipintel

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

const (
	defaultMaxMindBase = "https://download.maxmind.com/geoip/databases"
	maxMMDBSize        = 512 << 20
)

// MaxMindTable wraps one GeoLite2 database (City or ASN). The record shape
// is the union of both editions; absent fields stay zero.
type MaxMindTable struct {
	r *maxminddb.Reader
}

type mmRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Continent struct {
		Code  string            `maxminddb:"code"`
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"continent"`
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Subdivisions []struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"subdivisions"`
	ASN   uint32 `maxminddb:"autonomous_system_number"`
	ASOrg string `maxminddb:"autonomous_system_organization"`
}

// Lookup returns the record for addr; the second value is false when the
// database has no data for it.
func (t *MaxMindTable) Lookup(addr netip.Addr) (mmRecord, bool) {
	var rec mmRecord
	res := t.r.Lookup(addr.Unmap())
	if !res.Found() {
		return rec, false
	}
	if err := res.Decode(&rec); err != nil {
		return mmRecord{}, false
	}
	return rec, true
}

// Rows is the number of tree nodes, a stable proxy for database size.
func (t *MaxMindTable) Rows() int { return int(t.r.Metadata.NodeCount) }

func openMMDB(path string) (*MaxMindTable, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// FromBytes (not mmap) keeps old readers valid while lookups finish
	// after a table swap.
	r, err := maxminddb.OpenBytes(b)
	if err != nil {
		return nil, fmt.Errorf("open mmdb: %w", err)
	}
	return &MaxMindTable{r: r}, nil
}

type maxmindSource struct {
	fetcher
	edition    string
	base       string
	accountID  string
	licenseKey string
}

func (s *maxmindSource) Name() string            { return s.edition }
func (s *maxmindSource) Interval() time.Duration { return 24 * time.Hour }
func (s *maxmindSource) file() string            { return s.edition + ".mmdb" }

func (s *maxmindSource) url(suffix string) string {
	return strings.TrimRight(s.base, "/") + "/" + s.edition + "/download?suffix=" + suffix
}

func (s *maxmindSource) do(ctx context.Context, method, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(s.accountID, s.licenseKey)
	return s.client.Do(req)
}

func (s *maxmindSource) Load(dataDir string) (Table, error) {
	return openMMDB(filepath.Join(dataDir, s.file()))
}

func (s *maxmindSource) Fetch(ctx context.Context, dataDir string) (bool, error) {
	dest := filepath.Join(dataDir, s.file())
	st, _ := readState(dataDir, s.edition)
	_, statErr := os.Stat(dest)
	haveFile := statErr == nil

	head, err := s.do(ctx, http.MethodHead, s.url("tar.gz"))
	if err != nil {
		return false, err
	}
	head.Body.Close()
	if head.StatusCode != http.StatusOK {
		return false, &StatusError{Op: s.edition + ": HEAD status", Code: head.StatusCode}
	}
	lm, lmErr := http.ParseTime(head.Header.Get("Last-Modified"))
	if haveFile && lmErr == nil && !st.LastModified.IsZero() && !lm.After(st.LastModified) {
		st.FetchedAt = s.now()
		return false, writeState(dataDir, s.edition, st)
	}

	tarball, err := os.CreateTemp(dataDir, "."+s.edition+"-*.tar.gz")
	if err != nil {
		return false, err
	}
	defer os.Remove(tarball.Name())
	defer tarball.Close()

	sum, err := s.download(ctx, tarball)
	if err != nil {
		return false, err
	}
	want, err := s.remoteSum(ctx)
	if err != nil {
		return false, err
	}
	if !strings.EqualFold(sum, want) {
		return false, fmt.Errorf("%s: sha256 mismatch (got %s, want %s)", s.edition, sum, want)
	}

	mmdb, err := os.CreateTemp(dataDir, "."+s.file()+"-*.tmp")
	if err != nil {
		return false, err
	}
	defer os.Remove(mmdb.Name())
	if _, err := tarball.Seek(0, io.SeekStart); err != nil {
		mmdb.Close()
		return false, err
	}
	err = extractMMDB(tarball, mmdb)
	if cerr := mmdb.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return false, fmt.Errorf("%s: %w", s.edition, err)
	}
	t, err := openMMDB(mmdb.Name())
	if err != nil {
		return false, fmt.Errorf("%s: %w", s.edition, err)
	}
	if err := os.Rename(mmdb.Name(), dest); err != nil {
		return false, err
	}
	next := sourceState{LastModified: lm, FetchedAt: s.now(), RowCount: t.Rows()}
	return true, writeState(dataDir, s.edition, next)
}

// download streams the tarball into w and returns its sha256 hex digest.
func (s *maxmindSource) download(ctx context.Context, w io.Writer) (string, error) {
	resp, err := s.do(ctx, http.MethodGet, s.url("tar.gz"))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", &StatusError{Op: s.edition + ": GET status", Code: resp.StatusCode}
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(w, h), resp.Body); err != nil {
		return "", fmt.Errorf("%s: download: %w", s.edition, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// remoteSum fetches the published digest; the body is `<hex>  <filename>`.
func (s *maxmindSource) remoteSum(ctx context.Context) (string, error) {
	resp, err := s.do(ctx, http.MethodGet, s.url("tar.gz.sha256"))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", &StatusError{Op: s.edition + ": sha256 status", Code: resp.StatusCode}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	f := strings.Fields(string(b))
	if len(f) == 0 || len(f[0]) != 64 {
		return "", fmt.Errorf("%s: malformed sha256 file", s.edition)
	}
	return f[0], nil
}

// extractMMDB copies the single *.mmdb entry of a gzip tarball into w.
func extractMMDB(r io.Reader, w io.Writer) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return errors.New("no .mmdb entry in archive")
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		if h.Typeflag != tar.TypeReg || !strings.HasSuffix(h.Name, ".mmdb") {
			continue
		}
		n, err := io.Copy(w, io.LimitReader(tr, maxMMDBSize+1))
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		if n > maxMMDBSize {
			return errors.New("mmdb entry too large")
		}
		return nil
	}
}
