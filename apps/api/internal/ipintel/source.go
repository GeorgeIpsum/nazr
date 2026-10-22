// Package ipintel loads IP intelligence data (GeoIP, ASN, relay, Tor,
// datacenter and VPN ranges, JA4 database), keeps it fresh in the
// background and answers lookups.
package ipintel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Table is a parsed data set. Concrete kinds are *PrefixTable[T],
// *MaxMindTable and *JA4Table.
type Table interface{}

// Source is one refreshable data set.
type Source interface {
	Name() string
	Interval() time.Duration
	// Fetch downloads the data into dataDir, replacing the cached file
	// atomically only on success. changed reports whether new data landed.
	Fetch(ctx context.Context, dataDir string) (changed bool, err error)
	// Load parses the cached file.
	Load(dataDir string) (Table, error)
}

type rowCounter interface{ Rows() int }

// sourceState is persisted next to each cached file as <name>.state.json.
type sourceState struct {
	LastModified time.Time `json:"last_modified"`
	ETag         string    `json:"etag"`
	FetchedAt    time.Time `json:"fetched_at"`
	RowCount     int       `json:"row_count"`
}

func statePath(dataDir, name string) string {
	return filepath.Join(dataDir, name+".state.json")
}

func readState(dataDir, name string) (sourceState, bool) {
	var st sourceState
	b, err := os.ReadFile(statePath(dataDir, name))
	if err != nil || json.Unmarshal(b, &st) != nil {
		return sourceState{}, false
	}
	return st, true
}

func writeState(dataDir, name string, st sourceState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return writeFileAtomic(statePath(dataDir, name), b)
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// fetcher holds what every HTTP-backed source shares.
type fetcher struct {
	client *http.Client
	now    func() time.Time
}

// downloadFile performs a conditional GET of url into <dataDir>/<file>. The
// body is parsed with validate (which returns the row count) before the
// temp file replaces the cached one, so a truncated or garbage download
// never clobbers good data.
func (f fetcher) downloadFile(ctx context.Context, dataDir, name, file, url string, validate func(path string) (int, error)) (bool, error) {
	dest := filepath.Join(dataDir, file)
	st, hadState := readState(dataDir, name)
	_, statErr := os.Stat(dest)
	haveFile := statErr == nil

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	if hadState && haveFile {
		if st.ETag != "" {
			req.Header.Set("If-None-Match", st.ETag)
		}
		if !st.LastModified.IsZero() {
			req.Header.Set("If-Modified-Since", st.LastModified.UTC().Format(http.TimeFormat))
		}
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotModified && haveFile:
		st.FetchedAt = f.now()
		return false, writeState(dataDir, name, st)
	case resp.StatusCode != http.StatusOK:
		return false, fmt.Errorf("%s: unexpected status %d", name, resp.StatusCode)
	}

	tmp, err := os.CreateTemp(dataDir, "."+file+"-*.tmp")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		return false, fmt.Errorf("%s: download: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	rows, err := validate(tmp.Name())
	if err != nil {
		return false, fmt.Errorf("%s: %w", name, err)
	}
	if err := os.Rename(tmp.Name(), dest); err != nil {
		return false, err
	}
	next := sourceState{ETag: resp.Header.Get("ETag"), FetchedAt: f.now(), RowCount: rows}
	if lm, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
		next.LastModified = lm
	}
	return true, writeState(dataDir, name, next)
}

var errEmpty = errors.New("no usable rows")
