package ipintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const ja4dbFile = "ja4db.json"

// ja4dbSource is opt-in: FoxIO's database now requires an account, so there
// is no default URL. token, when set, is sent as a bearer credential.
type ja4dbSource struct {
	fetcher
	url   string
	token string
}

func (s *ja4dbSource) Name() string            { return "ja4db" }
func (s *ja4dbSource) Interval() time.Duration { return 7 * 24 * time.Hour }

type ja4dbRecord struct {
	Application *string `json:"application"`
	JA4         *string `json:"ja4_fingerprint"`
}

func parseJA4DB(r io.Reader) (*JA4Table, error) {
	var recs []ja4dbRecord
	if err := json.NewDecoder(r).Decode(&recs); err != nil {
		return nil, fmt.Errorf("ja4db json: %w", err)
	}
	m := map[string][]string{}
	for _, rec := range recs {
		if rec.Application == nil || rec.JA4 == nil {
			continue
		}
		app := strings.ToLower(strings.TrimSpace(*rec.Application))
		fp := strings.TrimSpace(*rec.JA4)
		if app == "" || fp == "" {
			continue
		}
		m[fp] = append(m[fp], app)
	}
	for k, v := range m {
		slices.Sort(v)
		m[k] = slices.Compact(v)
	}
	if len(m) == 0 {
		return nil, errEmpty
	}
	return &JA4Table{m: m}, nil
}

func loadJA4DBFile(path string) (*JA4Table, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseJA4DB(f)
}

func (s *ja4dbSource) Fetch(ctx context.Context, dataDir string) (bool, error) {
	return s.downloadFile(ctx, dataDir, s.Name(), ja4dbFile, s.url, s.token, func(p string) (int, error) {
		t, err := loadJA4DBFile(p)
		if err != nil {
			return 0, err
		}
		return t.Rows(), nil
	})
}

func (s *ja4dbSource) Load(dataDir string) (Table, error) {
	return loadJA4DBFile(filepath.Join(dataDir, ja4dbFile))
}
