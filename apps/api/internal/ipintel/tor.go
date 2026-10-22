package ipintel

import (
	"context"
	"path/filepath"
	"time"
)

const (
	defaultTorURL = "https://check.torproject.org/torbulkexitlist"
	torFile       = "tor.txt"
)

type torSource struct {
	fetcher
	url string
}

func (s *torSource) Name() string            { return "tor" }
func (s *torSource) Interval() time.Duration { return 6 * time.Hour }

func (s *torSource) Fetch(ctx context.Context, dataDir string) (bool, error) {
	return s.downloadFile(ctx, dataDir, s.Name(), torFile, s.url, func(p string) (int, error) {
		t, err := loadCIDRFile(p)
		if err != nil {
			return 0, err
		}
		return t.Rows(), nil
	})
}

func (s *torSource) Load(dataDir string) (Table, error) {
	return loadCIDRFile(filepath.Join(dataDir, torFile))
}
