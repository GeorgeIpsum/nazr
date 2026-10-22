package ipintel

import (
	"context"
	"os"
	"time"
)

const (
	defaultAppleURL = "https://mask-api.icloud.com/egress-ip-ranges.csv"
	appleFile       = "apple.csv"
)

type appleSource struct {
	fetcher
	url string
}

func (s *appleSource) Name() string            { return "apple" }
func (s *appleSource) Interval() time.Duration { return 24 * time.Hour }

func (s *appleSource) Fetch(ctx context.Context, dataDir string) (bool, error) {
	return s.downloadFile(ctx, dataDir, s.Name(), appleFile, s.url, "", func(p string) (int, error) {
		t, err := loadAppleFile(p)
		if err != nil {
			return 0, err
		}
		return t.Rows(), nil
	})
}

func loadAppleFile(path string) (*PrefixTable[relayEntry], error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseAppleCSV(f)
}

func (s *appleSource) Load(dataDir string) (Table, error) {
	return loadAppleFile(dataDir + "/" + appleFile)
}
