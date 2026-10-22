package ipintel

import (
	"context"
	"path/filepath"
	"time"
)

const (
	defaultDatacenterURL = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt"
	defaultVPNURL        = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt"

	kindDatacenter = "datacenter"
	kindVPN        = "vpn"
)

// cidrListSource serves both the datacenter and VPN lists, one per URL.
type cidrListSource struct {
	fetcher
	kind string // kindDatacenter | kindVPN
	name string
	url  string
}

func (s *cidrListSource) Name() string            { return s.name }
func (s *cidrListSource) Interval() time.Duration { return 24 * time.Hour }
func (s *cidrListSource) file() string            { return s.name + ".txt" }

func (s *cidrListSource) Fetch(ctx context.Context, dataDir string) (bool, error) {
	return s.downloadFile(ctx, dataDir, s.name, s.file(), s.url, "", func(p string) (int, error) {
		t, err := loadCIDRFile(p)
		if err != nil {
			return 0, err
		}
		return t.Rows(), nil
	})
}

func (s *cidrListSource) Load(dataDir string) (Table, error) {
	return loadCIDRFile(filepath.Join(dataDir, s.file()))
}
