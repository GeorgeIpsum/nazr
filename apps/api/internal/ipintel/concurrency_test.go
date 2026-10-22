package ipintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func appleOnly(t *testing.T, dir, url string, c *http.Client) *Service {
	t.Helper()
	s, err := New(Config{
		DataDir: dir, HTTPClient: c, AppleRelayURL: url, Now: fixedNow(t0),
		Disabled: []string{"tor", "datacenter", "vpn", "ja4db", "maxmind"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStatusDoesNotBlockDuringFetch(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		w.Write(mustRead(t, td("apple.csv")))
	}))
	defer srv.Close()
	s := appleOnly(t, t.TempDir(), srv.URL, srv.Client())
	done := make(chan error, 1)
	go func() { done <- s.RefreshAll(context.Background()) }()
	<-entered
	got := make(chan map[string]SourceStatus, 1)
	go func() { got <- s.Status() }()
	select {
	case st := <-got:
		if st["apple"].Loaded {
			t.Error("loaded before fetch finished")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Status blocked during an in-flight fetch")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !s.Status()["apple"].Loaded {
		t.Error("not loaded after fetch")
	}
}

func TestNoConcurrentFetchOfSameSource(t *testing.T) {
	var inflight, maxInflight, total int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&inflight, 1)
		for {
			m := atomic.LoadInt32(&maxInflight)
			if n <= m || atomic.CompareAndSwapInt32(&maxInflight, m, n) {
				break
			}
		}
		atomic.AddInt32(&total, 1)
		time.Sleep(30 * time.Millisecond)
		atomic.AddInt32(&inflight, -1)
		w.Write(mustRead(t, td("apple.csv")))
	}))
	defer srv.Close()
	s := appleOnly(t, t.TempDir(), srv.URL, srv.Client())
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); s.RefreshAll(context.Background()) }()
		go func() { defer wg.Done(); s.tick(context.Background()) }()
	}
	wg.Wait()
	if maxInflight != 1 {
		t.Errorf("max concurrent fetches = %d, want 1", maxInflight)
	}
	if total == 0 {
		t.Error("no fetch happened")
	}
}

func TestTickFansOutSoHungSourceDoesNotDelayOthers(t *testing.T) {
	block := make(chan struct{})
	slow := &blockingSource{fakeSource: fakeSource{name: "slow", interval: time.Hour}, block: block}
	fast := &fakeSource{name: "fast", interval: time.Hour}
	s := newService(Config{DataDir: t.TempDir(), Now: fixedNow(t0)})
	s.add(kindTor, slow)
	s.add(kindVPN, fast)
	go s.tick(context.Background())
	deadline := time.Now().Add(2 * time.Second)
	for fast.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if fast.count() == 0 {
		t.Error("fast source delayed by hung source")
	}
	close(block)
}

type blockingSource struct {
	fakeSource
	block chan struct{}
}

func (b *blockingSource) Fetch(ctx context.Context, dir string) (bool, error) {
	<-b.block
	return b.fakeSource.Fetch(ctx, dir)
}

func TestDataDirCreatedOnRefreshAndStart(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(mustRead(t, td("apple.csv")))
	}))
	defer srv.Close()
	dir := filepath.Join(t.TempDir(), "a", "b", "data")
	s := appleOnly(t, dir, srv.URL, srv.Client())
	if err := s.RefreshAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !s.Status()["apple"].Loaded {
		t.Error("not loaded in new dir")
	}

	dir2 := filepath.Join(t.TempDir(), "x", "y")
	s2 := appleOnly(t, dir2, srv.URL, srv.Client())
	ctx, cancel := context.WithCancel(context.Background())
	s2.Start(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for !s2.Status()["apple"].Loaded && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	s2.Wait()
	if !s2.Status()["apple"].Loaded {
		t.Error("Start did not create dir and fetch")
	}
}

func TestAppleOverrideClearsMismatchedCountryNames(t *testing.T) {
	s := seededService(t)
	pt, err := parseAppleCSV(stringsReader("2.125.160.216/29,US,US-CA,Cupertino,\n"))
	if err != nil {
		t.Fatal(err)
	}
	s.entries["apple"].tbl.Store(&tableHolder{t: pt})
	l := s.Lookup(mustAddr(testCityIP))
	if l.Country != "US" || l.CountryName != "" || l.ContinentCode != "" || l.ContinentName != "" {
		t.Errorf("lookup = %+v", l)
	}
	// Same country keeps MaxMind's names.
	l = seededService(t).Lookup(mustAddr(testCityIP))
	if l.CountryName != "United Kingdom" || l.ContinentCode != "EU" {
		t.Errorf("same-country lookup = %+v", l)
	}
}
