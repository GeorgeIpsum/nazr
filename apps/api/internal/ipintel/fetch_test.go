package ipintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

func fixedNow(tm time.Time) func() time.Time { return func() time.Time { return tm } }

func TestMaxMindFetchDownloadsAndInstalls(t *testing.T) {
	dir := t.TempDir()
	mm := mustRead(t, td("GeoLite2-City-Test.mmdb"))
	srv := newMMServer(t, "GeoLite2-City", mm, t0.Add(-time.Hour))
	src := newMMSource(srv, "GeoLite2-City", fixedNow(t0))
	changed, err := src.Fetch(context.Background(), dir)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if got := mustRead(t, filepath.Join(dir, "GeoLite2-City.mmdb")); sum(got) != sum(mm) {
		t.Error("installed mmdb differs from tarball content")
	}
	if srv.user != "acct" || srv.pass != "lic" {
		t.Errorf("basic auth = %q/%q", srv.user, srv.pass)
	}
	st, ok := readState(dir, "GeoLite2-City")
	if !ok || !st.LastModified.Equal(t0.Add(-time.Hour)) || !st.FetchedAt.Equal(t0) || st.RowCount == 0 {
		t.Errorf("state = %+v", st)
	}
	if _, err := src.Load(dir); err != nil {
		t.Errorf("load: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*")); len(left) != 0 {
		t.Errorf("temp files left: %v", left)
	}
}

func TestMaxMindFetchSkipsWhenNotModified(t *testing.T) {
	dir := t.TempDir()
	mm := mustRead(t, td("GeoLite2-City-Test.mmdb"))
	lm := t0.Add(-time.Hour)
	srv := newMMServer(t, "GeoLite2-City", mm, lm)
	src := newMMSource(srv, "GeoLite2-City", fixedNow(t0))
	if _, err := src.Fetch(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	getsBefore := srv.gets
	src.fetcher.now = fixedNow(t0.Add(25 * time.Hour))
	changed, err := src.Fetch(context.Background(), dir)
	if err != nil || changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if srv.gets != getsBefore {
		t.Error("tarball downloaded although Last-Modified unchanged")
	}
	if st, _ := readState(dir, "GeoLite2-City"); !st.FetchedAt.Equal(t0.Add(25 * time.Hour)) {
		t.Errorf("fetched_at not advanced: %v", st.FetchedAt)
	}
	// A newer Last-Modified downloads again.
	srv.lastModified = t0.Format(http.TimeFormat)
	if changed, err := src.Fetch(context.Background(), dir); err != nil || !changed {
		t.Errorf("newer: changed=%v err=%v", changed, err)
	}
}

func TestMaxMindFetch401KeepsOldTable(t *testing.T) {
	dir := t.TempDir()
	copyTD(t, dir, "GeoLite2-City-Test.mmdb", "GeoLite2-City.mmdb")
	copyTD(t, dir, "apple.csv", "apple.csv") // unrelated file stays untouched
	srv := newMMServer(t, "GeoLite2-City", mustRead(t, td("GeoLite2-City-Test.mmdb")), t0)
	srv.status = http.StatusUnauthorized
	s := newService(Config{DataDir: dir, Now: fixedNow(t0)})
	s.add(kindMaxMind, newMMSource(srv, "GeoLite2-City", fixedNow(t0)))
	s.loadAllCached()
	if !s.Status()["GeoLite2-City"].Loaded {
		t.Fatal("precondition: loaded")
	}
	before := sum(mustRead(t, filepath.Join(dir, "GeoLite2-City.mmdb")))
	err := s.RefreshAll(context.Background())
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err = %v", err)
	}
	st := s.Status()["GeoLite2-City"]
	if !st.Loaded || !strings.Contains(st.LastError, "401") {
		t.Errorf("status = %+v", st)
	}
	if sum(mustRead(t, filepath.Join(dir, "GeoLite2-City.mmdb"))) != before {
		t.Error("file changed")
	}
}

func TestFetchTruncatedDownloadKeepsOldTable(t *testing.T) {
	dir := t.TempDir()
	copyTD(t, dir, "GeoLite2-ASN-Test.mmdb", "GeoLite2-City.mmdb") // stand-in "old" file
	path := filepath.Join(dir, "GeoLite2-City.mmdb")
	before := sum(mustRead(t, path))
	srv := newMMServer(t, "GeoLite2-City", mustRead(t, td("GeoLite2-City-Test.mmdb")), t0)
	srv.truncate = true
	src := newMMSource(srv, "GeoLite2-City", fixedNow(t0))
	changed, err := src.Fetch(context.Background(), dir)
	if err == nil || changed {
		t.Fatalf("changed=%v err=%v, want error", changed, err)
	}
	if sum(mustRead(t, path)) != before {
		t.Error("old mmdb replaced by truncated download")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*")); len(left) != 0 {
		t.Errorf("temp files left: %v", left)
	}
}

func TestMaxMindFetchChecksumMismatchKeepsOldFile(t *testing.T) {
	dir := t.TempDir()
	copyTD(t, dir, "GeoLite2-ASN-Test.mmdb", "GeoLite2-City.mmdb")
	path := filepath.Join(dir, "GeoLite2-City.mmdb")
	before := sum(mustRead(t, path))
	srv := newMMServer(t, "GeoLite2-City", mustRead(t, td("GeoLite2-City-Test.mmdb")), t0)
	srv.sha = strings.Repeat("0", 64)
	src := newMMSource(srv, "GeoLite2-City", fixedNow(t0))
	if _, err := src.Fetch(context.Background(), dir); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("err = %v", err)
	}
	if sum(mustRead(t, path)) != before {
		t.Error("old mmdb replaced despite bad checksum")
	}
}

func TestPlainSourceConditionalFetch(t *testing.T) {
	body := mustRead(t, td("apple.csv"))
	var gets, conditional int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&gets, 1)
		if r.Header.Get("If-None-Match") == `"v1"` {
			atomic.AddInt32(&conditional, 1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write(body)
	}))
	defer srv.Close()
	dir := t.TempDir()
	src := &appleSource{fetcher: fetcher{client: srv.Client(), now: fixedNow(t0)}, url: srv.URL}
	if changed, err := src.Fetch(context.Background(), dir); err != nil || !changed {
		t.Fatalf("first: changed=%v err=%v", changed, err)
	}
	st, _ := readState(dir, "apple")
	if st.ETag != `"v1"` || st.RowCount != 10 {
		t.Errorf("state = %+v", st)
	}
	if changed, err := src.Fetch(context.Background(), dir); err != nil || changed {
		t.Fatalf("second: changed=%v err=%v", changed, err)
	}
	if conditional != 1 {
		t.Errorf("conditional requests = %d", conditional)
	}
	if _, err := src.Load(dir); err != nil {
		t.Errorf("load: %v", err)
	}
}

func TestPlainSourceRejectsGarbageAndKeepsOldFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>rate limited</html>"))
	}))
	defer srv.Close()
	dir := t.TempDir()
	copyTD(t, dir, "tor.txt", "tor.txt")
	before := sum(mustRead(t, filepath.Join(dir, "tor.txt")))
	src := &torSource{fetcher: fetcher{client: srv.Client(), now: fixedNow(t0)}, url: srv.URL}
	if _, err := src.Fetch(context.Background(), dir); err == nil {
		t.Fatal("want error")
	}
	if sum(mustRead(t, filepath.Join(dir, "tor.txt"))) != before {
		t.Error("tor.txt replaced by garbage")
	}
}

func TestAllSourcesFetchEndToEnd(t *testing.T) {
	files := map[string]string{
		"/apple": "apple.csv", "/tor": "tor.txt", "/dc": "dc-v4.txt", "/vpn": "vpn-v4.txt", "/ja4": "ja4db.json",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(mustRead(t, td(f)))
	}))
	defer srv.Close()
	dir := t.TempDir()
	s, err := New(Config{
		DataDir: dir, HTTPClient: srv.Client(), Now: fixedNow(t0),
		AppleRelayURL: srv.URL + "/apple", TorExitURL: srv.URL + "/tor", JA4DBURL: srv.URL + "/ja4",
		DatacenterURLs: []string{srv.URL + "/dc"}, VPNURLs: []string{srv.URL + "/vpn"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RefreshAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := s.Status()
	for name, rows := range map[string]int{"apple": 10, "tor": 5, "datacenter": 3, "vpn": 3, "ja4db": 2} {
		if !st[name].Loaded || st[name].Rows != rows || st[name].LastError != "" || st[name].Interval == 0 || !st[name].FetchedAt.Equal(t0) {
			t.Errorf("%s status = %+v", name, st[name])
		}
	}
	if !s.Lookup(mustAddr("185.220.101.1")).Tor {
		t.Error("tor lookup after refresh")
	}
	// Status returns a copy.
	st["tor"] = SourceStatus{}
	if !s.Status()["tor"].Loaded {
		t.Error("Status leaked internal map")
	}
	if _, err := os.Stat(statePath(dir, "tor")); err != nil {
		t.Error(err)
	}
}

func TestDisabledSourceSkipped(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	s, err := New(Config{
		DataDir: t.TempDir(), HTTPClient: srv.Client(), Now: fixedNow(t0),
		AppleRelayURL: srv.URL, TorExitURL: srv.URL, JA4DBURL: srv.URL,
		DatacenterURLs: []string{srv.URL}, VPNURLs: []string{srv.URL},
		Disabled:         []string{"Tor", "apple", "datacenter", "vpn", "ja4db", "maxmind"},
		MaxMindAccountID: "1", MaxMindLicenseKey: "k", MaxMindEditions: []string{"GeoLite2-City"},
		MaxMindBaseURL: srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RefreshAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hits != 0 {
		t.Errorf("%d requests made for disabled sources", hits)
	}
	st := s.Status()
	if len(st) != 6 {
		t.Errorf("status has %d entries: %v", len(st), st)
	}
	for name, v := range st {
		if v.Loaded || v.LastError != "disabled" {
			t.Errorf("%s = %+v", name, v)
		}
	}
}

func TestMaxMindSkippedWithoutCredentials(t *testing.T) {
	s, err := New(Config{
		DataDir: t.TempDir(), HTTPClient: noNetClient(), MaxMindEditions: []string{"GeoLite2-City"},
		Disabled: []string{"apple", "tor", "ja4db", "datacenter", "vpn"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RefreshAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := s.Status()["GeoLite2-City"]; st.Loaded || st.LastError != "no credentials" {
		t.Errorf("status = %+v", st)
	}
}
