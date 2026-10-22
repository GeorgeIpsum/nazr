package ipintel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Config configures the Service. Empty URLs fall back to the public
// defaults.
type Config struct {
	DataDir           string
	HTTPClient        *http.Client
	MaxMindAccountID  string
	MaxMindLicenseKey string
	MaxMindEditions   []string
	MaxMindBaseURL    string
	AppleRelayURL     string
	TorExitURL        string
	JA4DBURL          string
	JA4DBToken        string
	DatacenterURLs    []string
	VPNURLs           []string
	// Disabled lists source names (or kinds: maxmind, apple, tor,
	// datacenter, vpn, ja4db) to skip entirely.
	Disabled []string
	Logger   *slog.Logger
	Now      func() time.Time
	// TickInterval is how often the scheduler checks for stale sources.
	// Defaults to one minute.
	TickInterval time.Duration
}

// Lookup is the intelligence known about one address.
//
// Region formats differ by source: MaxMind regions are "<CC>-<subdivision>"
// (for example GB-ENG) while Apple publishes ISO 3166-2 style codes such as
// GB-EN, so a relay address overridden by Apple carries Apple's form. When
// Apple's country differs from MaxMind's, CountryName and the continent
// fields are cleared rather than left describing another country.
type Lookup struct {
	ASN           uint32
	ASOrg         string
	Country       string
	CountryName   string
	ContinentCode string
	ContinentName string
	Region        string
	City          string
	Tor           bool
	VPN           bool
	Datacenter    bool
	PrivateRelay  bool
	// GeoSource is "maxmind", "apple" or "" when no geo data applied.
	GeoSource string
}

// SourceStatus reports the state of one source.
type SourceStatus struct {
	Loaded       bool
	Rows         int
	FetchedAt    time.Time
	LastModified time.Time
	LastError    string
	Interval     time.Duration
}

const (
	kindMaxMind = "maxmind"
	kindApple   = "apple"
	kindTor     = "tor"
	kindJA4DB   = "ja4db"

	retryAfterFailure = 10 * time.Minute
)

type tableHolder struct{ t Table }

type entry struct {
	kind string
	src  Source // nil for sources skipped at construction

	fetchMu     sync.Mutex // held for a whole refresh; prevents concurrent fetches
	mu          sync.Mutex // guards status and lastAttempt; held only briefly
	status      SourceStatus
	lastAttempt time.Time
	tbl         atomic.Pointer[tableHolder]
}

func (e *entry) table() Table {
	if h := e.tbl.Load(); h != nil {
		return h.t
	}
	return nil
}

// Service owns all sources and answers lookups.
type Service struct {
	cfg     Config
	log     *slog.Logger
	entries map[string]*entry
	byKind  map[string][]*entry
	wg      sync.WaitGroup
}

func (c Config) disabled(name, kind string) bool {
	for _, d := range c.Disabled {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" && (d == strings.ToLower(name) || d == kind) {
			return true
		}
	}
	return false
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// New builds a Service from cfg. It performs no I/O.
func New(c Config) (*Service, error) {
	if c.DataDir == "" {
		return nil, errors.New("ipintel: DataDir is required")
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 10 * time.Minute}
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.TickInterval <= 0 {
		c.TickInterval = time.Minute
	}
	f := fetcher{client: c.HTTPClient, now: c.Now}
	s := newService(c)

	for _, ed := range c.MaxMindEditions {
		switch {
		case c.disabled(ed, kindMaxMind):
			s.addSkipped(ed, kindMaxMind, "disabled")
		case c.MaxMindAccountID == "" || c.MaxMindLicenseKey == "":
			s.addSkipped(ed, kindMaxMind, "no credentials")
		default:
			s.add(kindMaxMind, &maxmindSource{
				fetcher: f, edition: ed, accountID: c.MaxMindAccountID, licenseKey: c.MaxMindLicenseKey,
				base: orDefault(c.MaxMindBaseURL, defaultMaxMindBase),
			})
		}
	}
	if c.disabled(kindApple, kindApple) {
		s.addSkipped(kindApple, kindApple, "disabled")
	} else {
		s.add(kindApple, &appleSource{fetcher: f, url: orDefault(c.AppleRelayURL, defaultAppleURL)})
	}
	if c.disabled(kindTor, kindTor) {
		s.addSkipped(kindTor, kindTor, "disabled")
	} else {
		s.add(kindTor, &torSource{fetcher: f, url: orDefault(c.TorExitURL, defaultTorURL)})
	}
	if c.JA4DBURL == "" || c.disabled(kindJA4DB, kindJA4DB) {
		// Opt-in: the FoxIO database requires an account, so no default URL.
		s.addSkipped(kindJA4DB, kindJA4DB, "disabled")
	} else {
		s.add(kindJA4DB, &ja4dbSource{fetcher: f, url: c.JA4DBURL, token: c.JA4DBToken})
	}
	lists := func(kind string, urls, def []string) {
		if len(urls) == 0 {
			urls = def
		}
		for i, u := range urls {
			name := kind
			if i > 0 {
				name = fmt.Sprintf("%s-%d", kind, i+1)
			}
			if c.disabled(name, kind) {
				s.addSkipped(name, kind, "disabled")
				continue
			}
			s.add(kind, &cidrListSource{fetcher: f, kind: kind, name: name, url: u})
		}
	}
	lists(kindDatacenter, c.DatacenterURLs, defaultDatacenterURLs)
	lists(kindVPN, c.VPNURLs, defaultVPNURLs)
	return s, nil
}

func newService(c Config) *Service {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.TickInterval <= 0 {
		c.TickInterval = time.Minute
	}
	return &Service{cfg: c, log: c.Logger, entries: map[string]*entry{}, byKind: map[string][]*entry{}}
}

func (s *Service) add(kind string, src Source) {
	e := &entry{kind: kind, src: src}
	e.status.Interval = src.Interval()
	s.entries[src.Name()] = e
	s.byKind[kind] = append(s.byKind[kind], e)
}

func (s *Service) addSkipped(name, kind, reason string) {
	s.entries[name] = &entry{kind: kind, status: SourceStatus{LastError: reason}}
}

// loadCached parses the cached file of e and swaps it in. Callers hold
// e.fetchMu (or are single-threaded at startup); e.mu is taken only for the
// brief status update so Status never waits on I/O.
func (s *Service) loadCached(e *entry) error {
	t, err := e.src.Load(s.cfg.DataDir)
	if err != nil {
		return err
	}
	st, hasState := readState(s.cfg.DataDir, e.src.Name())
	e.tbl.Store(&tableHolder{t: t})
	e.mu.Lock()
	defer e.mu.Unlock()
	e.status.Loaded = true
	if rc, ok := t.(rowCounter); ok {
		e.status.Rows = rc.Rows()
	}
	if hasState {
		e.status.FetchedAt = st.FetchedAt
		e.status.LastModified = st.LastModified
		if st.RowCount > 0 {
			e.status.Rows = st.RowCount
		}
	}
	return nil
}

func (s *Service) ensureDataDir() error {
	if err := os.MkdirAll(s.cfg.DataDir, 0o755); err != nil {
		return fmt.Errorf("ipintel: create data dir: %w", err)
	}
	return nil
}

// Start loads every cached file, then refreshes stale sources in the
// background until ctx is cancelled.
func (s *Service) Start(ctx context.Context) {
	if err := s.ensureDataDir(); err != nil {
		s.log.Error("ipintel: data dir unavailable", "err", err)
	}
	s.loadAllCached()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.tick(ctx)
		t := time.NewTicker(s.cfg.TickInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.tick(ctx)
			}
		}
	}()
}

func (s *Service) loadAllCached() {
	for name, e := range s.entries {
		if e.src == nil {
			continue
		}
		if err := s.loadCached(e); err != nil {
			s.log.Info("ipintel: no cached data", "source", name, "err", err)
		}
	}
}

// Wait blocks until the background loop started by Start has exited.
func (s *Service) Wait() { s.wg.Wait() }

// tick refreshes every stale source concurrently, so one hung source
// cannot delay the others. A source already being fetched is skipped.
func (s *Service) tick(ctx context.Context) {
	var wg sync.WaitGroup
	for _, e := range s.entries {
		if e.src == nil || ctx.Err() != nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !e.fetchMu.TryLock() {
				return
			}
			defer e.fetchMu.Unlock()
			now := s.cfg.Now()
			e.mu.Lock()
			due := !e.status.FetchedAt.Add(e.src.Interval()).After(now) &&
				!e.lastAttempt.Add(retryAfterFailure).After(now)
			e.mu.Unlock()
			if due {
				_ = s.refresh(ctx, e)
			}
		}()
	}
	wg.Wait()
}

// refresh fetches and, when data changed, swaps the table. Callers hold
// e.fetchMu. On failure the previous table stays in place.
func (s *Service) refresh(ctx context.Context, e *entry) error {
	name := e.src.Name()
	e.mu.Lock()
	e.lastAttempt = s.cfg.Now()
	e.mu.Unlock()
	changed, err := e.src.Fetch(ctx, s.cfg.DataDir)
	if err == nil && (changed || e.table() == nil) {
		err = s.loadCached(e)
	} else if err == nil {
		if st, ok := readState(s.cfg.DataDir, name); ok {
			e.mu.Lock()
			e.status.FetchedAt = st.FetchedAt
			e.status.LastModified = st.LastModified
			e.mu.Unlock()
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err != nil {
		e.status.LastError = err.Error()
		s.log.Warn("ipintel: refresh failed", "source", name, "err", err)
		return fmt.Errorf("%s: %w", name, err)
	}
	e.status.FetchedAt = s.cfg.Now()
	e.status.LastError = ""
	return nil
}

// RefreshAll fetches every source regardless of age, concurrently. A source
// with a fetch already in flight is waited for, never run twice at once.
func (s *Service) RefreshAll(ctx context.Context) error {
	if err := s.ensureDataDir(); err != nil {
		return err
	}
	var (
		wg   sync.WaitGroup
		emu  sync.Mutex
		errs []error
	)
	for _, e := range s.entries {
		if e.src == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.fetchMu.Lock()
			defer e.fetchMu.Unlock()
			if err := s.refresh(ctx, e); err != nil {
				emu.Lock()
				errs = append(errs, err)
				emu.Unlock()
			}
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

// Status returns a snapshot of every source, keyed by name.
func (s *Service) Status() map[string]SourceStatus {
	out := make(map[string]SourceStatus, len(s.entries))
	for name, e := range s.entries {
		e.mu.Lock()
		out[name] = e.status
		e.mu.Unlock()
	}
	return out
}

// Lookup returns what is known about addr. It is safe to call before any
// source has loaded (the result is then zero).
func (s *Service) Lookup(addr netip.Addr) Lookup {
	var l Lookup
	addr = addr.Unmap()
	if !addr.IsValid() {
		return l
	}
	for _, e := range s.byKind[kindMaxMind] {
		t, ok := e.table().(*MaxMindTable)
		if !ok {
			continue
		}
		rec, found := t.Lookup(addr)
		if !found {
			continue
		}
		if rec.ASN != 0 && l.ASN == 0 {
			l.ASN, l.ASOrg = rec.ASN, rec.ASOrg
		}
		if rec.Country.ISOCode != "" && l.GeoSource == "" {
			l.GeoSource = "maxmind"
			l.Country = rec.Country.ISOCode
			l.CountryName = rec.Country.Names["en"]
			l.ContinentCode = rec.Continent.Code
			l.ContinentName = rec.Continent.Names["en"]
			l.City = rec.City.Names["en"]
			if len(rec.Subdivisions) > 0 && rec.Subdivisions[0].ISOCode != "" {
				l.Region = rec.Country.ISOCode + "-" + rec.Subdivisions[0].ISOCode
			}
		}
	}
	for _, e := range s.byKind[kindApple] {
		if t, ok := e.table().(*PrefixTable[relayEntry]); ok {
			if r, hit := t.Lookup(addr); hit {
				l.PrivateRelay = true
				l.GeoSource = "apple"
				if l.Country != r.Country {
					l.CountryName, l.ContinentCode, l.ContinentName = "", "", ""
				}
				l.Country, l.Region, l.City = r.Country, r.Region, r.City
			}
		}
	}
	l.Tor = s.inList(kindTor, addr)
	l.Datacenter = s.inList(kindDatacenter, addr)
	l.VPN = s.inList(kindVPN, addr)
	return l
}

func (s *Service) inList(kind string, addr netip.Addr) bool {
	for _, e := range s.byKind[kind] {
		if t, ok := e.table().(*PrefixTable[struct{}]); ok {
			if _, hit := t.Lookup(addr); hit {
				return true
			}
		}
	}
	return false
}

// JA4Families returns the application names FoxIO's database lists for a
// JA4 fingerprint; never nil.
func (s *Service) JA4Families(ja4 string) []string {
	for _, e := range s.byKind[kindJA4DB] {
		if t, ok := e.table().(*JA4Table); ok {
			return t.Families(ja4)
		}
	}
	return []string{}
}
