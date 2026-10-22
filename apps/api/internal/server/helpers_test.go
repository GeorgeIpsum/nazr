package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"nazr/api/internal/auth"
	"nazr/api/internal/config"
	"nazr/api/internal/conn"
	"nazr/api/internal/fingerprint"
	"nazr/api/internal/h2fp"
	"nazr/api/internal/ipintel"
	"nazr/api/internal/store"
	"nazr/api/internal/tlsfp"
	"nazr/api/internal/visitor"
)

// ---- fake store ----

type fakeStore struct {
	mu         sync.Mutex
	findCalls  int
	keys       map[string]*store.APIKey // by hash
	byID       map[string]*store.APIKey
	events     []store.Event
	obs        [][2]string
	logs       []json.RawMessage
	logKeys    []*string
	revoked    []string
	pingErr    error
	panicPing  bool
	uaFamilies []string
	uaQueries  []string
	seq        int
}

func newFakeStore() *fakeStore {
	return &fakeStore{keys: map[string]*store.APIKey{}, byID: map[string]*store.APIKey{}}
}

func (f *fakeStore) addKey(hash string, k *store.APIKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[hash] = k
	f.byID[k.ID] = k
}

func (f *fakeStore) Ping(context.Context) error {
	f.mu.Lock()
	p, err := f.panicPing, f.pingErr
	f.mu.Unlock()
	if p {
		panic("fake store exploded")
	}
	return err
}

func (f *fakeStore) FindKeyByHash(_ context.Context, hash string) (*store.APIKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.findCalls++
	return f.keys[hash], nil
}

func (f *fakeStore) TouchKey(context.Context, string) error { return nil }

func (f *fakeStore) InsertEvent(_ context.Context, e store.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
	return nil
}

func (f *fakeStore) RecordUAJA4(_ context.Context, ja4, family string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.obs = append(f.obs, [2]string{ja4, family})
	return nil
}

func (f *fakeStore) UAJA4Families(_ context.Context, ja4 string, _ int) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.uaQueries = append(f.uaQueries, ja4)
	return f.uaFamilies, nil
}

func (f *fakeStore) InsertClientLog(_ context.Context, keyID *string, body json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logs = append(f.logs, body)
	f.logKeys = append(f.logKeys, keyID)
	return nil
}

func (f *fakeStore) CreateKey(_ context.Context, n store.NewKey) (store.APIKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	k := &store.APIKey{
		ID: "00000000-0000-4000-8000-00000000000" + string(rune('0'+f.seq)), Prefix: n.Prefix, Label: n.Label,
		AllowedOrigins: n.AllowedOrigins, RateLimitPerMinute: n.RateLimitPerMinute,
		CreatedAt: time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC),
	}
	f.keys[n.Hash] = k
	f.byID[k.ID] = k
	return *k, nil
}

func (f *fakeStore) ListKeys(context.Context) ([]store.APIKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.APIKey
	for _, k := range f.byID {
		out = append(out, *k)
	}
	return out, nil
}

func (f *fakeStore) RevokeKey(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.byID[id]
	if !ok {
		return store.ErrNotFound
	}
	now := time.Now()
	k.RevokedAt = &now
	f.revoked = append(f.revoked, id)
	return nil
}

// ---- fake intel ----

type fakeIntel struct {
	lookup   ipintel.Lookup
	families map[string][]string
	status   map[string]ipintel.SourceStatus
}

func (f *fakeIntel) Lookup(netip.Addr) ipintel.Lookup { return f.lookup }
func (f *fakeIntel) JA4Families(ja4 string) []string {
	if v := f.families[ja4]; v != nil {
		return v
	}
	return []string{}
}
func (f *fakeIntel) Status() map[string]ipintel.SourceStatus { return f.status }

// ---- fake visitor repo ----

type fakeRepo struct {
	mu       sync.Mutex
	visitors map[string]*store.Visitor
	marks    map[string]string
	err      error
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{visitors: map[string]*store.Visitor{}, marks: map[string]string{}}
}

func (f *fakeRepo) GetVisitor(_ context.Context, keyID, id string) (*store.Visitor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	if v, ok := f.visitors[keyID+"/"+id]; ok {
		c := *v
		return &c, nil
	}
	return nil, nil
}

func (f *fakeRepo) FindVisitorByThumbmark(_ context.Context, keyID, thumb string, _ time.Time) (*store.Visitor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	if id, ok := f.marks[keyID+"/"+thumb]; ok {
		c := *f.visitors[keyID+"/"+id]
		return &c, nil
	}
	return nil, nil
}

func (f *fakeRepo) CreateVisitor(_ context.Context, keyID, id string, now time.Time) (*store.Visitor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := &store.Visitor{ID: id, APIKeyID: keyID, FirstSeen: now, LastSeen: now}
	f.visitors[keyID+"/"+id] = v
	c := *v
	return &c, nil
}

func (f *fakeRepo) RecordVisit(_ context.Context, keyID, id, thumb string, now time.Time) (int64, int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.visitors[keyID+"/"+id].LastSeen = now
	f.marks[keyID+"/"+thumb] = id
	return 1, int64(len(f.visitors)), nil
}

// ---- environment ----

var testNow = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

const (
	chromeUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	keyID    = "11111111-1111-4111-8111-111111111111"
	visID    = "01JBX7Y9Z0ABCDEFGHJKMNPQRS"
)

type env struct {
	t     *testing.T
	store *fakeStore
	intel *fakeIntel
	repo  *fakeRepo
	cfg   config.Config
	key   string
	rand  float64
	h     http.Handler
}

func defaultConfig(t *testing.T) config.Config {
	t.Helper()
	cfg, err := config.Load(func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	cfg.IPHashSalt = "salt"
	return cfg
}

func newEnv(t *testing.T, mut func(c *config.Config, s *fakeStore)) *env {
	t.Helper()
	return newEnvCache(t, mut, nil)
}

// newEnvCache is newEnv with a key cache wired into the server.
func newEnvCache(t *testing.T, mut func(c *config.Config, s *fakeStore), cache *auth.KeyCache) *env {
	t.Helper()
	e := &env{t: t, store: newFakeStore(), repo: newFakeRepo(), cfg: defaultConfig(t), rand: 1,
		intel: &fakeIntel{
			lookup: ipintel.Lookup{ASN: 64496, ASOrg: "Example Networks", Country: "US", CountryName: "United States",
				ContinentCode: "NA", ContinentName: "North America", Region: "US-NY", City: "New York"},
			families: map[string][]string{},
			status:   map[string]ipintel.SourceStatus{},
		}}
	plain, hash, prefix := auth.GenerateKey()
	e.key = plain
	e.store.addKey(hash, &store.APIKey{ID: keyID, Prefix: prefix, Label: "test"})
	if mut != nil {
		mut(&e.cfg, e.store)
	}
	ids := 0
	e.h = New(Deps{
		Cfg: e.cfg, Store: e.store, Intel: e.intel,
		Resolver: &visitor.Resolver{Repo: e.repo, Window: e.cfg.VisitorMatchWindow, Now: func() time.Time { return testNow },
			NewID: func() string { ids++; return visID[:24] + string(rune('A'+ids)) + "Z" }},
		Limiter: auth.NewMemoryLimiter(time.Now), KeyCache: cache,
		Logger: slog.New(slog.DiscardHandler), Version: "test-1.0", Now: func() time.Time { return testNow }, Rand: func() float64 { return e.rand },
	})
	return e
}

func (e *env) do(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func stockBody(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile("../../testdata/requests/stock-client-body.json")
	if err != nil {
		t.Fatal(err)
	}
	m, err := fingerprint.Decode(bytes.NewReader(b), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func thumbmarkReq(t *testing.T, key string, body []byte) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/thumbmark", bytes.NewReader(body))
	r.RemoteAddr = "203.0.113.42:5555"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", chromeUA)
	r.Header.Set("Accept", "*/*")
	r.Header.Set("Accept-Language", "en-US,en;q=0.9")
	r.Header.Set("Accept-Encoding", "gzip, deflate, br")
	r.Header.Set("Authorization", "custom-authorized")
	if key != "" {
		r.Header.Set("x-api-key", key)
	}
	return r
}

func decodeResp(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	m, err := fingerprint.Decode(bytes.NewReader(w.Body.Bytes()), 1<<22)
	if err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return m
}

func path(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

func wantError(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status %d want %d: %s", w.Code, status, w.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body %q: %v", w.Body.String(), err)
	}
	if body["error"] != code || body["message"] == "" {
		t.Fatalf("error body %v want code %q", body, code)
	}
}

// ---- real fingerprint inputs ----

func goTLSResult(t *testing.T) *tlsfp.Result {
	t.Helper()
	c, s := net.Pipe()
	defer s.Close()
	go func() {
		cl := tls.Client(c, &tls.Config{ServerName: "example.com", NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: true})
		_ = cl.Handshake()
	}()
	_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, hs, err := tlsfp.ReadClientHello(s)
	_ = c.Close()
	if err != nil {
		t.Fatal(err)
	}
	ch, err := tlsfp.Parse(hs)
	if err != nil {
		t.Fatal(err)
	}
	res := tlsfp.Fingerprint(ch, 't')
	return &res
}

func chromeH2() *h2fp.Result {
	r := &h2fp.Result{
		Settings:          []h2fp.Setting{{ID: 1, Value: 65536}, {ID: 2, Value: 0}, {ID: 4, Value: 6291456}, {ID: 6, Value: 262144}},
		WindowUpdate:      15663105,
		PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
	}
	r.Fingerprint = h2fp.Akamai(r)
	return r
}

var testHeaderOrder = []string{"Host", "Content-Length", "User-Agent", "Content-Type", "Accept", "Accept-Encoding", "Accept-Language", "Authorization", "X-Api-Key"}

// fullHolder returns a holder with TLS and h2 captures and one queued header
// order: testHeaderOrder, which matches a thumbmarkReq carrying an API key.
func fullHolder(t *testing.T) *conn.Holder { return fullHolderOrder(t, testHeaderOrder) }

func fullHolderOrder(t *testing.T, order []string) *conn.Holder {
	h := &conn.Holder{TLS: goTLSResult(t), H2: chromeH2(),
		RemoteAddr: netip.MustParseAddrPort("203.0.113.42:5555")}
	h.PushOrder(http.MethodPost, order)
	return h
}

// filterLikeClient mirrors the client's filterThumbmarkData over the API
// components: the browser for the stabilization rules is the client's.
func filterLikeClient(server, client map[string]any, opts fingerprint.Options) map[string]any {
	in := map[string]any{}
	for k, v := range server {
		in[k] = v
	}
	in["system"] = client["system"]
	out := fingerprint.Filter(in, opts)
	delete(out, "system")
	return out
}

var errBoom = errors.New("boom")
