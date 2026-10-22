package visitor

import (
	"context"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	"nazr/api/internal/store"
)

type fakeRepo struct {
	visitors  map[string]*store.Visitor // key: keyID+"/"+id
	marks     map[string]time.Time      // keyID/thumbmark -> last seen
	markVis   map[string]string         // keyID/thumbmark -> visitor id
	recorded  int
	findCalls int
}

func newFake() *fakeRepo {
	return &fakeRepo{visitors: map[string]*store.Visitor{}, marks: map[string]time.Time{}, markVis: map[string]string{}}
}

func (f *fakeRepo) seed(keyID, id, thumb string, seen time.Time) {
	f.visitors[keyID+"/"+id] = &store.Visitor{ID: id, APIKeyID: keyID, FirstSeen: seen, LastSeen: seen}
	f.marks[keyID+"/"+thumb] = seen
	f.markVis[keyID+"/"+thumb] = id
}

func (f *fakeRepo) GetVisitor(_ context.Context, keyID, id string) (*store.Visitor, error) {
	return f.visitors[keyID+"/"+id], nil
}

func (f *fakeRepo) FindVisitorByThumbmark(_ context.Context, keyID, thumb string, since time.Time) (*store.Visitor, error) {
	f.findCalls++
	k := keyID + "/" + thumb
	if seen, ok := f.marks[k]; ok && !seen.Before(since) {
		return f.visitors[keyID+"/"+f.markVis[k]], nil
	}
	return nil, nil
}

func (f *fakeRepo) CreateVisitor(_ context.Context, keyID, id string, now time.Time) (*store.Visitor, error) {
	v := &store.Visitor{ID: id, APIKeyID: keyID, FirstSeen: now, LastSeen: now}
	f.visitors[keyID+"/"+id] = v
	return v, nil
}

func (f *fakeRepo) RecordVisit(_ context.Context, keyID, id, thumb string, now time.Time) (int64, int64, error) {
	f.recorded++
	f.visitors[keyID+"/"+id].LastSeen = now
	f.marks[keyID+"/"+thumb] = now
	f.markVis[keyID+"/"+thumb] = id
	return 1, int64(len(f.visitors)), nil
}

var t0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func newResolver(f *fakeRepo) *Resolver {
	return &Resolver{Repo: f, Window: 720 * time.Hour, Now: func() time.Time { return t0 },
		NewID: func() string { return "01NEWVISITOR000000000000AA" }}
}

func TestResolveReusesBodyID(t *testing.T) {
	f := newFake()
	id := ulid.Make().String()
	f.seed("k1", id, "mine", t0.Add(-time.Hour))
	other := ulid.Make().String()
	f.seed("k1", other, "tm", t0.Add(-time.Minute))
	res, err := newResolver(f).Resolve(context.Background(), "k1", id, "tm")
	if err != nil {
		t.Fatal(err)
	}
	if f.findCalls != 0 {
		t.Fatal("thumbmark lookup must not run when the body id matches")
	}
	if res.ID != id || res.IsNew || !res.LastSeen.Equal(t0) || res.Sharing != 1 || res.Total != 2 {
		t.Fatalf("%+v", res)
	}
	if !res.FirstSeen.Equal(t0.Add(-time.Hour)) {
		t.Fatalf("first seen %v", res.FirstSeen)
	}
}

func TestResolveIgnoresForeignOrMalformedID(t *testing.T) {
	f := newFake()
	foreign := ulid.Make().String()
	f.seed("other-key", foreign, "tm", t0)
	for _, body := range []string{foreign, "not-a-ulid", "", ulid.Make().String(), "01arz3ndektsv4rrffq69g5fav"} {
		res, err := newResolver(f).Resolve(context.Background(), "k1", body, "tm-x")
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsNew || res.ID != "01NEWVISITOR000000000000AA" {
			t.Fatalf("body %q: expected fresh visitor, got %+v", body, res)
		}
		delete(f.visitors, "k1/01NEWVISITOR000000000000AA")
		delete(f.marks, "k1/tm-x")
	}
}

func TestResolveMatchesThumbmarkInWindow(t *testing.T) {
	f := newFake()
	id := ulid.Make().String()
	f.seed("k1", id, "tm", t0.Add(-24*time.Hour))
	res, err := newResolver(f).Resolve(context.Background(), "k1", "", "tm")
	if err != nil {
		t.Fatal(err)
	}
	if res.ID != id || res.IsNew {
		t.Fatalf("%+v", res)
	}
}

func TestResolveCreatesNewOutsideWindow(t *testing.T) {
	f := newFake()
	id := ulid.Make().String()
	f.seed("k1", id, "tm", t0.Add(-721*time.Hour))
	res, err := newResolver(f).Resolve(context.Background(), "k1", "", "tm")
	if err != nil {
		t.Fatal(err)
	}
	if res.ID == id || !res.IsNew || !res.FirstSeen.Equal(t0) {
		t.Fatalf("%+v", res)
	}
	if f.recorded != 1 {
		t.Fatalf("recorded %d", f.recorded)
	}
}

func TestUniqueness(t *testing.T) {
	tests := []struct {
		sharing, total int64
		want           float64
	}{
		{1, 1, 1}, {1, 100, 1}, {2, 100, 0.99}, {50, 100, 0.51}, {0, 0, 1}, {101, 100, 0},
		{1, 3, 1}, {2, 3, 0.6667},
	}
	for _, tc := range tests {
		if got := Uniqueness(tc.sharing, tc.total); got != tc.want {
			t.Errorf("Uniqueness(%d,%d)=%v want %v", tc.sharing, tc.total, got, tc.want)
		}
	}
}
