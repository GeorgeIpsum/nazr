package ipintel

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

type fakeSource struct {
	name     string
	interval time.Duration
	mu       sync.Mutex
	fetches  int
	err      error
}

func (f *fakeSource) Name() string            { return f.name }
func (f *fakeSource) Interval() time.Duration { return f.interval }
func (f *fakeSource) Fetch(ctx context.Context, dir string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetches++
	return true, f.err
}
func (f *fakeSource) Load(dir string) (Table, error) { return &PrefixTable[struct{}]{}, nil }
func (f *fakeSource) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetches
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestSchedulerRespectsInterval(t *testing.T) {
	clk := &clock{t: t0}
	src := &fakeSource{name: "fake", interval: time.Hour}
	s := newService(Config{DataDir: t.TempDir(), Now: clk.now})
	s.add(kindTor, src)
	ctx := context.Background()

	s.tick(ctx) // never fetched -> due
	if src.count() != 1 {
		t.Fatalf("t0 fetches = %d", src.count())
	}
	if st := s.Status()["fake"]; !st.Loaded {
		t.Errorf("status = %+v", st)
	}
	clk.advance(30 * time.Minute)
	s.tick(ctx)
	if src.count() != 1 {
		t.Errorf("t0+30m fetches = %d, want 1", src.count())
	}
	clk.advance(31 * time.Minute)
	s.tick(ctx)
	if src.count() != 2 {
		t.Errorf("t0+61m fetches = %d, want 2", src.count())
	}
}

func TestSchedulerKeepsTableAndBacksOffOnError(t *testing.T) {
	clk := &clock{t: t0}
	src := &fakeSource{name: "fake", interval: time.Hour}
	s := newService(Config{DataDir: t.TempDir(), Now: clk.now})
	s.add(kindTor, src)
	ctx := context.Background()
	s.tick(ctx)
	clk.advance(61 * time.Minute)
	src.err = context.DeadlineExceeded
	s.tick(ctx)
	st := s.Status()["fake"]
	if !st.Loaded || st.LastError == "" || src.count() != 2 {
		t.Errorf("status = %+v fetches=%d", st, src.count())
	}
	clk.advance(time.Minute) // within retry backoff: no hammering
	s.tick(ctx)
	if src.count() != 2 {
		t.Errorf("retried too soon: %d", src.count())
	}
	clk.advance(10 * time.Minute)
	src.err = nil
	s.tick(ctx)
	if st := s.Status()["fake"]; src.count() != 3 || st.LastError != "" {
		t.Errorf("recovery: status=%+v fetches=%d", st, src.count())
	}
}

func TestSchedulerStopsOnContextCancel(t *testing.T) {
	src := &fakeSource{name: "fake", interval: time.Millisecond}
	s := newService(Config{DataDir: t.TempDir(), TickInterval: time.Millisecond})
	s.add(kindTor, src)
	ctx, cancel := context.WithCancel(context.Background())
	s.Start(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for src.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if src.count() == 0 {
		t.Fatal("background loop never fetched")
	}
	cancel()
	done := make(chan struct{})
	go func() { s.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler goroutine did not stop")
	}
	n := src.count()
	time.Sleep(20 * time.Millisecond)
	if src.count() != n {
		t.Error("fetches continued after cancel")
	}
}

func TestSchedulerExponentialBackoffCappedAtInterval(t *testing.T) {
	clk := &clock{t: t0}
	src := &fakeSource{name: "fake", interval: 6 * time.Hour, err: context.DeadlineExceeded}
	s := newService(Config{DataDir: t.TempDir(), Now: clk.now})
	s.add(kindTor, src)
	ctx := context.Background()
	s.tick(ctx) // failure 1 at t0: next retry +10m
	// Each step: just before the delay nothing happens; at the delay one
	// more fetch fails and the delay doubles, until it reaches the interval.
	for i, d := range []time.Duration{10 * time.Minute, 20 * time.Minute, 40 * time.Minute, 80 * time.Minute, 160 * time.Minute, 320 * time.Minute, 6 * time.Hour, 6 * time.Hour} {
		n := src.count()
		clk.advance(d - time.Second)
		s.tick(ctx)
		if src.count() != n {
			t.Fatalf("step %d: retried before %v", i, d)
		}
		clk.advance(time.Second)
		s.tick(ctx)
		if src.count() != n+1 {
			t.Fatalf("step %d: no retry after %v (fetches %d)", i, d, src.count())
		}
	}
	src.mu.Lock()
	src.err = nil
	src.mu.Unlock()
	clk.advance(6 * time.Hour)
	s.tick(ctx)
	if st := s.Status()["fake"]; st.LastError != "" {
		t.Fatalf("not recovered: %+v", st)
	}
	// After a success the backoff starts over at 10 minutes.
	src.mu.Lock()
	src.err = context.DeadlineExceeded
	src.mu.Unlock()
	clk.advance(6 * time.Hour)
	s.tick(ctx)
	n := src.count()
	clk.advance(10 * time.Minute)
	s.tick(ctx)
	if src.count() != n+1 {
		t.Fatal("backoff not reset after success")
	}
}

func TestSchedulerThrottledWaitsFullInterval(t *testing.T) {
	for _, code := range []int{429, 403} {
		clk := &clock{t: t0}
		src := &fakeSource{name: "fake", interval: 6 * time.Hour,
			err: fmt.Errorf("wrapped: %w", &StatusError{Op: "fake: unexpected status", Code: code})}
		s := newService(Config{DataDir: t.TempDir(), Now: clk.now})
		s.add(kindTor, src)
		ctx := context.Background()
		s.tick(ctx)
		clk.advance(6*time.Hour - time.Second)
		s.tick(ctx)
		if src.count() != 1 {
			t.Fatalf("%d: retried within the interval (%d fetches)", code, src.count())
		}
		clk.advance(time.Second)
		s.tick(ctx)
		if src.count() != 2 {
			t.Fatalf("%d: no retry after the interval", code)
		}
		if st := s.Status()["fake"]; st.LastError != fmt.Sprintf("wrapped: fake: unexpected status %d", code) {
			t.Fatalf("last error %q", st.LastError)
		}
	}
}
