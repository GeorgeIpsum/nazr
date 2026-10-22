package main

import (
	"context"
	crand "crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oklog/ulid/v2"

	"nazr/api/internal/auth"
	"nazr/api/internal/certs"
	"nazr/api/internal/config"
	"nazr/api/internal/conn"
	"nazr/api/internal/ipintel"
	"nazr/api/internal/server"
	"nazr/api/internal/store"
	"nazr/api/internal/version"
	"nazr/api/internal/visitor"
)

const (
	shutdownTimeout = 15 * time.Second
	pruneInterval   = time.Hour
	pruneBatch      = 10000
	h2FrameLimit    = 65536
)

func newLogger(cfg config.Config, w io.Writer) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if cfg.LogFormat == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}

func newIntel(cfg config.Config, logger *slog.Logger) (*ipintel.Service, error) {
	return ipintel.New(ipintel.Config{
		DataDir:           cfg.DataDir,
		MaxMindAccountID:  cfg.MaxMindAccountID,
		MaxMindLicenseKey: cfg.MaxMindLicenseKey,
		MaxMindEditions:   cfg.MaxMindEditions,
		AppleRelayURL:     cfg.AppleRelayURL,
		TorExitURL:        cfg.TorExitURL,
		DatacenterURLs:    cfg.DatacenterURLs,
		VPNURLs:           cfg.VPNURLs,
		JA4DBURL:          cfg.JA4DBURL,
		JA4DBToken:        cfg.JA4DBToken,
		Disabled:          cfg.ListsDisable,
		Logger:            logger,
	})
}

func newULID() string {
	return strings.ToUpper(ulid.MustNew(ulid.Timestamp(time.Now()), crand.Reader).String())
}

func serve(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	printConfig := fs.Bool("print-config", false, "print the effective configuration (secrets redacted) and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(os.LookupEnv)
	if err != nil {
		fmt.Fprintln(stderr, "nazr:", err)
		return 1
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(stderr, "nazr:", err)
		return 1
	}
	if *printConfig {
		red := cfg.Redacted()
		keys := make([]string, 0, len(red))
		for k := range red {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			fmt.Fprintf(stdout, "%s=%s\n", k, red[k])
		}
		return 0
	}
	if err := runServer(cfg, stderr); err != nil {
		fmt.Fprintln(stderr, "nazr:", err)
		return 1
	}
	return 0
}

func runServer(cfg config.Config, logw io.Writer) error {
	logger := newLogger(cfg, logw)
	logger.Debug("effective config", "config", cfg.Redacted())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if cfg.DatabaseURL == "" {
		return errors.New("NAZR_DATABASE_URL is required")
	}
	st, err := store.Open(ctx, cfg.DatabaseURL, cfg.RedisURL)
	if err != nil {
		return err
	}
	defer st.Close()
	if cfg.AutoMigrate {
		if err := st.Migrate(ctx); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}

	intel, err := newIntel(cfg, logger)
	if err != nil {
		return err
	}
	// ctx cancellation stops the intel background loops; Wait below proves
	// they have exited.
	intel.Start(ctx)
	defer func() { stop(); intel.Wait() }()

	var limiter auth.Limiter
	if rdb := st.Redis(); rdb != nil {
		limiter = auth.NewRedisLimiter(rdb)
	} else {
		limiter = auth.NewMemoryLimiter(time.Now)
	}
	keyCache := auth.NewKeyCache(60*time.Second, st.Redis())
	resolver := &visitor.Resolver{Repo: st, Window: cfg.VisitorMatchWindow, Now: time.Now, NewID: newULID}

	handler := server.New(server.Deps{
		Cfg: cfg, Store: st, Intel: intel, Resolver: resolver, Limiter: limiter,
		KeyCache: keyCache, Logger: logger, Version: version.Version,
		Now: time.Now, Rand: rand.Float64,
	})

	tlsCfg, acme, err := certs.Setup(ctx, cfg, logger)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return err
	}
	ln = conn.Listen(ln, conn.Options{ProxyProtocol: cfg.ProxyProtocol, TLSConfig: tlsCfg, CaptureH2: tlsCfg != nil})

	// The timeouts are mandatory: conn does the TLS handshake and ClientHello
	// capture lazily on first read, so without ReadHeaderTimeout a client that
	// connects and goes silent (slowloris) would hold a goroutine and a file
	// descriptor forever. Header size is capped well above real browser
	// headers but far below net/http's 1 MiB default.
	pub := &http.Server{
		Handler:           handler,
		ConnContext:       conn.ConnContext,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	if tlsCfg != nil {
		if err := conn.ConfigureServer(pub, h2FrameLimit); err != nil {
			return err
		}
	}

	servers := []*http.Server{pub}
	var wg sync.WaitGroup
	errc := make(chan error, 4)
	run := func(srv *http.Server, l net.Listener, name string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Info("listening", "server", name, "addr", l.Addr().String())
			if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s server: %w", name, err)
			}
		}()
	}
	run(pub, ln, "public")

	switch {
	case cfg.HTTPAddr != "" && cfg.TLSMode == "terminate":
		hl, err := net.Listen("tcp", cfg.HTTPAddr)
		if err != nil {
			_ = ln.Close()
			return err
		}
		hs := &http.Server{
			Handler:           certs.HTTPHandler(acme, ""),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    64 << 10,
		}
		servers = append(servers, hs)
		run(hs, hl, "http")
	case cfg.HTTPAddr != "":
		logger.Info("NAZR_HTTP_ADDR is ignored unless NAZR_TLS_MODE=terminate", "http_addr", cfg.HTTPAddr)
	}

	if cfg.MetricsAddr != "" {
		ml, err := net.Listen("tcp", cfg.MetricsAddr)
		if err != nil {
			stop()
			shutdown(servers, logger)
			wg.Wait()
			return err
		}
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", server.NewMetricsHandler())
		ms := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
		servers = append(servers, ms)
		run(ms, ml, "metrics")
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		retention(ctx, st, cfg, logger)
	}()

	var runErr error
	select {
	case <-ctx.Done():
		logger.Info("shutting down")
	case runErr = <-errc:
		stop()
	}
	shutdown(servers, logger)
	wg.Wait()
	return runErr
}

// shutdown drains every server concurrently within shutdownTimeout.
func shutdown(servers []*http.Server, logger *slog.Logger) {
	sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	var wg sync.WaitGroup
	for _, s := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Shutdown(sctx); err != nil {
				logger.Error("shutdown", "err", err)
				_ = s.Close()
			}
		}()
	}
	wg.Wait()
}

// retention prunes old events (and client logs when LogRetention is set)
// hourly. A zero retention disables that table: Prune with a zero cutoff
// deletes nothing.
func retention(ctx context.Context, st *store.Store, cfg config.Config, logger *slog.Logger) {
	prune := func() {
		now := time.Now()
		var events, logs time.Time
		if cfg.EventRetention > 0 {
			events = now.Add(-cfg.EventRetention)
		}
		if cfg.LogRetention > 0 {
			logs = now.Add(-cfg.LogRetention)
		}
		n, err := st.Prune(ctx, events, logs, pruneBatch)
		if err != nil && ctx.Err() == nil {
			logger.Error("retention prune failed", "err", err)
		} else if n > 0 {
			logger.Info("retention pruned rows", "rows", n)
		}
	}
	prune()
	t := time.NewTicker(pruneInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			prune()
		}
	}
}
