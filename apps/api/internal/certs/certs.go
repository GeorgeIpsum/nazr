// Package certs builds the server's TLS configuration from inline PEM,
// on-disk files (reloaded on SIGHUP and periodically) or ACME.
package certs

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"nazr/api/internal/config"
)

// reloadInterval is how often file-backed certificates are re-read, in
// addition to SIGHUP.
const reloadInterval = 12 * time.Hour

// Load returns the TLS config for cfg: nil, nil unless TLSMode is "terminate".
// Precedence is inline PEM, then files, then ACME. Background reloading stops
// when ctx is cancelled.
func Load(ctx context.Context, cfg config.Config, logger *slog.Logger) (*tls.Config, error) {
	tc, _, err := Setup(ctx, cfg, logger)
	return tc, err
}

// Setup is Load that also returns the autocert manager when ACME is active
// (nil otherwise), so the caller can serve HTTP-01 challenges.
func Setup(ctx context.Context, cfg config.Config, logger *slog.Logger) (*tls.Config, *autocert.Manager, error) {
	if cfg.TLSMode != "terminate" {
		return nil, nil, nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	base := &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	}
	switch {
	case cfg.TLSCertPEM != "" && cfg.TLSKeyPEM != "":
		c, err := tls.X509KeyPair([]byte(cfg.TLSCertPEM), []byte(cfg.TLSKeyPEM))
		if err != nil {
			return nil, nil, errors.New("certs: invalid inline TLS certificate/key: " + err.Error())
		}
		base.Certificates = []tls.Certificate{c}
		return base, nil, nil
	case cfg.TLSCertFile != "" && cfg.TLSKeyFile != "":
		var cur atomic.Pointer[tls.Certificate]
		reload := func() error {
			c, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
			if err != nil {
				return err
			}
			cur.Store(&c)
			return nil
		}
		if err := reload(); err != nil {
			return nil, nil, errors.New("certs: loading TLS files: " + err.Error())
		}
		// Register synchronously: a SIGHUP arriving before the goroutine is
		// scheduled would otherwise hit the default action and kill us.
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		go watch(ctx, hup, reload, logger)
		base.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return cur.Load(), nil
		}
		return base, nil, nil
	case len(cfg.ACMEDomains) > 0:
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(cfg.ACMEDir),
			HostPolicy: autocert.HostWhitelist(cfg.ACMEDomains...),
			Email:      cfg.ACMEEmail,
		}
		base.GetCertificate = m.GetCertificate
		base.NextProtos = append(base.NextProtos, "acme-tls/1")
		return base, m, nil
	}
	return nil, nil, errors.New("certs: TLS_MODE=terminate needs inline PEM, certificate files or ACME domains")
}

// watch calls reload on SIGHUP and every reloadInterval until ctx ends. A
// failed reload keeps the previous certificate.
func watch(ctx context.Context, hup chan os.Signal, reload func() error, logger *slog.Logger) {
	defer signal.Stop(hup)
	t := time.NewTicker(reloadInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
		case <-t.C:
		}
		if err := reload(); err != nil {
			logger.Error("tls certificate reload failed; keeping previous", "err", err)
			continue
		}
		logger.Info("tls certificate reloaded")
	}
}

// HTTPHandler serves the plain-HTTP listener. With ACME active it answers
// HTTP-01 challenges and redirects everything else; otherwise it redirects
// to https with a 308. redirectTo, when non-empty, is a fixed https host to
// redirect to instead of the request's Host header.
func HTTPHandler(m *autocert.Manager, redirectTo string) http.Handler {
	if m != nil {
		return m.HTTPHandler(redirectHandler(redirectTo))
	}
	return redirectHandler(redirectTo)
}

func redirectHandler(host string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := host
		if h == "" {
			h = r.Host
			if h == "" {
				http.Error(w, "missing Host header", http.StatusBadRequest)
				return
			}
			if hh, _, err := net.SplitHostPort(h); err == nil {
				h = hh // the HTTP port is meaningless on the https side
				if strings.Contains(h, ":") {
					h = "[" + h + "]"
				}
			}
		}
		http.Redirect(w, r, "https://"+h+r.URL.RequestURI(), http.StatusPermanentRedirect)
	})
}
