package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"nazr/api/internal/config"
)

func genPair(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})
}

func cnOf(t *testing.T, c *tls.Certificate) string {
	t.Helper()
	x, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return x.Subject.CommonName
}

func TestInlinePEMPreferred(t *testing.T) {
	dir := t.TempDir()
	fc, fk := genPair(t, "file")
	ic, ik := genPair(t, "inline")
	os.WriteFile(filepath.Join(dir, "c.pem"), fc, 0o600)
	os.WriteFile(filepath.Join(dir, "k.pem"), fk, 0o600)
	cfg := config.Config{
		TLSMode: "terminate", TLSCertPEM: string(ic), TLSKeyPEM: string(ik),
		TLSCertFile: filepath.Join(dir, "c.pem"), TLSKeyFile: filepath.Join(dir, "k.pem"),
	}
	tc, err := Load(context.Background(), cfg, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if len(tc.Certificates) != 1 || cnOf(t, &tc.Certificates[0]) != "inline" {
		t.Fatalf("inline PEM not preferred: %+v", tc.Certificates)
	}
	if !slices.Equal(tc.NextProtos, []string{"h2", "http/1.1"}) || tc.MinVersion != tls.VersionTLS12 {
		t.Fatalf("protos/min version: %v %v", tc.NextProtos, tc.MinVersion)
	}
}

func TestFileReloadOnSIGHUP(t *testing.T) {
	dir := t.TempDir()
	cf, kf := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	ac, ak := genPair(t, "A")
	os.WriteFile(cf, ac, 0o600)
	os.WriteFile(kf, ak, 0o600)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tc, err := Load(ctx, config.Config{TLSMode: "terminate", TLSCertFile: cf, TLSKeyFile: kf}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	got, err := tc.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || cnOf(t, got) != "A" {
		t.Fatalf("initial: %v %v", got, err)
	}
	bc, bk := genPair(t, "B")
	os.WriteFile(cf, bc, 0o600)
	os.WriteFile(kf, bk, 0o600)
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got, _ := tc.GetCertificate(&tls.ClientHelloInfo{}); got != nil && cnOf(t, got) == "B" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("certificate not reloaded after SIGHUP")
}

func TestPlainModeReturnsNil(t *testing.T) {
	for _, mode := range []string{"plain", "proxied"} {
		tc, err := Load(context.Background(), config.Config{TLSMode: mode}, slog.Default())
		if tc != nil || err != nil {
			t.Fatalf("%s: got %v, %v", mode, tc, err)
		}
	}
	if _, err := Load(context.Background(), config.Config{TLSMode: "terminate"}, slog.Default()); err == nil {
		t.Fatal("terminate with no cert source must error")
	}
}

func TestACMEConfigBuildsManager(t *testing.T) {
	cfg := config.Config{TLSMode: "terminate", ACMEDomains: []string{"example.com"}, ACMEDir: t.TempDir(), ACMEEmail: "a@example.com"}
	tc, err := Load(context.Background(), cfg, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if tc.GetCertificate == nil {
		t.Fatal("GetCertificate nil")
	}
	for _, p := range []string{"h2", "http/1.1", "acme-tls/1"} {
		if !slices.Contains(tc.NextProtos, p) {
			t.Fatalf("NextProtos missing %s: %v", p, tc.NextProtos)
		}
	}
	if tc.MinVersion != tls.VersionTLS12 {
		t.Fatal("min version")
	}
}

func TestUsesFileCerts(t *testing.T) {
	for _, tc := range []struct {
		cfg  config.Config
		want bool
	}{
		{config.Config{TLSMode: "terminate", TLSCertFile: "c", TLSKeyFile: "k"}, true},
		{config.Config{TLSMode: "terminate", TLSCertFile: "c"}, false},
		{config.Config{TLSMode: "terminate", TLSCertFile: "c", TLSKeyFile: "k", TLSCertPEM: "p", TLSKeyPEM: "q"}, false},
		{config.Config{TLSMode: "terminate", TLSCertFile: "c", TLSKeyFile: "k", TLSCertPEM: "p"}, true},
		{config.Config{TLSMode: "plain", TLSCertFile: "c", TLSKeyFile: "k"}, false},
	} {
		if got := UsesFileCerts(tc.cfg); got != tc.want {
			t.Errorf("%+v: got %v want %v", tc.cfg, got, tc.want)
		}
	}
}
