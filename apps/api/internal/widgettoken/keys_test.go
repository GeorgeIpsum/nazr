package widgettoken

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"nazr/api/internal/store"
)

func TestGenerateAndKeyring(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	sk, err := Generate(now)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode([]byte(sk.PrivateKeyPEM))
	if blk == nil || blk.Type != "PRIVATE KEY" {
		t.Fatalf("bad pem block")
	}
	pk, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if ec, ok := pk.(*ecdsa.PrivateKey); !ok || ec.Curve != elliptic.P256() {
		t.Fatalf("not P-256: %T", pk)
	}
	var jwk JWK
	if err := json.Unmarshal(sk.PublicJWK, &jwk); err != nil || jwk.Kid != sk.Kid {
		t.Fatalf("jwk %+v %v", jwk, err)
	}
	if len(sk.HMACSecret) != 32 || len(sk.Kid) != 22 || !sk.CreatedAt.Equal(now) || sk.RetiredAt != nil ||
		!sk.ActivatesAt.Equal(now) {
		t.Fatalf("bad key: %+v", sk)
	}

	k0, _ := Generate(now.Add(-2 * time.Hour))
	k1, _ := Generate(now.Add(-time.Hour))
	retired := now.Add(-time.Hour)
	k0.RetiredAt = &retired

	fail := false
	kr := NewKeyring(func(context.Context) ([]store.SigningKey, error) {
		if fail {
			return nil, errors.New("db down")
		}
		return []store.SigningKey{k0, k1}, nil
	})
	if _, ok := kr.Active(now); ok {
		t.Fatal("active before refresh")
	}
	if err := kr.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	check := func(kr *Keyring) {
		t.Helper()
		a, ok := kr.Active(now)
		if !ok || a.Kid != k1.Kid || a.Private == nil {
			t.Fatalf("active %+v %v", a.Kid, ok)
		}
		if l, ok := kr.Lookup(k0.Kid); !ok || l.RetiredAt == nil {
			t.Fatal("retired key not found")
		}
		if _, ok := kr.Lookup("nope"); ok {
			t.Fatal("unexpected lookup")
		}
		ks := kr.JWKS().Keys
		if len(ks) != 2 || ks[0].Kid != k1.Kid || ks[1].Kid != k0.Kid {
			t.Fatalf("jwks %+v", ks)
		}
	}
	check(kr)
	fail = true
	if err := kr.Refresh(context.Background()); err == nil {
		t.Fatal("want error")
	}
	check(kr)

	a, _ := kr.Active(now)
	l, _ := kr.Lookup(k0.Kid)
	check(NewStaticKeyring(l, a))
	if err := NewStaticKeyring(a).Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestKeyringActiveAcrossRotation follows a rotation's publish hour: the old
// key signs until the new one activates, and both are published throughout.
func TestKeyringActiveAcrossRotation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	old, _ := Generate(now.Add(-48 * time.Hour))
	next, _ := Generate(now)
	switchAt := now.Add(SigningKeyPublish)
	old.RetiredAt = &switchAt
	next.ActivatesAt = switchAt
	kr := NewKeyring(func(context.Context) ([]store.SigningKey, error) { return []store.SigningKey{old, next}, nil })
	if err := kr.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if l, ok := kr.Lookup(next.Kid); !ok || !l.ActivatesAt.Equal(switchAt) {
		t.Fatalf("lookup next: %+v %v", l.ActivatesAt, ok)
	}
	for _, c := range []struct {
		at   time.Time
		want string
	}{
		{now, old.Kid},
		{switchAt.Add(-time.Second), old.Kid},
		{switchAt, next.Kid},
		{switchAt.Add(time.Hour), next.Kid},
	} {
		if a, ok := kr.Active(c.at); !ok || a.Kid != c.want {
			t.Fatalf("Active(%v) = %s %v, want %s", c.at, a.Kid, ok, c.want)
		}
	}
	if ks := kr.JWKS().Keys; len(ks) != 2 || ks[0].Kid != next.Kid || ks[1].Kid != old.Kid {
		t.Fatalf("jwks %+v", ks)
	}

	// A lone key that has not activated yet is not active. EnsureSigningKey
	// never produces this state: the first key activates at creation.
	lone := NewStaticKeyring(Key{Kid: "lone", Private: mustKey(t, next).Private, ActivatesAt: switchAt})
	if _, ok := lone.Active(now); ok {
		t.Fatal("not-yet-active key is active")
	}
	if _, ok := lone.Active(switchAt); !ok {
		t.Fatal("key not active at its activation")
	}
}

func mustKey(t *testing.T, sk store.SigningKey) Key {
	t.Helper()
	k, err := FromStored(sk)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestFromStoredRejects(t *testing.T) {
	if _, err := FromStored(store.SigningKey{PrivateKeyPEM: "junk"}); err == nil {
		t.Fatal("want error")
	}
}

func TestRunLogsRefreshFailure(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	kr := NewKeyring(func(context.Context) ([]store.SigningKey, error) {
		cancel()
		return nil, errors.New("db down")
	})
	done := make(chan struct{})
	go func() {
		kr.Run(ctx, 20*time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], "level=WARN") ||
		!strings.Contains(lines[0], "signing key refresh failed") || !strings.Contains(lines[0], "db down") {
		t.Fatalf("log %q", buf.String())
	}
}
