package widgettoken

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
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
	if len(sk.HMACSecret) != 32 || len(sk.Kid) != 22 || !sk.CreatedAt.Equal(now) || sk.RetiredAt != nil {
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
	if _, ok := kr.Active(); ok {
		t.Fatal("active before refresh")
	}
	if err := kr.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	check := func(kr *Keyring) {
		t.Helper()
		a, ok := kr.Active()
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

	a, _ := kr.Active()
	l, _ := kr.Lookup(k0.Kid)
	check(NewStaticKeyring(l, a))
	if err := NewStaticKeyring(a).Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestFromStoredRejects(t *testing.T) {
	if _, err := FromStored(store.SigningKey{PrivateKeyPEM: "junk"}); err == nil {
		t.Fatal("want error")
	}
}
