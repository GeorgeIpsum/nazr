package store

import (
	"context"
	"sync"
	"testing"
	"time"
)

func testSigningKey(kid string, createdAt time.Time) SigningKey {
	return SigningKey{Kid: kid, PrivateKeyPEM: "pem-" + kid, PublicJWK: []byte(`{"kid": "` + kid + `"}`),
		HMACSecret: []byte("secret-" + kid), CreatedAt: createdAt}
}

func TestSigningKeys(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	k1 := testSigningKey("k1", now.Add(-time.Hour))
	k2 := testSigningKey("k2", now)

	calls := 0
	gen := func() (SigningKey, error) { calls++; return k1, nil }
	got, err := s.EnsureSigningKey(ctx, gen)
	if err != nil || got.Kid != "k1" || calls != 1 {
		t.Fatalf("first ensure: %+v calls %d %v", got, calls, err)
	}
	got, err = s.EnsureSigningKey(ctx, gen)
	if err != nil || got.Kid != "k1" || calls != 1 {
		t.Fatalf("second ensure: %+v calls %d %v", got, calls, err)
	}
	if got.PrivateKeyPEM != "pem-k1" || string(got.PublicJWK) != `{"kid": "k1"}` || string(got.HMACSecret) != "secret-k1" ||
		!got.CreatedAt.Equal(k1.CreatedAt) || got.RetiredAt != nil {
		t.Fatalf("round trip: %+v", got)
	}

	if err := s.RotateSigningKey(ctx, k2); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListSigningKeys(ctx, now.Add(-time.Hour))
	if err != nil || len(list) != 2 || list[0].Kid != "k2" || list[0].RetiredAt != nil ||
		list[1].Kid != "k1" || list[1].RetiredAt == nil {
		t.Fatalf("list: %+v %v", list, err)
	}
	list, err = s.ListSigningKeys(ctx, now.Add(time.Hour))
	if err != nil || len(list) != 1 || list[0].Kid != "k2" {
		t.Fatalf("list future: %+v %v", list, err)
	}
	n, err := s.DeleteRetiredSigningKeys(ctx, now.Add(time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("delete: %d %v", n, err)
	}
}

func TestEnsureSigningKeyConcurrent(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 5)
	for i := range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.EnsureSigningKey(ctx, func() (SigningKey, error) {
				return testSigningKey(newID()+string(rune('a'+i)), time.Now().UTC()), nil
			})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM signing_keys`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("rows %d %v", n, err)
	}
}

func TestKeySecret(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	k, err := s.CreateKey(ctx, NewKey{Hash: "h1", Prefix: "aaaaaaaa", SecretHash: "s1", SecretPrefix: "sec_1111"})
	if err != nil {
		t.Fatal(err)
	}
	if k.SecretPrefix != "sec_1111" {
		t.Fatalf("created: %+v", k)
	}
	got, err := s.FindKeyBySecretHash(ctx, "s1")
	if err != nil || got == nil || got.ID != k.ID || got.SecretPrefix != "sec_1111" {
		t.Fatalf("find: %+v %v", got, err)
	}
	if err := s.SetKeySecret(ctx, k.ID, "s2", "sec_2222"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.FindKeyBySecretHash(ctx, "s1"); err != nil || got != nil {
		t.Fatalf("old hash: %+v %v", got, err)
	}
	if got, err := s.FindKeyBySecretHash(ctx, "s2"); err != nil || got == nil || got.SecretPrefix != "sec_2222" {
		t.Fatalf("new hash: %+v %v", got, err)
	}
	if err := s.SetKeySecret(ctx, "00000000-0000-0000-0000-000000000000", "x", "y"); err != ErrNotFound {
		t.Fatalf("unknown id: %v", err)
	}
	if err := s.SetKeySecret(ctx, "not-a-uuid", "x", "y"); err != ErrNotFound {
		t.Fatalf("bad id: %v", err)
	}
	plain, err := s.CreateKey(ctx, NewKey{Hash: "h2", Prefix: "bbbbbbbb"})
	if err != nil || plain.SecretPrefix != "" {
		t.Fatalf("plain: %+v %v", plain, err)
	}
	var isNull bool
	if err := s.pool.QueryRow(ctx, `SELECT secret_hash IS NULL FROM api_keys WHERE id = $1::uuid`, plain.ID).Scan(&isNull); err != nil || !isNull {
		t.Fatalf("secret_hash not NULL: %v %v", isNull, err)
	}
}
