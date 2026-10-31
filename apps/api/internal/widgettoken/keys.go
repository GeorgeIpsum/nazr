package widgettoken

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"

	"nazr/api/internal/store"
)

const (
	// SigningKeyGrace is how long a retired key stays published and usable
	// for verification.
	SigningKeyGrace = 24 * time.Hour
	// SigningKeyPublish is how long a rotated-in key is published in the
	// JWKS before it starts signing: the JWKS cache time (one hour) plus two
	// refresh periods, so every replica has loaded the key before it signs
	// and consumers have it cached before its first token.
	SigningKeyPublish = time.Hour + 2*SigningKeyRefresh
	// SigningKeyRefresh is how often the keyring reloads from the database.
	SigningKeyRefresh = 60 * time.Second
)

// Key is a parsed signing key. It signs from ActivatesAt until RetiredAt.
type Key struct {
	Kid         string
	Private     *ecdsa.PrivateKey
	Secret      []byte
	CreatedAt   time.Time
	RetiredAt   *time.Time
	ActivatesAt time.Time
}

// Generate creates a new P-256 signing key, a random 22-character kid and a
// 32-byte challenge HMAC secret, ready to store. It activates at now.
func Generate(now time.Time) (store.SigningKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return store.SigningKey{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return store.SigningKey{}, err
	}
	var kidBytes [16]byte
	secret := make([]byte, 32)
	if _, err := rand.Read(kidBytes[:]); err != nil {
		return store.SigningKey{}, err
	}
	if _, err := rand.Read(secret); err != nil {
		return store.SigningKey{}, err
	}
	kid := enc.EncodeToString(kidBytes[:])
	jwk, err := json.Marshal(PublicJWK(kid, &priv.PublicKey))
	if err != nil {
		return store.SigningKey{}, err
	}
	return store.SigningKey{
		Kid:           kid,
		PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		PublicJWK:     jwk,
		HMACSecret:    secret,
		CreatedAt:     now,
		ActivatesAt:   now,
	}, nil
}

// FromStored parses a stored key. The private key must be P-256 PKCS#8.
func FromStored(sk store.SigningKey) (Key, error) {
	blk, _ := pem.Decode([]byte(sk.PrivateKeyPEM))
	if blk == nil {
		return Key{}, errors.New("widgettoken: signing key is not PEM")
	}
	pk, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return Key{}, err
	}
	priv, ok := pk.(*ecdsa.PrivateKey)
	if !ok || priv.Curve != elliptic.P256() {
		return Key{}, errors.New("widgettoken: signing key is not ECDSA P-256")
	}
	return Key{Kid: sk.Kid, Private: priv, Secret: sk.HMACSecret, CreatedAt: sk.CreatedAt, RetiredAt: sk.RetiredAt,
		ActivatesAt: sk.ActivatesAt}, nil
}

// Keyring is a concurrency-safe set of signing keys, newest first.
type Keyring struct {
	load func(ctx context.Context) ([]store.SigningKey, error)
	mu   sync.RWMutex
	keys []Key
}

// NewKeyring returns an empty keyring that fills from load on Refresh.
func NewKeyring(load func(ctx context.Context) ([]store.SigningKey, error)) *Keyring {
	return &Keyring{load: load}
}

// NewStaticKeyring returns a keyring fixed to keys; Refresh does nothing.
func NewStaticKeyring(keys ...Key) *Keyring {
	k := &Keyring{}
	k.set(keys)
	return k
}

func (k *Keyring) set(keys []Key) {
	sorted := append([]Key(nil), keys...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].CreatedAt.After(sorted[j].CreatedAt) })
	k.mu.Lock()
	k.keys = sorted
	k.mu.Unlock()
}

// Refresh reloads the key set. On any error the previous set is kept.
func (k *Keyring) Refresh(ctx context.Context) error {
	if k.load == nil {
		return nil
	}
	rows, err := k.load(ctx)
	if err != nil {
		return err
	}
	keys := make([]Key, 0, len(rows))
	for _, r := range rows {
		key, err := FromStored(r)
		if err != nil {
			return err
		}
		keys = append(keys, key)
	}
	k.set(keys)
	return nil
}

// Active returns the newest key that signs at now: activated (ActivatesAt
// at or before now) and not retired (RetiredAt nil or after now). During a
// rotation's publish window that is the outgoing key.
func (k *Keyring) Active(now time.Time) (Key, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	for _, key := range k.keys {
		if !key.ActivatesAt.After(now) && (key.RetiredAt == nil || key.RetiredAt.After(now)) {
			return key, true
		}
	}
	return Key{}, false
}

// Lookup returns the key with the given kid, retired or not.
func (k *Keyring) Lookup(kid string) (Key, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	for _, key := range k.keys {
		if key.Kid == kid {
			return key, true
		}
	}
	return Key{}, false
}

// JWKS returns the public keys of every loaded key, newest first.
func (k *Keyring) JWKS() JWKS {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := JWKS{Keys: make([]JWK, 0, len(k.keys))}
	for _, key := range k.keys {
		out.Keys = append(out.Keys, PublicJWK(key.Kid, &key.Private.PublicKey))
	}
	return out
}

// Run refreshes every interval until ctx is done. Errors are logged at Warn
// and the last good set stays in place.
func (k *Keyring) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := k.Refresh(ctx); err != nil {
				slog.Warn("widgettoken: signing key refresh failed", "err", err)
			}
		}
	}
}
