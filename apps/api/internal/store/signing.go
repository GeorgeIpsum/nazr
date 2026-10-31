package store

import (
	"encoding/json"
	"time"
)

// SigningKey is one row of the signing_keys table: an ES256 private key
// (PKCS#8 PEM), its public JWK, and the HMAC secret that authenticates
// challenges minted under the same kid. RetiredAt is nil for the key in use.
type SigningKey struct {
	Kid           string
	PrivateKeyPEM string
	PublicJWK     json.RawMessage
	HMACSecret    []byte
	CreatedAt     time.Time
	RetiredAt     *time.Time
}
