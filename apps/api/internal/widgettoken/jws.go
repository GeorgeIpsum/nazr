// Package widgettoken signs and verifies the ES256 compact JWS tokens nazr
// issues to browsers that pass a bot challenge, and encodes the public keys
// as a JWKS.
package widgettoken

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
)

// Errors returned by Parse.
var (
	ErrMalformed    = errors.New("widgettoken: malformed token")
	ErrAlgorithm    = errors.New("widgettoken: unsupported algorithm")
	ErrUnknownKid   = errors.New("widgettoken: unknown key id")
	ErrBadSignature = errors.New("widgettoken: bad signature")
)

const (
	algES256 = "ES256"
	coordLen = 32
)

var enc = base64.RawURLEncoding

// Claims is the token payload. Unknown fields are ignored when parsing.
type Claims struct {
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`
	ID       string `json:"jti"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
	Hostname string `json:"hostname"`
	Verdict  string `json:"verdict"`
}

// header is the protected header; field order fixes the encoded form.
type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	Typ string `json:"typ,omitempty"`
}

// Sign returns c as a compact ES256 JWS signed by priv with the given kid.
func Sign(priv *ecdsa.PrivateKey, kid string, c Claims) (string, error) {
	h, err := json.Marshal(header{Alg: algES256, Kid: kid, Typ: "JWT"})
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	input := enc.EncodeToString(h) + "." + enc.EncodeToString(p)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 2*coordLen)
	r.FillBytes(sig[:coordLen])
	s.FillBytes(sig[coordLen:])
	return input + "." + enc.EncodeToString(sig), nil
}

// Parse verifies token against the key keyFor returns for its kid and returns
// the claims. The signature is checked before the claims are decoded. Parse
// does not check exp; callers do.
func Parse(token string, keyFor func(kid string) (*ecdsa.PublicKey, bool)) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, ErrMalformed
	}
	hb, err := enc.DecodeString(parts[0])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	var h header
	if err := json.Unmarshal(hb, &h); err != nil {
		return Claims{}, ErrMalformed
	}
	if h.Alg != algES256 {
		return Claims{}, ErrAlgorithm
	}
	pub, ok := keyFor(h.Kid)
	if !ok || pub == nil {
		return Claims{}, ErrUnknownKid
	}
	pb, err := enc.DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	if len(sig) != 2*coordLen {
		return Claims{}, ErrBadSignature
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:coordLen])
	s := new(big.Int).SetBytes(sig[coordLen:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return Claims{}, ErrBadSignature
	}
	var c Claims
	if err := json.Unmarshal(pb, &c); err != nil {
		return Claims{}, ErrMalformed
	}
	return c, nil
}

// JWK is a public EC key in JSON Web Key form.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// JWKS is a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// PublicJWK encodes a P-256 public key as a signing JWK with the given kid.
func PublicJWK(kid string, pub *ecdsa.PublicKey) JWK {
	raw, err := pub.Bytes() // 0x04 || X || Y, fixed-width
	if err != nil || len(raw) != 1+2*coordLen {
		panic("widgettoken: public key is not a valid P-256 point")
	}
	return JWK{
		Kty: "EC", Crv: "P-256", Kid: kid, Use: "sig", Alg: algES256,
		X: enc.EncodeToString(raw[1 : 1+coordLen]),
		Y: enc.EncodeToString(raw[1+coordLen:]),
	}
}
