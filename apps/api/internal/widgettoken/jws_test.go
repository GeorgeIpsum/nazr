package widgettoken

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// RFC 7515 Appendix A.3 key and token.
const (
	rfcX = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
	rfcY = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
	rfcD = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"

	rfcToken = "eyJhbGciOiJFUzI1NiJ9" +
		"." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
		"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
		"." +
		"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA" +
		"pmWQxfKTUJqPP3-Kg6NU1Q"
)

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func rfcKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), b64(t, rfcD))
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func rfcPub(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	raw := append([]byte{4}, b64(t, rfcX)...)
	raw = append(raw, b64(t, rfcY)...)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func only(pub *ecdsa.PublicKey, kid string) func(string) (*ecdsa.PublicKey, bool) {
	return func(k string) (*ecdsa.PublicKey, bool) { return pub, k == kid }
}

func TestParseRFC7515ES256(t *testing.T) {
	pub := rfcPub(t)
	if !rfcKey(t).PublicKey.Equal(pub) {
		t.Fatal("RFC d does not match RFC x/y")
	}
	got, err := Parse(rfcToken, only(pub, ""))
	if err != nil {
		t.Fatal(err)
	}
	if want := (Claims{Issuer: "joe", Expires: 1300819380}); got != want {
		t.Fatalf("claims = %+v, want %+v", got, want)
	}
}

func TestSignParseRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	in := Claims{Issuer: "https://nazr.example", Audience: "key", ID: "01H...", IssuedAt: 1, Expires: 301, Hostname: "https://shop.example", Verdict: "pass"}
	tok, err := Sign(priv, "k1", in)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || strings.Contains(tok, "=") {
		t.Fatalf("bad token shape: %q", tok)
	}
	if h := string(b64(t, parts[0])); h != `{"alg":"ES256","kid":"k1","typ":"JWT"}` {
		t.Fatalf("header = %s", h)
	}
	if n := len(b64(t, parts[2])); n != 64 {
		t.Fatalf("signature length = %d", n)
	}
	out, err := Parse(tok, only(&priv.PublicKey, "k1"))
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("claims = %+v, want %+v", out, in)
	}
}

// forge builds a token with the given header and a signature of sigLen bytes
// (at most 64); it is deliberately not a valid signature over its input.
func forge(t *testing.T, priv *ecdsa.PrivateKey, header string, sigLen int) string {
	t.Helper()
	enc := base64.RawURLEncoding
	input := enc.EncodeToString([]byte(header)) + "." + enc.EncodeToString([]byte(`{"iss":"x"}`))
	tok, err := Sign(priv, "k1", Claims{})
	if err != nil {
		t.Fatal(err)
	}
	sig := b64(t, strings.Split(tok, ".")[2])
	if sigLen != 64 {
		sig = sig[:sigLen]
	}
	return input + "." + enc.EncodeToString(sig)
}

func TestParseRejects(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyFor := only(&priv.PublicKey, "k1")
	good, err := Sign(priv, "k1", Claims{Issuer: "i", Expires: 5})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(good, ".")
	payload := []byte(parts[1])
	if payload[3] == 'A' {
		payload[3] = 'B'
	} else {
		payload[3] = 'A'
	}
	tampered := parts[0] + "." + string(payload) + "." + parts[2]

	tests := []struct {
		name  string
		token string
		keyFn func(string) (*ecdsa.PublicKey, bool)
		want  error
	}{
		{"flipped payload", tampered, keyFor, ErrBadSignature},
		{"two segments", parts[0] + "." + parts[1], keyFor, ErrMalformed},
		{"alg none", forge(t, priv, `{"alg":"none","kid":"k1"}`, 64), keyFor, ErrAlgorithm},
		{"alg HS256", forge(t, priv, `{"alg":"HS256","kid":"k1"}`, 64), keyFor, ErrAlgorithm},
		{"unknown kid", good, func(string) (*ecdsa.PublicKey, bool) { return nil, false }, ErrUnknownKid},
		{"short signature", forge(t, priv, `{"alg":"ES256","kid":"k1"}`, 63), keyFor, ErrBadSignature},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(tc.token, tc.keyFn); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestPublicJWK(t *testing.T) {
	j := PublicJWK("k", rfcPub(t))
	want := JWK{Kty: "EC", Crv: "P-256", Kid: "k", Use: "sig", Alg: "ES256", X: rfcX, Y: rfcY}
	if j != want {
		t.Fatalf("jwk = %+v, want %+v", j, want)
	}
}
