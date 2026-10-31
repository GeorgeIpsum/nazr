package widgettoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"
)

// Errors returned by ParseChallenge.
var (
	ErrChallengeMalformed  = errors.New("widgettoken: malformed challenge")
	ErrChallengeUnknownKid = errors.New("widgettoken: challenge signed by unknown key")
	ErrChallengeBadMAC     = errors.New("widgettoken: challenge MAC mismatch")
	ErrChallengeExpired    = errors.New("widgettoken: challenge expired")
)

// maxChallengeLen bounds the encoded challenge before anything is decoded.
const maxChallengeLen = 512

// Challenge is the server-minted payload a browser must solve before it can
// ask for a token. Field order fixes the encoded form.
type Challenge struct {
	ID      string `json:"id"`
	Expires int64  `json:"exp"`
	Bits    int    `json:"bits"`
	Kid     string `json:"kid"`
	Origin  string `json:"origin"`
}

// MintChallenge returns "<payload>.<mac>", both base64url without padding.
// The payload is the JSON of c; the MAC is HMAC-SHA256 under secret over the
// bytes of the encoded payload string, so a verifier can check it before
// decoding anything.
func MintChallenge(secret []byte, c Challenge) string {
	p, err := json.Marshal(c)
	if err != nil {
		panic("widgettoken: marshal challenge: " + err.Error())
	}
	payload := enc.EncodeToString(p)
	return payload + "." + enc.EncodeToString(challengeMAC(secret, payload))
}

func challengeMAC(secret []byte, payload string) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(payload))
	return m.Sum(nil)
}

// ParseChallenge verifies s and returns the challenge. secretFor is called
// once, with the kid read from the payload; the MAC is checked before the
// expiry. A challenge is expired when now is at or past Expires.
func ParseChallenge(s string, secretFor func(kid string) ([]byte, bool), now time.Time) (Challenge, error) {
	if len(s) > maxChallengeLen || strings.Count(s, ".") != 1 {
		return Challenge{}, ErrChallengeMalformed
	}
	payload, macPart, _ := strings.Cut(s, ".")
	pb, err := enc.DecodeString(payload)
	if err != nil {
		return Challenge{}, ErrChallengeMalformed
	}
	mac, err := enc.DecodeString(macPart)
	if err != nil {
		return Challenge{}, ErrChallengeMalformed
	}
	var c Challenge
	if err := json.Unmarshal(pb, &c); err != nil {
		return Challenge{}, ErrChallengeMalformed
	}
	secret, ok := secretFor(c.Kid)
	if !ok {
		return Challenge{}, ErrChallengeUnknownKid
	}
	if !hmac.Equal(mac, challengeMAC(secret, payload)) {
		return Challenge{}, ErrChallengeBadMAC
	}
	if now.Unix() >= c.Expires {
		return Challenge{}, ErrChallengeExpired
	}
	return c, nil
}

// EmbeddingOrigin returns scheme://host[:port] of a Referer, or "" when it is
// not an http(s) URL with a host.
func EmbeddingOrigin(referer string) string {
	u, err := url.Parse(referer)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
