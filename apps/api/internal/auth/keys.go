// Package auth implements API keys, origin scoping, rate limiting and the
// HTTP middleware that enforces them.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"strings"
)

const keyPrefix = "nzr_"

var keyEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateKey returns a new random API key, its SHA-256 hex hash and the
// display prefix (the first 8 characters after "nzr_").
func GenerateKey() (plaintext, hash, prefix string) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("auth: crypto/rand failed: " + err.Error())
	}
	plaintext = keyPrefix + strings.ToLower(keyEncoding.EncodeToString(b[:]))
	return plaintext, HashKey(plaintext), plaintext[len(keyPrefix) : len(keyPrefix)+8]
}

// HashKey returns the SHA-256 hex digest of a plaintext key.
func HashKey(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}
