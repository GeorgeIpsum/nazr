package widgettoken

import (
	"crypto/sha256"
	"math/bits"
	"strconv"
)

const (
	maxPoWBits       = 32
	maxCounterDigits = 32
)

// VerifyPoW reports whether SHA-256 of id + ":" + counter has at least bits
// leading zero bits. counter must be 1 to 32 ASCII digits and bits within 0
// to 32; with bits == 0 any such counter passes.
func VerifyPoW(id, counter string, bits int) bool {
	if bits < 0 || bits > maxPoWBits || len(counter) == 0 || len(counter) > maxCounterDigits {
		return false
	}
	for i := 0; i < len(counter); i++ {
		if counter[i] < '0' || counter[i] > '9' {
			return false
		}
	}
	return leadingZeroBits(sha256.Sum256([]byte(id+":"+counter))) >= bits
}

// SolvePoW returns the first decimal counter, counting up from 0, that
// satisfies VerifyPoW. It is the reference solver used by tests and tools;
// bits must be within 0 to 32.
func SolvePoW(id string, bits int) string {
	if bits <= 0 {
		return "0"
	}
	for n := uint64(0); ; n++ {
		c := strconv.FormatUint(n, 10)
		if VerifyPoW(id, c, bits) {
			return c
		}
	}
}

func leadingZeroBits(h [sha256.Size]byte) int {
	n := 0
	for _, b := range h {
		if b != 0 {
			return n + bits.LeadingZeros8(b)
		}
		n += 8
	}
	return n
}
