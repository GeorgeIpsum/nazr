package fingerprint

import (
	"encoding/binary"
	"encoding/hex"
	"math/bits"
)

const (
	c1 uint32 = 0x239b961b
	c2 uint32 = 0xab0e9789
	c3 uint32 = 0x38b34ae5
	c4 uint32 = 0xa1e38b93
)

func fmix(h uint32) uint32 {
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

// Murmur128Hex returns murmur3 x86 128 (seed 0) of the UTF-8 bytes of s as 32
// hex characters: the four state words, each little-endian, as the client does.
func Murmur128Hex(s string) string {
	key := []byte(s)
	var h1, h2, h3, h4 uint32
	blocks := len(key) / 16
	for i := 0; i < blocks; i++ {
		b := key[i*16:]
		k1 := binary.LittleEndian.Uint32(b[0:])
		k2 := binary.LittleEndian.Uint32(b[4:])
		k3 := binary.LittleEndian.Uint32(b[8:])
		k4 := binary.LittleEndian.Uint32(b[12:])

		k1 = bits.RotateLeft32(k1*c1, 15) * c2
		h1 ^= k1
		h1 = bits.RotateLeft32(h1, 19) + h2
		h1 = h1*5 + 0x561ccd1b

		k2 = bits.RotateLeft32(k2*c2, 16) * c3
		h2 ^= k2
		h2 = bits.RotateLeft32(h2, 17) + h3
		h2 = h2*5 + 0x0bcaa747

		k3 = bits.RotateLeft32(k3*c3, 17) * c4
		h3 ^= k3
		h3 = bits.RotateLeft32(h3, 15) + h4
		h3 = h3*5 + 0x96cd1c35

		k4 = bits.RotateLeft32(k4*c4, 18) * c1
		h4 ^= k4
		h4 = bits.RotateLeft32(h4, 13) + h1
		h4 = h4*5 + 0x32ac3b17
	}

	tail := key[blocks*16:]
	var k1, k2, k3, k4 uint32
	n := len(tail)
	word := func(from, to int) uint32 { // little-endian bytes tail[from:to] (to capped at n)
		var w uint32
		for i := from; i < to && i < n; i++ {
			w |= uint32(tail[i]) << (8 * uint(i-from))
		}
		return w
	}
	if n > 12 {
		k4 = word(12, 16)
		k4 = bits.RotateLeft32(k4*c4, 18) * c1
		h4 ^= k4
	}
	if n > 8 {
		k3 = word(8, 12)
		k3 = bits.RotateLeft32(k3*c3, 17) * c4
		h3 ^= k3
	}
	if n > 4 {
		k2 = word(4, 8)
		k2 = bits.RotateLeft32(k2*c2, 16) * c3
		h2 ^= k2
	}
	if n > 0 {
		k1 = word(0, 4)
		k1 = bits.RotateLeft32(k1*c1, 15) * c2
		h1 ^= k1
	}

	l := uint32(len(key))
	h1 ^= l
	h2 ^= l
	h3 ^= l
	h4 ^= l

	h1 += h2
	h1 += h3
	h1 += h4
	h2 += h1
	h3 += h1
	h4 += h1

	h1, h2, h3, h4 = fmix(h1), fmix(h2), fmix(h3), fmix(h4)

	h1 += h2
	h1 += h3
	h1 += h4
	h2 += h1
	h3 += h1
	h4 += h1

	var out [16]byte
	binary.LittleEndian.PutUint32(out[0:], h1)
	binary.LittleEndian.PutUint32(out[4:], h2)
	binary.LittleEndian.PutUint32(out[8:], h3)
	binary.LittleEndian.PutUint32(out[12:], h4)
	return hex.EncodeToString(out[:])
}

// Hash returns the fingerprint hash of c.
func Hash(c Components) string {
	return Murmur128Hex(StableStringify(c))
}
