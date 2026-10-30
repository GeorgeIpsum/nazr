package server

// validNonce reports whether s is 1..64 printable ASCII bytes (0x20..0x7e);
// anything else is treated as an absent nonce.
func validNonce(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
