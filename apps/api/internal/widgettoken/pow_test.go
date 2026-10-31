package widgettoken

import (
	"crypto/sha256"
	"math/bits"
	"strconv"
	"strings"
	"testing"
)

func leadingZeros(id, counter string) int {
	h := sha256.Sum256([]byte(id + ":" + counter))
	n := 0
	for _, b := range h {
		if b == 0 {
			n += 8
			continue
		}
		return n + bits.LeadingZeros8(b)
	}
	return n
}

func TestPoW(t *testing.T) {
	if !VerifyPoW("id", "0", 0) {
		t.Fatal("bits 0 must accept")
	}
	if got := SolvePoW("id", 0); got != "0" {
		t.Fatalf("SolvePoW bits 0 = %q", got)
	}
	c := SolvePoW("abc", 12)
	if !VerifyPoW("abc", c, 12) || leadingZeros("abc", c) < 12 {
		t.Fatalf("solution %q invalid", c)
	}
	for _, bad := range []string{"", strings.Repeat("1", 33), "1a", "-1"} {
		if VerifyPoW("abc", bad, 0) || VerifyPoW("abc", bad, 12) {
			t.Errorf("accepted %q", bad)
		}
	}
	if VerifyPoW("abc", "0", 33) || VerifyPoW("abc", "0", -1) {
		t.Error("out-of-range bits accepted")
	}
	for i := 0; ; i++ {
		s := strconv.Itoa(i)
		if leadingZeros("abc", s) == 11 {
			if VerifyPoW("abc", s, 12) {
				t.Fatalf("accepted %q with 11 zero bits", s)
			}
			break
		}
	}
}
