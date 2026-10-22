// Package jsnum formats float64 values the way JavaScript's Number::toString does.
package jsnum

import (
	"math"
	"strconv"
	"strings"
)

// Format implements ECMA-262 Number::toString(10). Non-finite values return
// "null" (the client maps them to null when stringifying) and -0 returns "0".
func Format(f float64) string {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "null"
	}
	if f == 0 {
		return "0"
	}
	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}
	// Shortest digits as d.ddde±XX.
	s := strconv.FormatFloat(f, 'e', -1, 64)
	mant, expStr, _ := strings.Cut(s, "e")
	exp, _ := strconv.Atoi(expStr)
	digits := strings.Replace(mant, ".", "", 1)
	k := len(digits)
	n := exp + 1

	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		e := n - 1
		es := "+"
		if e < 0 {
			es = "-"
			e = -e
		}
		if k == 1 {
			out = digits + "e" + es + strconv.Itoa(e)
		} else {
			out = digits[:1] + "." + digits[1:] + "e" + es + strconv.Itoa(e)
		}
	}
	return sign + out
}
