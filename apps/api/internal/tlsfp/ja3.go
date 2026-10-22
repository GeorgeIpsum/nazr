package tlsfp

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"
)

func ja3(ch *ClientHello) (string, string) {
	dec := func(in []uint16) string {
		parts := make([]string, 0, len(in))
		for _, v := range in {
			if !IsGrease(v) {
				parts = append(parts, strconv.Itoa(int(v)))
			}
		}
		return strings.Join(parts, "-")
	}
	pts := make([]string, len(ch.PointFormats))
	for i, p := range ch.PointFormats {
		pts[i] = strconv.Itoa(int(p))
	}
	s := strings.Join([]string{
		strconv.Itoa(int(ch.LegacyVersion)),
		dec(ch.CipherSuites),
		dec(ch.Extensions),
		dec(ch.SupportedGroups),
		strings.Join(pts, "-"),
	}, ",")
	sum := md5.Sum([]byte(s))
	return s, hex.EncodeToString(sum[:])
}
