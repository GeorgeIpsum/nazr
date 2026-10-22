package classify

import (
	"bufio"
	_ "embed"
	"strings"
	"sync"
)

// zone1970.tab is the IANA tz database file of the same name (public domain).
// It is data only and is parsed, never executed.
//
//go:embed zone1970.tab
var zone1970 string

// tzAliases maps common legacy names absent from zone1970.tab (IANA
// "backward") to their canonical zone.
var tzAliases = map[string]string{
	"US/Eastern":    "America/New_York",
	"US/Pacific":    "America/Los_Angeles",
	"Asia/Calcutta": "Asia/Kolkata",
	"Europe/Kiev":   "Europe/Kyiv",
	"Asia/Saigon":   "Asia/Ho_Chi_Minh",
}

var (
	tzOnce  sync.Once
	tzTable map[string][]string
)

func loadTZ() {
	tzTable = make(map[string][]string, 512)
	sc := bufio.NewScanner(strings.NewReader(zone1970))
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 3 {
			continue
		}
		tzTable[f[2]] = strings.Split(f[0], ",")
	}
}

// TimezoneCountries returns the ISO country codes sharing an IANA timezone,
// or nil when the timezone is unknown.
func TimezoneCountries(tz string) []string {
	tzOnce.Do(loadTZ)
	if a, ok := tzAliases[tz]; ok {
		tz = a
	}
	c := tzTable[tz]
	if c == nil {
		return nil
	}
	return append([]string(nil), c...)
}
