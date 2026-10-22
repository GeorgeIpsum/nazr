package ipintel

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"github.com/gaissmai/bart"
)

// PrefixTable maps CIDR prefixes to values using a longest-prefix-match trie.
type PrefixTable[T any] struct {
	t    bart.Table[T]
	rows int
}

func (p *PrefixTable[T]) insert(pfx netip.Prefix, v T) {
	p.t.Insert(pfx.Masked(), v)
	p.rows++
}

// Lookup returns the value of the longest prefix containing addr.
func (p *PrefixTable[T]) Lookup(addr netip.Addr) (T, bool) {
	return p.t.Lookup(addr.Unmap())
}

// Rows is the number of prefixes parsed.
func (p *PrefixTable[T]) Rows() int { return p.rows }

// parsePrefix accepts "a.b.c.d/n" or a bare address.
func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		pfx, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(pfx.Addr().Unmap(), unmapBits(pfx)), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func unmapBits(p netip.Prefix) int {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		return p.Bits() - 96
	}
	return p.Bits()
}

// parseCIDRList reads one CIDR (or bare IP) per line; blank lines and
// '#' comments (whole-line or trailing) are ignored, and malformed lines
// are skipped. A non-empty input with no valid rows is an error.
func parseCIDRList(r io.Reader) (*PrefixTable[struct{}], error) {
	pt := &PrefixTable[struct{}]{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pfx, err := parsePrefix(line)
		if err != nil {
			continue
		}
		pt.insert(pfx, struct{}{})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if pt.rows == 0 {
		return nil, errEmpty
	}
	return pt, nil
}

func loadCIDRFile(path string) (*PrefixTable[struct{}], error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseCIDRList(f)
}

// relayEntry is the location Apple publishes for an egress range.
type relayEntry struct{ Country, Region, City string }

// parseAppleCSV reads Apple's `cidr,country,region,city,` rows.
func parseAppleCSV(r io.Reader) (*PrefixTable[relayEntry], error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = true
	pt := &PrefixTable[relayEntry]{}
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("apple csv: %w", err)
		}
		if len(rec) < 4 {
			continue
		}
		pfx, err := parsePrefix(strings.TrimSpace(rec[0]))
		if err != nil {
			continue
		}
		pt.insert(pfx, relayEntry{
			Country: strings.TrimSpace(rec[1]),
			Region:  strings.TrimSpace(rec[2]),
			City:    strings.TrimSpace(rec[3]),
		})
	}
	if pt.rows == 0 {
		return nil, errEmpty
	}
	return pt, nil
}

// JA4Table maps a JA4 fingerprint to the sorted unique lowercase
// application names FoxIO's database associates with it.
type JA4Table struct {
	m map[string][]string
}

// Rows is the number of distinct fingerprints.
func (t *JA4Table) Rows() int { return len(t.m) }

// Families returns a copy of the application names for ja4, never nil.
func (t *JA4Table) Families(ja4 string) []string {
	return append([]string{}, t.m[ja4]...)
}
