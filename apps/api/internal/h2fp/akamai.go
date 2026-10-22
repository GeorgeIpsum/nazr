package h2fp

import (
	"strconv"
	"strings"
)

// Akamai renders the Akamai HTTP/2 fingerprint "S|WU|P|PHO".
func Akamai(r *Result) string {
	s := make([]string, 0, len(r.Settings))
	for _, st := range r.Settings {
		s = append(s, strconv.Itoa(int(st.ID))+":"+strconv.FormatUint(uint64(st.Value), 10))
	}
	p := "0"
	if len(r.Priorities) > 0 {
		ps := priorityStrings(r)
		p = strings.Join(ps, ",")
	}
	pho := phoString(r)
	return strings.Join(s, ";") + "|" + strconv.FormatUint(uint64(r.WindowUpdate), 10) + "|" + p + "|" + pho
}

func priorityStrings(r *Result) []string {
	out := make([]string, 0, len(r.Priorities))
	for _, p := range r.Priorities {
		ex := "0"
		if p.Exclusive {
			ex = "1"
		}
		// RFC 7540 encodes weights 1..256 as 0..255; Akamai displays 1..256.
		out = append(out, strconv.FormatUint(uint64(p.StreamID), 10)+":"+ex+":"+
			strconv.FormatUint(uint64(p.DependsOn), 10)+":"+strconv.Itoa(int(p.Weight)+1))
	}
	return out
}

func phoString(r *Result) string {
	pho := make([]string, 0, len(r.PseudoHeaderOrder))
	for _, h := range r.PseudoHeaderOrder {
		h = strings.TrimPrefix(h, ":")
		if h != "" {
			pho = append(pho, h[:1])
		}
	}
	return strings.Join(pho, ",")
}
