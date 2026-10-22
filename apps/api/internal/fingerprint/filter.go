package fingerprint

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// Options mirrors the include/exclude/stabilize filtering options.
type Options struct {
	Include, Exclude, Stabilize []string
}

// OptionsFromRequest extracts Options from a decoded request options object.
// Fields that are not arrays are ignored, as are non-string entries.
func OptionsFromRequest(opts map[string]any) Options {
	return Options{
		Include:   stringList(opts["include"]),
		Exclude:   stringList(opts["exclude"]),
		Stabilize: stringList(opts["stabilize"]),
	}
}

func stringList(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

var versionedBrowser = regexp.MustCompile(`(.+?)(>=)(\d+)`)

// browserOf reads components.system.browser.{name,version} like the
// server-side path of getExcludeList. ok is false for an unknown major version.
func browserOf(c Components) (name string, major int, ok bool) {
	sys, _ := c["system"].(map[string]any)
	b, _ := sys["browser"].(map[string]any)
	n := scalarString(b["name"])
	if n == "" {
		return "unknown", 0, false
	}
	ver := scalarString(b["version"])
	if ver == "" {
		ver = "unknown"
	}
	first, _, _ := strings.Cut(ver, ".")
	if first == "" {
		first = "0"
	}
	end := 0
	for end < len(first) && first[end] >= '0' && first[end] <= '9' {
		end++
	}
	if end == 0 {
		return strings.ToLower(n), 0, false // parseInt -> NaN
	}
	m, err := strconv.Atoi(first[:end])
	return strings.ToLower(n), m, err == nil
}

func scalarString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	}
	return ""
}

func excludeList(c Components, o Options) []string {
	name, major, haveMajor := browserOf(c)
	list := append([]string(nil), o.Exclude...)
	seen := map[string]bool{}
	for _, opt := range append(append([]string(nil), o.Stabilize...), "always") {
		if seen[opt] {
			continue
		}
		seen[opt] = true
		for _, r := range stabilizationExclusionRules[opt] {
			if r.browsers == nil || matchesBrowser(r.browsers, name, major, haveMajor) {
				list = append(list, r.exclude...)
			}
		}
	}
	return list
}

func matchesBrowser(browsers []string, name string, major int, haveMajor bool) bool {
	for _, br := range browsers {
		if m := versionedBrowser.FindStringSubmatch(br); m != nil {
			min, _ := strconv.Atoi(m[3])
			if name == m[1] && haveMajor && major >= min {
				return true
			}
		} else if name == br {
			return true
		}
	}
	return false
}

func hasPrefixAny(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// Filter ports filterThumbmarkData: leaves whose dotted path starts with an
// excluded prefix are dropped unless they also start with an included prefix,
// and objects left empty are removed. The input is not modified; the result is
// a deep copy.
func Filter(c Components, o Options) Components {
	ex := excludeList(c, o)
	return filterNode(c, "", ex, o.Include)
}

func filterNode(m map[string]any, path string, ex, in []string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		p := k
		if path != "" {
			p = path + "." + k
		}
		if sub, ok := v.(map[string]any); ok {
			if f := filterNode(sub, p, ex, in); len(f) > 0 {
				out[k] = f
			}
			continue
		}
		if !hasPrefixAny(p, ex) || hasPrefixAny(p, in) {
			out[k] = deepCopy(v)
		}
	}
	return out
}

func deepCopy(v any) any {
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = deepCopy(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = deepCopy(e)
		}
		return out
	}
	return v
}
