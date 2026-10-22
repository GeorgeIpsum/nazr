package fingerprint

import (
	"encoding/json"
	"reflect"
	"testing"
)

type filterCase struct {
	Name       string          `json:"name"`
	Components json.RawMessage `json:"components"`
	Options    map[string]any  `json:"options"`
	Filtered   json.RawMessage `json:"filtered"`
}

func TestFilterFixtures(t *testing.T) {
	var cases []filterCase
	if err := json.Unmarshal(readFixture(t, "filter.json"), &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			in := decodeJSON(t, c.Components).(map[string]any)
			want := decodeJSON(t, c.Filtered)
			got := Filter(in, OptionsFromRequest(c.Options))
			if !reflect.DeepEqual(any(map[string]any(got)), want) {
				t.Errorf("got  %s\nwant %s", StableStringify(got), StableStringify(want))
			}
		})
	}
	t.Logf("%d cases", len(cases))
}

func TestFilterDoesNotMutate(t *testing.T) {
	in := Components{
		"system": map[string]any{"browser": map[string]any{"name": "Firefox", "version": "120.0"}},
		"canvas": map[string]any{"h": "x"},
		"list":   []any{"a"},
	}
	before := StableStringify(in)
	out := Filter(in, Options{Stabilize: []string{"private"}})
	if StableStringify(in) != before {
		t.Fatal("input mutated")
	}
	if _, ok := out["canvas"]; ok {
		t.Fatal("canvas should be excluded for firefox/private")
	}
	out["list"].([]any)[0] = "changed"
	out["system"].(map[string]any)["x"] = 1
	if StableStringify(in) != before {
		t.Fatal("output shares memory with input")
	}
}

func TestOptionsFromRequest(t *testing.T) {
	o := OptionsFromRequest(map[string]any{
		"include": []any{"a", 3.0}, "exclude": "nope", "stabilize": []any{"private"},
	})
	if !reflect.DeepEqual(o, Options{Include: []string{"a"}, Stabilize: []string{"private"}}) {
		t.Errorf("got %+v", o)
	}
	if !reflect.DeepEqual(OptionsFromRequest(nil), Options{}) {
		t.Error("nil opts")
	}
}

func TestParseMajor(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{" 17", 17, true}, {"+17", 17, true}, {"17.1", 17, true}, {"abc", 0, false},
		{"", 0, true}, {"-3", -3, true}, {"99999999999999999999", maxInt, true},
		{"unknown", 0, false},
	}
	for _, c := range cases {
		if got, ok := parseMajor(c.in); got != c.want || ok != c.ok {
			t.Errorf("parseMajor(%q) = %d,%v want %d,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestSafariVersionRule(t *testing.T) {
	for _, c := range []struct {
		ver  any
		drop bool
	}{
		{" 17", true}, {"+17", true}, {"17.1", true}, {"abc", false}, {"", false},
		{"99999999999999999999", true}, {"16.9", false}, {json.Number("1.7e1"), true},
	} {
		in := Components{
			"system": map[string]any{"browser": map[string]any{"name": "Safari", "version": c.ver}},
			"canvas": map[string]any{"h": "x"},
		}
		_, kept := Filter(in, Options{Stabilize: []string{"private"}})["canvas"]
		if kept == c.drop {
			t.Errorf("version %v: canvas kept=%v", c.ver, kept)
		}
	}
}
