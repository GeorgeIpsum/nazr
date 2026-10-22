package fingerprint

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

type stringifyCase struct {
	Name        string          `json:"name"`
	Input       json.RawMessage `json:"input"`
	Stringified string          `json:"stringified"`
	Hash        string          `json:"hash"`
}

func loadStringify(t *testing.T) []stringifyCase {
	t.Helper()
	var cases []stringifyCase
	if err := json.Unmarshal(readFixture(t, "stringify.json"), &cases); err != nil {
		t.Fatal(err)
	}
	return cases
}

func TestStableStringifyFixtures(t *testing.T) {
	cases := loadStringify(t)
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			if got := StableStringify(decodeJSON(t, c.Input)); got != c.Stringified {
				t.Errorf("got  %s\nwant %s", got, c.Stringified)
			}
		})
	}
	t.Logf("%d cases", len(cases))
}

func TestHashFixtures(t *testing.T) {
	for _, c := range loadStringify(t) {
		t.Run(c.Name, func(t *testing.T) {
			if got := Murmur128Hex(StableStringify(decodeJSON(t, c.Input))); got != c.Hash {
				t.Errorf("got %s want %s", got, c.Hash)
			}
		})
	}
}

func TestHashOfComponents(t *testing.T) {
	c := Components{"a": "x"}
	if Hash(c) != Murmur128Hex(`{"a":"x"}`) {
		t.Fatal("Hash must be Murmur128Hex(StableStringify(c))")
	}
}

func TestKeyOrderIsUTF16(t *testing.T) {
	v := map[string]any{"￿": 1.0, "\U0001F600": 2.0}
	want := "{\"\U0001F600\":2,\"￿\":1}"
	if got := StableStringify(v); got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestStringifyNumberSpecials(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{math.Copysign(0, -1), "0"},
		{math.NaN(), "null"},
		{math.Inf(1), "null"},
		{json.Number("1e999"), "null"},
		{json.Number("1e21"), "1e+21"},
		{json.Number("9007199254740993"), "9007199254740992"},
		{1.5, "1.5"},
	}
	for _, c := range cases {
		if got := StableStringify(c.in); got != c.want {
			t.Errorf("StableStringify(%v) = %q want %q", c.in, got, c.want)
		}
	}
}

func TestStringifyNested(t *testing.T) {
	v := map[string]any{
		"z": []any{json.Number("1"), nil, "a", map[string]any{"b": true, "a": json.Number("2.50")}},
		"a": map[string]any{},
		"m": nil,
	}
	want := `{"a":{},"m":null,"z":[1,null,"a",{"a":2.5,"b":true}]}`
	if got := StableStringify(v); got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

func TestStringEscaping(t *testing.T) {
	cases := map[string]string{
		"\"\\":                `"\"\\"`,
		"\b\f\n\r\t":          `"\b\f\n\r\t"`,
		"\x00\x1f":            `"\u0000\u001f"`,
		"\x7f\u2028\u2029<>&": "\"\x7f\u2028\u2029<>&\"",
		"\xed\xa0\xbd":        `"\ud83d"`, // lone surrogate encoded as (invalid) UTF-8
	}
	for in, want := range cases {
		if got := StableStringify(in); got != want {
			t.Errorf("escape(%q) = %q want %q", in, got, want)
		}
	}
	if strings.Contains(StableStringify("<"), "\\u003c") {
		t.Error("must not HTML-escape")
	}
}
