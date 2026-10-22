package jsnum

import (
	"encoding/json"
	"math"
	"os"
	"strconv"
	"testing"
)

func TestFormatFixtures(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/fixtures/numbers.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Value    json.Number `json:"value"`
		Expected string      `json:"expected"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		f, err := strconv.ParseFloat(c.Value.String(), 64)
		if err != nil {
			t.Fatal(err)
		}
		if got := Format(f); got != c.Expected {
			t.Errorf("Format(%s) = %q, want %q", c.Value, got, c.Expected)
		}
	}
	t.Logf("%d fixture cases", len(cases))
}

func TestFormatSpecials(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{math.NaN(), "null"},
		{math.Inf(1), "null"},
		{math.Inf(-1), "null"},
		{math.Copysign(0, -1), "0"},
		{1e21, "1e+21"},
		{1e-7, "1e-7"},
		{123456789, "123456789"},
		{0.000001, "0.000001"},
		{1.5e300, "1.5e+300"},
		{-1.5e-10, "-1.5e-10"},
		{1e20, "100000000000000000000"},
		{-12.5, "-12.5"},
	}
	for _, c := range cases {
		if got := Format(c.in); got != c.want {
			t.Errorf("Format(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
