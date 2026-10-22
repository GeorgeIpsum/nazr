package fingerprint

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDecode(t *testing.T) {
	c, err := Decode(strings.NewReader(`{"a":1.50}`), 100)
	if err != nil || c["a"] != json.Number("1.50") {
		t.Fatalf("got %v %v", c, err)
	}
	if _, err := Decode(strings.NewReader(`{"a":"`+strings.Repeat("x", 100)+`"}`), 50); !errors.Is(err, ErrTooLarge) {
		t.Errorf("want ErrTooLarge, got %v", err)
	}
	if _, err := Decode(strings.NewReader(`{"a":1}`), 7); err != nil {
		t.Errorf("exactly at limit must pass: %v", err)
	}
	for _, in := range []string{`[1]`, `"x"`, `null`, `3`} {
		if _, err := Decode(strings.NewReader(in), 100); !errors.Is(err, ErrNotObject) {
			t.Errorf("%s: want ErrNotObject, got %v", in, err)
		}
	}
	if _, err := Decode(strings.NewReader(`{"a":1} x`), 100); err == nil {
		t.Error("trailing data must fail")
	}
}

func TestDecodeLoneSurrogates(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"a":"\ud83d"}`, `{"a":"\ud83d"}`},
		{`{"a":"\udc00"}`, `{"a":"\udc00"}`},
		{`{"a":"\ud83dA"}`, `{"a":"\ud83dA"}`},
		{`{"a":"\ud83d\u0041"}`, `{"a":"\ud83dA"}`},
		{`{"\ud83d":"\uD83D\uDE00"}`, "{\"\\ud83d\":\"\U0001F600\"}"},
		{`{"a":"😀"}`, "{\"a\":\"\U0001F600\"}"},
		{`{"a":"\ud83d\ude00"}`, "{\"a\":\"\U0001F600\"}"},
		{`{"a":"\\ud83d"}`, `{"a":"\\ud83d"}`},
		{`{"a":"\\\ud83d"}`, `{"a":"\\\ud83d"}`},
		{`{"a":"\uf8ff\ud83d"}`, "{\"a\":\"\uf8ff\\ud83d\"}"},
		{"{\"a\":\"\uf8ffx0041\"}", "{\"a\":\"\uf8ffx0041\"}"},
	}
	for _, c := range cases {
		m, err := Decode(strings.NewReader(c.in), 1000)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if got := StableStringify(m); got != c.want {
			t.Errorf("%s: got %s want %s", c.in, got, c.want)
		}
	}
}

func TestDecodeTrailingSentinel(t *testing.T) {
	if _, err := Decode(strings.NewReader(`{} {}`), 100); !errors.Is(err, ErrTrailingData) {
		t.Errorf("got %v", err)
	}
}
