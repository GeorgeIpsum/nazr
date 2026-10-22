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
