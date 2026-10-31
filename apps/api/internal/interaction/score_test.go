package interaction

import (
	"slices"
	"testing"
)

func base() Trace {
	return Trace{ShownMS: 1000, ClickMS: 2840, Input: "pointer", Trusted: true, Moves: 41,
		PathPX: 512.3, Straightness: 0.71, PointerType: "mouse", Visible: true}
}

func TestScoreRules(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*Trace)
		fired string // "" means ok
	}{
		{"base", func(*Trace) {}, ""},
		{"untrusted", func(x *Trace) { x.Trusted = false }, "untrusted_event"},
		{"too fast", func(x *Trace) { x.ClickMS = 1299 }, "too_fast"},
		{"too slow", func(x *Trace) { x.ClickMS = 601001 }, "too_slow"},
		{"hidden", func(x *Trace) { x.Visible = false }, "hidden_document"},
		{"no path", func(x *Trace) { x.Moves = 0 }, "no_pointer_path"},
		{"pen no path", func(x *Trace) { x.PointerType, x.Moves = "pen", 0 }, "no_pointer_path"},
		{"one move ok", func(x *Trace) { x.Moves = 1 }, ""},
		{"two moves ok", func(x *Trace) { x.Moves = 2 }, ""},
		{"straight", func(x *Trace) { x.Straightness = 0.98 }, "straight_path"},
		{"perfectly straight", func(x *Trace) { x.Straightness = 1 }, "straight_path"},
		{"touch ok", func(x *Trace) { x.PointerType, x.Moves, x.Straightness = "touch", 0, 1 }, ""},
		{"keyboard ok", func(x *Trace) { x.Input, x.PointerType, x.Moves, x.Straightness = "keyboard", "", 0, 1 }, ""},
		{"moves 201", func(x *Trace) { x.Moves = 201 }, "malformed_trace"},
		{"bad input", func(x *Trace) { x.Input = "tap" }, "malformed_trace"},
		{"bad pointer type", func(x *Trace) { x.PointerType = "stylus" }, "malformed_trace"},
		{"straightness 1.5", func(x *Trace) { x.Straightness = 1.5 }, "malformed_trace"},
		{"negative path", func(x *Trace) { x.PathPX = -1 }, "malformed_trace"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := base()
			c.mut(&tr)
			ok, sig := Score(tr)
			if len(sig) != len(Rules()) {
				t.Fatalf("signals has %d keys, want %d", len(sig), len(Rules()))
			}
			// straight_path is advisory: it fires but does not fail the attempt.
			if wantOK := c.fired == "" || c.fired == "straight_path"; ok != wantOK {
				t.Fatalf("ok = %v, signals %v", ok, sig)
			}
			if c.fired == "malformed_trace" {
				// other rules still run on raw values, so only require this one.
				if !sig[c.fired] {
					t.Errorf("malformed_trace not fired")
				}
				return
			}
			for k, v := range sig {
				if v != (k == c.fired) {
					t.Errorf("signal %s = %v, want %v", k, v, k == c.fired)
				}
			}
		})
	}
}

func TestStraightPathWithNoPointerPathFails(t *testing.T) {
	tr := base()
	tr.Moves, tr.Straightness = 0, 1
	ok, sig := Score(tr)
	if ok || !sig["straight_path"] || !sig["no_pointer_path"] {
		t.Fatalf("ok = %v, signals %v", ok, sig)
	}
}

func TestRulesOrder(t *testing.T) {
	var got []string
	for _, r := range Rules() {
		got = append(got, r.Signal)
		if r.Advisory != (r.Signal == "straight_path") {
			t.Errorf("%s advisory = %v", r.Signal, r.Advisory)
		}
	}
	want := []string{"untrusted_event", "too_fast", "too_slow", "hidden_document", "no_pointer_path", "straight_path", "malformed_trace"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestValidRejectsNonFiniteAndLongStrings(t *testing.T) {
	nan := base()
	nan.PathPX = nan.PathPX - nan.PathPX
	nan.PathPX = nan.PathPX / nan.PathPX
	if nan.Valid() {
		t.Error("NaN accepted")
	}
	long := base()
	long.PointerType = "mouseeeeeeeeeeeeeeeee"
	if long.Valid() {
		t.Error("long string accepted")
	}
}
