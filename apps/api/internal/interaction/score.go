package interaction

type rule struct {
	signal string
	test   func(Trace) bool
}

// RuleInfo describes one scoring rule.
type RuleInfo struct {
	Signal string
}

// pathExpected reports whether the trace should carry a pointer path: a mouse
// or pen click. Touch and keyboard activations legitimately have none.
func pathExpected(t Trace) bool {
	return t.Input == "pointer" && (t.PointerType == "mouse" || t.PointerType == "pen")
}

var rules = []rule{
	{"untrusted_event", func(t Trace) bool { return !t.Trusted }},
	{"too_fast", func(t Trace) bool { return t.ClickMS-t.ShownMS < MinClickMS }},
	{"too_slow", func(t Trace) bool { return t.ClickMS-t.ShownMS > MaxClickMS }},
	{"hidden_document", func(t Trace) bool { return !t.Visible }},
	{"no_pointer_path", func(t Trace) bool { return pathExpected(t) && t.Moves < MinMoves }},
	{"straight_path", func(t Trace) bool { return pathExpected(t) && t.Straightness >= MaxStraightness }},
	{"malformed_trace", func(t Trace) bool { return !t.Valid() }},
}

// Rules lists the scoring rules in table order, for the docs.
func Rules() []RuleInfo {
	out := make([]RuleInfo, len(rules))
	for i, r := range rules {
		out[i] = RuleInfo{r.signal}
	}
	return out
}

// Score evaluates every rule, even on a malformed trace, and returns whether
// none fired along with each rule's result keyed by signal name.
func Score(t Trace) (ok bool, signals map[string]bool) {
	signals = make(map[string]bool, len(rules))
	ok = true
	for _, r := range rules {
		fired := r.test(t)
		signals[r.signal] = fired
		if fired {
			ok = false
		}
	}
	return ok, signals
}
