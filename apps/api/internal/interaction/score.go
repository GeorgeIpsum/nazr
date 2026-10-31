package interaction

// rule is one row of the scoring table. An advisory rule is still evaluated
// and recorded in the signals, but firing does not fail the attempt.
type rule struct {
	signal   string
	advisory bool
	test     func(Trace) bool
}

// RuleInfo describes one scoring rule.
type RuleInfo struct {
	Signal   string
	Advisory bool // recorded in signals but does not fail the attempt
}

// pathExpected reports whether the trace should carry a pointer path: a mouse
// or pen click. Touch and keyboard activations legitimately have none.
func pathExpected(t Trace) bool {
	return t.Input == "pointer" && (t.PointerType == "mouse" || t.PointerType == "pen")
}

var rules = []rule{
	{"untrusted_event", false, func(t Trace) bool { return !t.Trusted }},
	{"too_fast", false, func(t Trace) bool { return t.ClickMS-t.ShownMS < MinClickMS }},
	{"too_slow", false, func(t Trace) bool { return t.ClickMS-t.ShownMS > MaxClickMS }},
	{"hidden_document", false, func(t Trace) bool { return !t.Visible }},
	{"no_pointer_path", false, func(t Trace) bool { return pathExpected(t) && t.Moves < MinMoves }},
	{"straight_path", true, func(t Trace) bool { return pathExpected(t) && t.Straightness >= MaxStraightness }},
	{"malformed_trace", false, func(t Trace) bool { return !t.Valid() }},
}

// Rules lists the scoring rules in table order, for the docs.
func Rules() []RuleInfo {
	out := make([]RuleInfo, len(rules))
	for i, r := range rules {
		out[i] = RuleInfo{r.signal, r.advisory}
	}
	return out
}

// Score evaluates every rule, even on a malformed trace, and returns each
// rule's result keyed by signal name. ok is true when no non-advisory rule
// fired; advisory rules (straight_path) appear in signals but never clear ok.
func Score(t Trace) (ok bool, signals map[string]bool) {
	signals = make(map[string]bool, len(rules))
	ok = true
	for _, r := range rules {
		fired := r.test(t)
		signals[r.signal] = fired
		if fired && !r.advisory {
			ok = false
		}
	}
	return ok, signals
}
