// Package interaction scores the click-to-verify trace the widget frame
// records while a visitor presses its button.
package interaction

import "math"

// Bounds and thresholds for a Trace.
const (
	MinClickMS      = 300    // fastest plausible delay between button shown and click
	MaxClickMS      = 600000 // slowest delay before the click is treated as stale
	MinMoves        = 3      // fewest pointer moves a mouse or pen click should show
	MaxStraightness = 0.98   // straightness at or above this is a synthetic path

	maxTimeMS   = 86400000 // validity bound for shown_ms and click_ms
	maxMoves    = 200
	maxPathPX   = 1e6
	maxStringLn = 16
)

// Trace is the small interaction summary the frame sends with a solve.
// ShownMS is when the button appeared and ClickMS when it was activated, both
// in milliseconds since the frame loaded.
type Trace struct {
	ShownMS      int     `json:"shown_ms"`
	ClickMS      int     `json:"click_ms"`
	Input        string  `json:"input"` // "pointer" or "keyboard"
	Trusted      bool    `json:"trusted"`
	Moves        int     `json:"moves"`
	PathPX       float64 `json:"path_px"`
	Straightness float64 `json:"straightness"` // chord length over path length, 0..1
	PointerType  string  `json:"pointer_type"` // "mouse", "touch", "pen" or ""
	Visible      bool    `json:"visible"`
}

func finite(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) }

// Valid reports whether every field is inside its bounds and enum.
func (t Trace) Valid() bool {
	if t.ShownMS < 0 || t.ShownMS > maxTimeMS || t.ClickMS < 0 || t.ClickMS > maxTimeMS {
		return false
	}
	if t.Moves < 0 || t.Moves > maxMoves {
		return false
	}
	if !finite(t.PathPX) || t.PathPX < 0 || t.PathPX > maxPathPX {
		return false
	}
	if !finite(t.Straightness) || t.Straightness < 0 || t.Straightness > 1 {
		return false
	}
	if len(t.Input) > maxStringLn || len(t.PointerType) > maxStringLn {
		return false
	}
	if t.Input != "pointer" && t.Input != "keyboard" {
		return false
	}
	switch t.PointerType {
	case "mouse", "touch", "pen", "":
	default:
		return false
	}
	return true
}
