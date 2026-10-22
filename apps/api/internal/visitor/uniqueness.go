package visitor

import "math"

// Uniqueness scores how unique a thumbmark is among the visitors under a key:
// 1 - (sharing-1)/max(total,1), rounded to 4 decimals and clamped to [0,1].
// A sharing count below 1 is treated as 1.
func Uniqueness(sharing, total int64) float64 {
	sharing = max(sharing, 1)
	score := 1 - float64(sharing-1)/float64(max(total, 1))
	score = math.Round(score*1e4) / 1e4
	return math.Min(1, math.Max(0, score))
}
