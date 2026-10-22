package h2fp

import "strconv"

// Component returns the `h2` fingerprint component. Settings keys are decimal
// ids with uint32 values; priorities is a non-nil []string.
func (r *Result) Component() map[string]any {
	settings := make(map[string]any, len(r.Settings))
	for _, s := range r.Settings {
		settings[strconv.Itoa(int(s.ID))] = s.Value
	}
	return map[string]any{
		"fingerprint":         Akamai(r),
		"settings":            settings,
		"window_update":       r.WindowUpdate,
		"priorities":          priorityStrings(r),
		"pseudo_header_order": phoString(r),
	}
}
