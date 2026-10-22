package fingerprint

// rule mirrors an entry of stabilizationExclusionRules in
// packages/thumbmark/src/options.ts. A nil browsers list applies to everyone.
type rule struct {
	exclude  []string
	browsers []string
}

var stabilizationExclusionRules = map[string][]rule{
	"private": {
		{[]string{"canvas"}, []string{"firefox", "safari>=17", "brave"}},
		{[]string{"audio"}, []string{"samsungbrowser", "safari"}},
		{[]string{"fonts"}, []string{"firefox"}},
		{[]string{
			"audio.sampleHash",
			"hardware.deviceMemory",
			"header.acceptLanguage.q",
			"system.hardwareConcurrency",
			"plugins",
		}, []string{"brave"}},
		{[]string{"tls.extensions"}, []string{"firefox", "chrome", "safari"}},
		{[]string{"header.acceptLanguage"}, []string{"edge", "chrome"}},
		// Fork additions.
		{[]string{"clientrects"}, []string{"firefox", "brave"}},
		{[]string{"clienthints"}, []string{"brave"}},
	},
	"iframe": {
		{[]string{"system.applePayVersion", "system.cookieEnabled"}, []string{"safari"}},
		{[]string{"permissions"}, nil},
	},
	"vpn":    {{[]string{"ip"}, nil}},
	"always": {{[]string{"speech"}, []string{"brave", "firefox"}}},
}
