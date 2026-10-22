// Package classify turns request evidence into a classification and signals
// using the scoring table in spec section 8.
package classify

import (
	"slices"
	"strings"

	"nazr/api/internal/ipintel"
	"nazr/api/internal/ua"
)

// Input is the evidence classify scores.
type Input struct {
	IP                    ipintel.Lookup
	HasTLS                bool
	UserAgent             string
	AcceptLanguagePresent bool
	Timezone              string // components.locales.timezone
	Webdriver             bool   // components.privacy.webdriver, false when absent
	JA4Families           []string
	H2Fingerprint         string
}

// Output is the classification plus every evaluated signal.
type Output struct {
	Tor, VPN, Bot, Datacenter, PrivateRelay bool
	DangerLevel                             int
	Signals                                 map[string]bool
}

// RuleInfo describes one scoring rule.
type RuleInfo struct {
	Signal      string
	Danger, Bot int
}

type rule struct {
	signal      string
	danger, bot int
	test        func(Input) bool
}

const botThreshold = 3

// knownAutomationH2 holds Akamai-style HTTP/2 fingerprints of common
// non-browser clients.
var knownAutomationH2 = []string{
	// Go net/http (x/net/http2 defaults), observed with internal/conn
	// TestH2ClientGetsTLSAndH2.
	"2:0;4:4194304;5:16384;6:10485760|1073741824|0|a,m,p,s",
	// curl (nghttp2) defaults, as documented in the task brief.
	"3:100;4:10485760;2:0|1048510465|0|m,p,a,s",
}

var browserFamilies = []string{"chrome", "edge", "firefox", "safari", "opera", "samsung", "brave"}

func isBrowser(family string) bool { return slices.Contains(browserFamilies, family) }

// tlsFamily collapses Chromium derivatives onto chrome, which shares their
// TLS stack.
func tlsFamily(f string) string {
	switch f {
	case "edge", "opera", "brave", "samsung":
		return "chrome"
	}
	return f
}

// rules is the single scoring table; docs/signals.md mirrors it.
var rules = []rule{
	{"tor_exit", 3, 0, func(in Input) bool { return in.IP.Tor }},
	{"datacenter", 2, 0, func(in Input) bool { return in.IP.Datacenter }},
	{"vpn", 1, 0, func(in Input) bool { return in.IP.VPN }},
	{"private_relay", 0, 0, func(in Input) bool { return in.IP.PrivateRelay }},
	{"webdriver", 2, 3, func(in Input) bool { return in.Webdriver }},
	{"headless_ua", 2, 3, func(in Input) bool { return ua.Headless(in.UserAgent) }},
	{"ua_tls_mismatch", 1, 2, uaTLSMismatch},
	{"h2_automation", 1, 2, func(in Input) bool {
		return in.H2Fingerprint != "" && slices.Contains(knownAutomationH2, in.H2Fingerprint)
	}},
	{"missing_accept_language", 1, 1, func(in Input) bool {
		return !in.AcceptLanguagePresent && isBrowser(ua.Family(in.UserAgent))
	}},
	{"timezone_country_mismatch", 1, 0, tzMismatch},
	{"datacenter_browser_ua", 1, 1, func(in Input) bool {
		return in.IP.Datacenter && isBrowser(ua.Family(in.UserAgent))
	}},
}

func uaTLSMismatch(in Input) bool {
	if len(in.JA4Families) == 0 {
		return false
	}
	fam := ua.Family(in.UserAgent)
	if !isBrowser(fam) {
		return false
	}
	want := tlsFamily(fam)
	for _, f := range in.JA4Families {
		if tlsFamily(strings.ToLower(f)) == want {
			return false
		}
	}
	return true
}

func tzMismatch(in Input) bool {
	cc := strings.ToUpper(in.IP.Country)
	if cc == "" {
		return false
	}
	countries := TimezoneCountries(in.Timezone)
	return len(countries) > 0 && !slices.Contains(countries, cc)
}

// Rules describes the scoring table for documentation.
func Rules() []RuleInfo {
	out := make([]RuleInfo, len(rules))
	for i, r := range rules {
		out[i] = RuleInfo{r.signal, r.danger, r.bot}
	}
	return out
}

// Classify scores the input.
func Classify(in Input) Output {
	o := Output{
		Tor: in.IP.Tor, VPN: in.IP.VPN, Datacenter: in.IP.Datacenter, PrivateRelay: in.IP.PrivateRelay,
		Signals: make(map[string]bool, len(rules)),
	}
	danger, bot := 0, 0
	for _, r := range rules {
		hit := r.test(in)
		o.Signals[r.signal] = hit
		if hit {
			danger += r.danger
			bot += r.bot
		}
	}
	o.DangerLevel = min(max(danger, 0), 5)
	o.Bot = bot >= botThreshold
	return o
}
