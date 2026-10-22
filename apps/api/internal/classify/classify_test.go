package classify

import (
	"slices"
	"testing"

	"nazr/api/internal/ipintel"
)

const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

func clean() Input {
	return Input{
		IP:                    ipintel.Lookup{Country: "US"},
		HasTLS:                true,
		UserAgent:             chromeUA,
		AcceptLanguagePresent: true,
		Timezone:              "America/New_York",
	}
}

func active(o Output) []string {
	var s []string
	for k, v := range o.Signals {
		if v {
			s = append(s, k)
		}
	}
	slices.Sort(s)
	return s
}

func TestClassifyTable(t *testing.T) {
	tor := clean()
	tor.IP.Tor = true
	dc := clean()
	dc.IP.Datacenter = true
	wd := clean()
	wd.Webdriver = true
	wd.UserAgent = "Mozilla/5.0 HeadlessChrome/126.0.0.0 Safari/537.36"
	pr := clean()
	pr.IP.PrivateRelay = true
	tz := clean()
	tz.Timezone = "Europe/Berlin"
	all := Input{
		IP:            ipintel.Lookup{Country: "US", Tor: true, VPN: true, Datacenter: true},
		UserAgent:     "Mozilla/5.0 HeadlessChrome/126.0.0.0 Safari/537.36",
		Timezone:      "Europe/Berlin",
		Webdriver:     true,
		JA4Families:   []string{"firefox"},
		H2Fingerprint: knownAutomationH2[0],
	}

	cases := []struct {
		name   string
		in     Input
		level  int
		bot    bool
		signal []string
	}{
		{"clean", clean(), 0, false, nil},
		{"tor", tor, 3, false, []string{"tor_exit"}},
		{"datacenter chrome", dc, 3, false, []string{"datacenter", "datacenter_browser_ua"}},
		{"webdriver headless", wd, 4, true, []string{"headless_ua", "webdriver"}},
		{"private relay", pr, 0, false, nil},
		{"tz mismatch", tz, 1, false, []string{"timezone_country_mismatch"}},
		{"everything", all, 5, true, nil},
	}
	for _, c := range cases {
		o := Classify(c.in)
		if o.DangerLevel != c.level || o.Bot != c.bot {
			t.Errorf("%s: level=%d bot=%v, want %d %v (%v)", c.name, o.DangerLevel, o.Bot, c.level, c.bot, active(o))
		}
		if c.signal != nil && !slices.Equal(active(o), c.signal) {
			t.Errorf("%s: signals %v, want %v", c.name, active(o), c.signal)
		}
		if c.name == "clean" && len(active(o)) != 0 {
			t.Errorf("clean has signals %v", active(o))
		}
		if len(o.Signals) != len(Rules()) {
			t.Errorf("%s: Signals has %d entries, want %d", c.name, len(o.Signals), len(Rules()))
		}
	}
	if o := Classify(pr); !o.PrivateRelay || !Classify(tor).Tor {
		t.Error("ip booleans not propagated")
	}
	if o := Classify(all); !o.VPN || !o.Datacenter {
		t.Error("vpn/datacenter not propagated")
	}
}

func TestUATLSMismatch(t *testing.T) {
	in := clean()
	in.JA4Families = []string{"firefox"}
	if !Classify(in).Signals["ua_tls_mismatch"] {
		t.Error("chrome UA vs firefox corpus should mismatch")
	}
	in.JA4Families = []string{"chrome", "firefox"}
	if Classify(in).Signals["ua_tls_mismatch"] {
		t.Error("chrome in corpus should not mismatch")
	}
	in.UserAgent = chromeUA + " Edg/126.0"
	in.JA4Families = []string{"chrome"}
	if Classify(in).Signals["ua_tls_mismatch"] {
		t.Error("edge should match chrome corpus")
	}
	in.JA4Families = nil
	in.UserAgent = "curl/8.0"
	if Classify(in).Signals["ua_tls_mismatch"] {
		t.Error("empty corpus must not claim")
	}
	in.JA4Families = []string{"firefox"}
	if Classify(in).Signals["ua_tls_mismatch"] {
		t.Error("non-browser UA must not mismatch")
	}
}

func TestMissingAcceptLanguage(t *testing.T) {
	in := clean()
	in.AcceptLanguagePresent = false
	if !Classify(in).Signals["missing_accept_language"] {
		t.Error("browser without Accept-Language")
	}
	in.UserAgent = "curl/8.0"
	if Classify(in).Signals["missing_accept_language"] {
		t.Error("curl without Accept-Language is normal")
	}
}

func TestTimezoneMismatchEdges(t *testing.T) {
	in := clean()
	in.Timezone = "Mars/Olympus"
	if Classify(in).Signals["timezone_country_mismatch"] {
		t.Error("unknown tz")
	}
	in.Timezone = "Europe/Berlin"
	in.IP.Country = ""
	if Classify(in).Signals["timezone_country_mismatch"] {
		t.Error("empty country")
	}
	in.IP.Country = "de"
	if Classify(in).Signals["timezone_country_mismatch"] {
		t.Error("case-insensitive match")
	}
}

func TestH2Automation(t *testing.T) {
	in := clean()
	in.H2Fingerprint = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	if Classify(in).Signals["h2_automation"] {
		t.Error("chrome h2 flagged")
	}
	for _, f := range knownAutomationH2 {
		in.H2Fingerprint = f
		if !Classify(in).Signals["h2_automation"] {
			t.Errorf("%q not flagged", f)
		}
	}
}

func TestTimezoneCountries(t *testing.T) {
	if got := TimezoneCountries("America/New_York"); !slices.Equal(got, []string{"US"}) {
		t.Errorf("got %v", got)
	}
	if got := TimezoneCountries("Europe/Zurich"); !slices.Contains(got, "CH") {
		t.Errorf("got %v", got)
	}
	if got := TimezoneCountries("US/Eastern"); !slices.Equal(got, []string{"US"}) {
		t.Errorf("alias: %v", got)
	}
	if got := TimezoneCountries("Asia/Calcutta"); !slices.Contains(got, "IN") {
		t.Errorf("alias: %v", got)
	}
	if got := TimezoneCountries("Nope/Nowhere"); got != nil {
		t.Errorf("got %v", got)
	}
}

func TestRules(t *testing.T) {
	r := Rules()
	if len(r) != 11 {
		t.Fatalf("len = %d", len(r))
	}
}
