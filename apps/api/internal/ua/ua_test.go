package ua

import "testing"

func TestFamily(t *testing.T) {
	cases := []struct{ name, ua, want string }{
		{"chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", "chrome"},
		{"edge", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0", "edge"},
		{"firefox", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0", "firefox"},
		{"safari ios", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1", "safari"},
		{"chrome ios", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.0.0 Mobile/15E148 Safari/604.1", "chrome"},
		{"firefox ios", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/127.0 Mobile/15E148 Safari/605.1.15", "firefox"},
		{"opera", "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/111.0.0.0", "opera"},
		{"samsung", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36", "samsung"},
		{"curl", "curl/8.7.1", "curl"},
		{"wget", "Wget/1.21.4", "wget"},
		{"python-requests", "python-requests/2.32.3", "python"},
		{"aiohttp", "Python/3.12 aiohttp/3.9.5", "python"},
		{"go", "Go-http-client/2.0", "go"},
		{"node", "node-fetch/1.0", "node"},
		{"okhttp", "okhttp/4.12.0", "okhttp"},
		{"googlebot", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "other"},
		{"empty", "", "other"},
	}
	for _, c := range cases {
		if got := Family(c.ua); got != c.want {
			t.Errorf("%s: Family = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestFamilyWithBrave(t *testing.T) {
	chrome := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	if got := FamilyWithBrave(chrome, true); got != "brave" {
		t.Errorf("got %q", got)
	}
	if got := FamilyWithBrave(chrome, false); got != "chrome" {
		t.Errorf("got %q", got)
	}
	if got := FamilyWithBrave("curl/8.0", true); got != "curl" {
		t.Errorf("got %q", got)
	}
}

func TestHeadless(t *testing.T) {
	yes := []string{
		"Mozilla/5.0 HeadlessChrome/126.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) app/1.0 Chrome/100 Electron/20.0 Safari/537.36",
		"Puppeteer/1", "my-PLAYWRIGHT-bot", "Selenium/4",
	}
	for _, u := range yes {
		if !Headless(u) {
			t.Errorf("Headless(%q) = false", u)
		}
	}
	no := []string{"", "curl/8.0", "Mozilla/5.0 (Windows NT 10.0) Chrome/126.0.0.0 Safari/537.36"}
	for _, u := range no {
		if Headless(u) {
			t.Errorf("Headless(%q) = true", u)
		}
	}
}
