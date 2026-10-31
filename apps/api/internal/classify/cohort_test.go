package classify

import "testing"

func TestCohortKey(t *testing.T) {
	const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	for _, tc := range []struct {
		name  string
		ua    string
		brave bool
		ja4   []string
		want  string
	}{
		{"chrome", chromeUA, false, []string{"chrome"}, "chrome|chrome"},
		{"curl no ja4", "curl/8.4.0", false, nil, "curl|"},
		{"brave", chromeUA, true, []string{"chrome"}, "brave|chrome"},
	} {
		if got := CohortKey(tc.ua, tc.brave, tc.ja4); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}
