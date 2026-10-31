package auth

import (
	"strings"
	"testing"
)

func TestValidateOrigins(t *testing.T) {
	good := []string{"*", "https://shop.example", "http://localhost:3000", "https://*.example.com", "HTTPS://Shop.Example/", " https://a.test ", "", "http://[::1]:8080", "chrome-extension://abcdef"}
	if err := ValidateOrigins(good); err != nil {
		t.Fatalf("valid origins rejected: %v", err)
	}
	for _, bad := range []string{
		"shop.example", "https://", "https://a.test/path", "https://a.test?q=1", "https://a.test#f",
		"https://user@a.test", "https://a.*.test", "https://*", "https://*.", "*.example.com",
		"https://a.test:0", "https://a.test:99999", "https://a.test:", "mailto:a@b.test", "**",
		// CSP separators would split a frame-ancestors source list.
		"https://a.test;script-src", "https://a.test,https://b.test", "https://a'.test", "https://*.a;b.test",
	} {
		err := ValidateOrigins([]string{"https://ok.test", bad})
		if err == nil || !strings.Contains(err.Error(), bad) {
			t.Errorf("%q: want error naming it, got %v", bad, err)
		}
	}
}
