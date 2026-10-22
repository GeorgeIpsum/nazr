// Package ua derives a coarse browser or client family from a User-Agent
// string and flags well-known automation markers.
package ua

import "strings"

// Family returns the client family for a User-Agent. Brave is never returned
// because its UA is indistinguishable from Chrome; see FamilyWithBrave.
func Family(userAgent string) string { return FamilyWithBrave(userAgent, false) }

// FamilyWithBrave is Family, but reports "brave" for Chromium-looking user
// agents when the caller knows (for example from client components) that the
// browser is Brave.
func FamilyWithBrave(userAgent string, brave bool) string {
	l := strings.ToLower(userAgent)
	if l == "" {
		return "other"
	}
	// Tools first: they rarely look like a browser, and crawlers that
	// impersonate Chrome (Googlebot) must not count as one.
	switch {
	case strings.Contains(l, "bot/") || strings.Contains(l, "bot;") || strings.Contains(l, "spider") || strings.Contains(l, "crawler"):
		return "other"
	case strings.HasPrefix(l, "curl/"):
		return "curl"
	case strings.HasPrefix(l, "wget/"):
		return "wget"
	case strings.HasPrefix(l, "python") || strings.Contains(l, "aiohttp/") || strings.HasPrefix(l, "httpx/"):
		return "python"
	case strings.HasPrefix(l, "go-http-client/"):
		return "go"
	case strings.HasPrefix(l, "node") || strings.HasPrefix(l, "axios/") || strings.HasPrefix(l, "undici"):
		return "node"
	case strings.HasPrefix(l, "okhttp/"):
		return "okhttp"
	}
	// Order matters: Chromium derivatives also say Chrome and Safari.
	switch {
	case strings.Contains(l, "edg/") || strings.Contains(l, "edga/") || strings.Contains(l, "edgios/") || strings.Contains(l, "edge/"):
		return "edge"
	case strings.Contains(l, "opr/") || strings.Contains(l, "opera"):
		return "opera"
	case strings.Contains(l, "samsungbrowser/"):
		return "samsung"
	case strings.Contains(l, "firefox/") || strings.Contains(l, "fxios/"):
		return "firefox"
	case strings.Contains(l, "chrome/") || strings.Contains(l, "crios/") || strings.Contains(l, "chromium/"):
		if brave {
			return "brave"
		}
		return "chrome"
	case strings.Contains(l, "safari/") && strings.Contains(l, "version/"):
		return "safari"
	}
	return "other"
}

var headlessMarkers = []string{"headlesschrome", "phantomjs", "electron", "puppeteer", "playwright", "selenium"}

// Headless reports whether the User-Agent carries an automation marker.
func Headless(userAgent string) bool {
	l := strings.ToLower(userAgent)
	for _, m := range headlessMarkers {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}
