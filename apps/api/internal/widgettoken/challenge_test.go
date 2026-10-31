package widgettoken

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestChallengeRoundTrip(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s1 := []byte("secret-one-secret-one-secret-one")
	c := Challenge{ID: "01HXABCDEFGHJKMNPQRSTVWXYZ", Expires: now.Unix() + 600, Bits: 18, Kid: "k1", Origin: "https://shop.example"}
	s := MintChallenge(s1, c)
	if strings.Count(s, ".") != 1 {
		t.Fatalf("want exactly one dot in %q", s)
	}
	calls := 0
	lookup := func(kid string) ([]byte, bool) {
		calls++
		if kid == "k1" {
			return s1, true
		}
		return nil, false
	}
	got, err := ParseChallenge(s, lookup, now)
	if err != nil || got != c {
		t.Fatalf("got %+v, %v", got, err)
	}
	if calls != 1 {
		t.Fatalf("secretFor called %d times, want 1", calls)
	}

	// Tampered payload.
	b := []byte(s)
	if b[2] == 'A' {
		b[2] = 'B'
	} else {
		b[2] = 'A'
	}
	calls = 0
	if _, err := ParseChallenge(string(b), lookup, now); !errors.Is(err, ErrChallengeBadMAC) && !errors.Is(err, ErrChallengeMalformed) && !errors.Is(err, ErrChallengeUnknownKid) {
		t.Fatalf("tampered: %v", err)
	}
	// Tampered MAC half is always a bad MAC.
	i := strings.Index(s, ".") + 1
	b = []byte(s)
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	calls = 0
	if _, err := ParseChallenge(string(b), lookup, now); !errors.Is(err, ErrChallengeBadMAC) {
		t.Fatalf("tampered mac: %v", err)
	}
	if calls != 1 {
		t.Fatalf("secretFor called %d times, want 1", calls)
	}
	// Payload swap with a valid-looking encoding must fail the MAC.
	other := MintChallenge(s1, Challenge{ID: "x", Expires: c.Expires, Kid: "k1"})
	forged := strings.Split(other, ".")[0] + "." + strings.Split(s, ".")[1]
	if _, err := ParseChallenge(forged, lookup, now); !errors.Is(err, ErrChallengeBadMAC) {
		t.Fatalf("forged: %v", err)
	}

	// Unknown kid.
	u := MintChallenge(s1, Challenge{ID: "x", Expires: c.Expires, Kid: "nope"})
	if _, err := ParseChallenge(u, lookup, now); !errors.Is(err, ErrChallengeUnknownKid) {
		t.Fatalf("unknown kid: %v", err)
	}
	// Expired.
	if _, err := ParseChallenge(s, lookup, time.Unix(c.Expires, 0)); !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("expired: %v", err)
	}
	// Malformed.
	for _, m := range []string{"abc", strings.Repeat("a", 513), "a.b.c", "!!!.???"} {
		if _, err := ParseChallenge(m, lookup, now); !errors.Is(err, ErrChallengeMalformed) {
			t.Fatalf("%.10q: %v", m, err)
		}
	}
}

func TestEmbeddingOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://shop.example/cart?x=1": "https://shop.example",
		"http://localhost:4173/":        "http://localhost:4173",
		"":                              "",
		"garbage":                       "",
		"ftp://x":                       "",
		"https:///path":                 "",
	} {
		if got := EmbeddingOrigin(in); got != want {
			t.Errorf("EmbeddingOrigin(%q) = %q, want %q", in, got, want)
		}
	}
}
