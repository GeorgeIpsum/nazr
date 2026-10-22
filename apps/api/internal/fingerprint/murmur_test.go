package fingerprint

import "testing"

func TestMurmurKnownVectors(t *testing.T) {
	// Produced with the client implementation:
	// cd packages/thumbmark && npx tsx -e 'import {hash} from "./src/utils/hash"; console.log(hash("hello"), hash(""))'
	cases := map[string]string{
		"":      "00000000000000000000000000000000",
		"hello": "a044242bf7de91dbb631db9ab631db9a",
	}
	for in, want := range cases {
		if got := Murmur128Hex(in); got != want {
			t.Errorf("Murmur128Hex(%q) = %s want %s", in, got, want)
		}
	}
}
