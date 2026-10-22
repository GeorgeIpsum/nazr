package fingerprint

import (
	"os"
	"strings"
	"testing"
)

func decodeJSON(t *testing.T, raw []byte) any {
	t.Helper()
	c, err := Decode(strings.NewReader(`{"v":`+string(raw)+`}`), 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	return c["v"]
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/fixtures/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
