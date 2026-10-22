package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestKeysCreateRejectsBadOrigins(t *testing.T) {
	var out, errb bytes.Buffer
	code := keysCmd("create", []string{"--label", "shop", "--origins", "https://ok.test,shop.example"}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit %d, want 2 (stderr %q)", code, errb.String())
	}
	if !strings.Contains(errb.String(), `"shop.example"`) {
		t.Fatalf("stderr does not name the bad origin: %q", errb.String())
	}
}
