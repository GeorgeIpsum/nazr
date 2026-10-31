package main

import (
	"bytes"
	"context"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"nazr/api/internal/auth"
	"nazr/api/internal/store"
	"nazr/api/internal/widgettoken"
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

var secretRE = regexp.MustCompile(`^nzs_[a-z2-7]{52}$`)

func TestKeysCreatePrintsSecret(t *testing.T) {
	t.Setenv("NAZR_DATABASE_URL", newTestDB(t))
	var out, errb bytes.Buffer
	if code := keysCmd("create", []string{"--label", "x"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 || !secretRE.MatchString(lines[1]) || !strings.HasSuffix(lines[2], "  x") {
		t.Fatalf("output %q", out.String())
	}
	s := openTestStore(t)
	k, err := s.FindKeyBySecretHash(context.Background(), auth.HashKey(lines[1]))
	if err != nil || k == nil || !strings.HasPrefix(lines[2], k.ID+"  ") {
		t.Fatalf("find by secret: %v %v", k, err)
	}
}

func TestKeysSecretRotate(t *testing.T) {
	t.Setenv("NAZR_DATABASE_URL", newTestDB(t))
	var out, errb bytes.Buffer
	if code := keysCmd("create", []string{"--label", "x"}, &out, &errb); code != 0 {
		t.Fatalf("create exit %d: %s", code, errb.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	oldSecret, id := lines[1], strings.Fields(lines[2])[0]
	out.Reset()
	if code := keysCmd("secret-rotate", []string{id}, &out, &errb); code != 0 {
		t.Fatalf("rotate exit %d: %s", code, errb.String())
	}
	newSecret := strings.TrimSpace(out.String())
	if !secretRE.MatchString(newSecret) || newSecret == oldSecret {
		t.Fatalf("rotated output %q", out.String())
	}
	s := openTestStore(t)
	ctx := context.Background()
	if k, _ := s.FindKeyBySecretHash(ctx, auth.HashKey(oldSecret)); k != nil {
		t.Fatal("old secret still resolves")
	}
	if k, _ := s.FindKeyBySecretHash(ctx, auth.HashKey(newSecret)); k == nil || k.ID != id {
		t.Fatalf("new secret does not resolve to %s: %v", id, k)
	}
	errb.Reset()
	if code := keysCmd("secret-rotate", []string{"00000000-0000-0000-0000-000000000000"}, &out, &errb); code != 1 {
		t.Fatalf("unknown id exit %d", code)
	}
	if code := keysCmd("secret-rotate", nil, &out, &errb); code != 2 {
		t.Fatalf("missing id exit %d", code)
	}
}

func TestSigningRotateList(t *testing.T) {
	t.Setenv("NAZR_DATABASE_URL", newTestDB(t))
	s := openTestStore(t)
	if _, err := s.EnsureSigningKey(context.Background(), func() (store.SigningKey, error) { return widgettoken.Generate(time.Now()) }); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	before := time.Now()
	if code := signingCmd("rotate", nil, &out, &errb); code != 0 {
		t.Fatalf("rotate exit %d: %s", code, errb.String())
	}
	// "<kid> activates at <RFC3339>", one publish window ahead.
	line := strings.TrimSpace(out.String())
	kid, at, ok := strings.Cut(line, " activates at ")
	if !ok || kid == "" || strings.Contains(line, "\n") {
		t.Fatalf("rotate output %q", out.String())
	}
	activates, err := time.Parse(time.RFC3339, at)
	if err != nil || activates.Before(before.Add(widgettoken.SigningKeyPublish-time.Minute)) ||
		activates.After(time.Now().Add(widgettoken.SigningKeyPublish+time.Minute)) {
		t.Fatalf("activates %q %v", at, err)
	}
	out.Reset()
	if code := signingCmd("list", nil, &out, &errb); code != 0 {
		t.Fatalf("list exit %d: %s", code, errb.String())
	}
	rows := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(rows) != 3 || !slices.Equal(strings.Fields(rows[0]), []string{"KID", "CREATED", "ACTIVATES", "RETIRED"}) {
		t.Fatalf("list output %q", out.String())
	}
	// The new key activates when the old one retires.
	first, second := strings.Fields(rows[1]), strings.Fields(rows[2])
	if len(first) != 4 || len(second) != 4 || first[0] != kid || first[2] != at || first[3] != "-" ||
		second[3] != at || second[2] == "-" {
		t.Fatalf("rows %q", rows)
	}
}

func TestSigningUsage(t *testing.T) {
	for _, args := range [][]string{{"signing"}, {"signing", "nope"}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 2 || !strings.Contains(errb.String(), "signing rotate|list") {
			t.Errorf("%v: exit %d stderr %q", args, code, errb.String())
		}
	}
}

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), os.Getenv("NAZR_DATABASE_URL"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}
