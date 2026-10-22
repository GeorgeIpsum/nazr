package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"nazr/api/internal/auth"
	"nazr/api/internal/config"
	"nazr/api/internal/store"
)

func keysCmd(sub string, args []string, stdout, stderr io.Writer) int {
	var (
		label, origins string
		rate           int
	)
	fs := flag.NewFlagSet("keys "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	if sub == "create" {
		fs.StringVar(&label, "label", "", "human-readable label (required)")
		fs.StringVar(&origins, "origins", "", "comma-separated allowed origins (default: any)")
		fs.IntVar(&rate, "rate", 0, "requests per minute (default: server default)")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	switch sub {
	case "create":
		if strings.TrimSpace(label) == "" {
			fmt.Fprintln(stderr, "nazr keys create: --label is required")
			return 2
		}
		if rate < 0 {
			fmt.Fprintln(stderr, "nazr keys create: --rate must be positive")
			return 2
		}
		if err := auth.ValidateOrigins(strings.Split(origins, ",")); err != nil {
			fmt.Fprintln(stderr, "nazr keys create: --origins:", err)
			return 2
		}
	case "revoke":
		if fs.NArg() != 1 {
			fmt.Fprintln(stderr, "usage: nazr keys revoke <id>")
			return 2
		}
	}

	ctx := context.Background()
	s, code := openStore(ctx, stderr)
	if s == nil {
		return code
	}
	defer s.Close()

	switch sub {
	case "create":
		plain, hash, prefix := auth.GenerateKey()
		nk := store.NewKey{Hash: hash, Prefix: prefix, Label: label}
		for _, o := range strings.Split(origins, ",") {
			if o = strings.TrimSpace(o); o != "" {
				nk.AllowedOrigins = append(nk.AllowedOrigins, o)
			}
		}
		if rate > 0 {
			nk.RateLimitPerMinute = &rate
		}
		k, err := s.CreateKey(ctx, nk)
		if err != nil {
			fmt.Fprintln(stderr, "nazr:", err)
			return 1
		}
		fmt.Fprintln(stdout, plain)
		fmt.Fprintf(stdout, "%s  %s  %s\n", k.ID, k.Prefix, k.Label)
	case "list":
		ks, err := s.ListKeys(ctx)
		if err != nil {
			fmt.Fprintln(stderr, "nazr:", err)
			return 1
		}
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tPREFIX\tLABEL\tORIGINS\tRATE\tCREATED\tREVOKED")
		for _, k := range ks {
			origins, rate, revoked := "*", "default", "-"
			if len(k.AllowedOrigins) > 0 {
				origins = strings.Join(k.AllowedOrigins, ",")
			}
			if k.RateLimitPerMinute != nil {
				rate = fmt.Sprint(*k.RateLimitPerMinute)
			}
			if k.RevokedAt != nil {
				revoked = k.RevokedAt.UTC().Format(time.RFC3339)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", k.ID, k.Prefix, k.Label, origins, rate,
				k.CreatedAt.UTC().Format(time.RFC3339), revoked)
		}
		_ = tw.Flush()
	case "revoke":
		if err := s.RevokeKey(ctx, fs.Arg(0)); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				fmt.Fprintf(stderr, "nazr: no such key %q\n", fs.Arg(0))
			} else {
				fmt.Fprintln(stderr, "nazr:", err)
			}
			return 1
		}
		fmt.Fprintf(stdout, "revoked %s\n", fs.Arg(0))
	}
	return 0
}

func openStore(ctx context.Context, stderr io.Writer) (*store.Store, int) {
	cfg, err := config.Load(os.LookupEnv)
	if err != nil {
		fmt.Fprintln(stderr, "nazr:", err)
		return nil, 1
	}
	if cfg.DatabaseURL == "" {
		fmt.Fprintln(stderr, "nazr: NAZR_DATABASE_URL is required")
		return nil, 1
	}
	s, err := store.Open(ctx, cfg.DatabaseURL, "")
	if err != nil {
		fmt.Fprintln(stderr, "nazr:", err)
		return nil, 1
	}
	return s, 0
}
