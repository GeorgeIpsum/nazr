package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"nazr/api/internal/widgettoken"
)

// signingCmd runs "nazr signing rotate|list" against the configured database.
func signingCmd(sub string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("signing "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "usage: nazr signing %s\n", sub)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, code := openStore(ctx, stderr)
	if s == nil {
		return code
	}
	defer s.Close()

	switch sub {
	case "rotate":
		next, err := widgettoken.Generate(time.Now())
		if err == nil {
			err = s.RotateSigningKey(ctx, next, widgettoken.SigningKeyPublish)
		}
		if err != nil {
			fmt.Fprintln(stderr, "nazr:", err)
			return 1
		}
		// The activation time is the database's; read it back.
		at := time.Now().Add(widgettoken.SigningKeyPublish)
		if ks, err := s.ListSigningKeys(ctx, time.Time{}); err == nil {
			for _, k := range ks {
				if k.Kid == next.Kid {
					at = k.ActivatesAt
				}
			}
		}
		fmt.Fprintf(stdout, "%s activates at %s\n", next.Kid, at.UTC().Format(time.RFC3339))
	case "list":
		ks, err := s.ListSigningKeys(ctx, time.Time{})
		if err != nil {
			fmt.Fprintln(stderr, "nazr:", err)
			return 1
		}
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "KID\tCREATED\tACTIVATES\tRETIRED")
		for _, k := range ks {
			retired := "-"
			if k.RetiredAt != nil {
				retired = k.RetiredAt.UTC().Format(time.RFC3339)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", k.Kid, k.CreatedAt.UTC().Format(time.RFC3339),
				k.ActivatesAt.UTC().Format(time.RFC3339), retired)
		}
		_ = tw.Flush()
	}
	return 0
}
