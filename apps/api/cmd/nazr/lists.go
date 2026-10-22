package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"text/tabwriter"
	"time"

	"nazr/api/internal/config"
)

// listsRefresh fetches every intelligence source once and prints the result.
// Sources are optional, so per-source errors appear in the table and the exit
// code stays 0.
func listsRefresh(stdout, stderr io.Writer) int {
	cfg, err := config.Load(os.LookupEnv)
	if err != nil {
		fmt.Fprintln(stderr, "nazr:", err)
		return 1
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(stderr, "nazr:", err)
		return 1
	}
	intel, err := newIntel(cfg, newLogger(cfg, stderr))
	if err != nil {
		fmt.Fprintln(stderr, "nazr:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := intel.RefreshAll(ctx); err != nil {
		fmt.Fprintln(stderr, "nazr: refresh:", err)
	}
	st := intel.Status()
	names := make([]string, 0, len(st))
	for n := range st {
		names = append(names, n)
	}
	slices.Sort(names)
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "source\tloaded\trows\tfetched_at\tlast_error")
	for _, n := range names {
		s := st[n]
		at := "-"
		if !s.FetchedAt.IsZero() {
			at = s.FetchedAt.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(tw, "%s\t%t\t%d\t%s\t%s\n", n, s.Loaded, s.Rows, at, s.LastError)
	}
	tw.Flush()
	return 0
}
