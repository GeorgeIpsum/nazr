// Command nazr is the nazr API server and admin CLI.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"

	"nazr/api/internal/config"
	"nazr/api/internal/store"
	"nazr/api/internal/version"
)

const usage = `usage: nazr <command> [args]

commands:
  serve [--print-config]       run the server
  migrate                      apply database migrations
  keys create|list|revoke      manage API keys
  lists refresh                refresh intelligence lists
  version                      print the version
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Fprintln(stdout, version.Version)
		return 0
	case "serve":
		return serve(args[1:], stdout, stderr)
	case "migrate":
		return migrate(stdout, stderr)
	case "keys":
		if len(args) < 2 || !slices.Contains([]string{"create", "list", "revoke"}, args[1]) {
			fmt.Fprint(stderr, usage)
			return 2
		}
		return notImplemented(stderr, "keys "+args[1])
	case "lists":
		if len(args) < 2 || args[1] != "refresh" {
			fmt.Fprint(stderr, usage)
			return 2
		}
		return notImplemented(stderr, "lists refresh")
	default:
		fmt.Fprintf(stderr, "nazr: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

func notImplemented(stderr io.Writer, name string) int {
	fmt.Fprintf(stderr, "nazr %s: not implemented\n", name)
	return 1
}

func serve(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	printConfig := fs.Bool("print-config", false, "print the effective configuration (secrets redacted) and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !*printConfig {
		return notImplemented(stderr, "serve")
	}
	cfg, err := config.Load(os.LookupEnv)
	if err != nil {
		fmt.Fprintln(stderr, "nazr:", err)
		return 1
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(stderr, "nazr:", err)
		return 1
	}
	red := cfg.Redacted()
	keys := make([]string, 0, len(red))
	for k := range red {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		fmt.Fprintf(stdout, "%s=%s\n", k, red[k])
	}
	return 0
}

func migrate(stdout, stderr io.Writer) int {
	cfg, err := config.Load(os.LookupEnv)
	if err != nil {
		fmt.Fprintln(stderr, "nazr:", err)
		return 1
	}
	if cfg.DatabaseURL == "" {
		fmt.Fprintln(stderr, "nazr: NAZR_DATABASE_URL is required")
		return 1
	}
	ctx := context.Background()
	s, err := store.Open(ctx, cfg.DatabaseURL, "")
	if err != nil {
		fmt.Fprintln(stderr, "nazr:", err)
		return 1
	}
	defer s.Close()
	if err := s.Migrate(ctx); err != nil {
		fmt.Fprintln(stderr, "nazr:", err)
		return 1
	}
	v, err := s.MigrationVersion(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "nazr:", err)
		return 1
	}
	fmt.Fprintf(stdout, "migrations applied; version %d\n", v)
	return 0
}
