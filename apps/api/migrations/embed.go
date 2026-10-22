// Package migrations embeds the goose SQL migrations.
package migrations

import "embed"

// FS holds the *.sql migration files at its root.
//
//go:embed *.sql
var FS embed.FS
