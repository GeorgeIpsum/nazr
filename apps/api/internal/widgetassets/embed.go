// Package widgetassets embeds the built @nazr/widget files (synced into
// assets/ by scripts/sync-widget.mjs before go build). The committed tree
// holds only assets/.gitkeep, so a binary built without the sync has no
// widget and its widget routes 404.
package widgetassets

import (
	"embed"
	"io/fs"
	"os"
)

//go:embed all:assets
var embedded embed.FS

// Open returns the embedded assets when dir is "", otherwise dir on disk
// (NAZR_WIDGET_DIR).
func Open(dir string) (fs.FS, error) {
	if dir == "" {
		return fs.Sub(embedded, "assets")
	}
	return os.DirFS(dir), nil
}

// Present reports whether fsys holds a built widget: loader.js and
// manifest.json both exist.
func Present(fsys fs.FS) bool {
	for _, name := range []string{"loader.js", "manifest.json"} {
		if _, err := fs.Stat(fsys, name); err != nil {
			return false
		}
	}
	return true
}
