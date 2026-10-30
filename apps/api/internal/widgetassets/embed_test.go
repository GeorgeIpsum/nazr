package widgetassets

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestEmbedded checks the embedded FS is rooted at assets/ and that Present
// matches what is on disk: false on the committed tree (only .gitkeep), true
// after scripts/sync-widget.mjs has copied a built widget in (as `pnpm build`
// does before `pnpm test`).
func TestEmbedded(t *testing.T) {
	fsys, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Stat(fsys, ".gitkeep"); err != nil {
		t.Fatalf("embedded FS is not rooted at assets/: %v", err)
	}
	synced := true
	for _, name := range []string{"loader.js", "manifest.json"} {
		if _, err := os.Stat(filepath.Join("assets", name)); err != nil {
			synced = false
		}
	}
	if got := Present(fsys); got != synced {
		t.Fatalf("Present = %v, want %v (assets on disk)", got, synced)
	}
}

func TestDirPresent(t *testing.T) {
	dir := t.TempDir()
	fsys, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if Present(fsys) {
		t.Fatal("empty dir reported present")
	}
	for _, name := range []string{"loader.js", "manifest.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if !Present(fsys) {
		t.Fatal("dir with loader.js and manifest.json not present")
	}
}
