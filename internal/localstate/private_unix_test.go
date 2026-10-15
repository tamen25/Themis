//go:build linux || darwin

package localstate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRejectPublicModeAndSymlink(t *testing.T) {
	dir, err := CreateDirectory(filepath.Join(t.TempDir(), "private"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if Check(dir) == nil {
		t.Fatal("public directory accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if Check(link) == nil {
		t.Fatal("symlink accepted")
	}
}
