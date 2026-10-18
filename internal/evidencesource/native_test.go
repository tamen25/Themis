package evidencesource

import (
	"strings"
	"testing"

	obs "github.com/tamen25/themis/pkg/nativeobservation"
)

func TestNativeInventoryIsCanonicalAndPublic(t *testing.T) {
	files := Inventory(obs.Engine)
	if len(files) != 9 {
		t.Fatal("incomplete native inventory")
	}
	for i, f := range files {
		if i > 0 && files[i-1].Path >= f.Path {
			t.Fatal("unsorted or duplicate artifact inventory")
		}
		if !strings.HasPrefix(f.Path, "artifacts/native-") || strings.Contains(f.Path, "authorization") || strings.Contains(f.Path, "private") || f.Role == "" || f.Version == "" {
			t.Fatal("unsafe or unspecified native artifact", f.Path)
		}
	}
}
