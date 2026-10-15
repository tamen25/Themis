package localstate_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tamen25/themis/internal/localstate"
)

func TestPrivateState(t *testing.T) {
	dir, err := localstate.CreateDirectory(filepath.Join(t.TempDir(), "private"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "credentials.json")
	if err := localstate.WriteNew(path, map[string]string{"secret": "test-only-value"}); err != nil {
		t.Fatal(err)
	}
	var read map[string]string
	if err := localstate.Read(path, &read); err != nil {
		t.Fatal(err)
	}
	if read["secret"] != "test-only-value" {
		t.Fatal("state changed")
	}
	if err := localstate.WriteNew(path, map[string]string{}); err == nil {
		t.Fatal("state overwritten")
	}
	if err := os.WriteFile(filepath.Join(dir, "corrupt.json"), []byte("{}{}"), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestStrictJSON(t *testing.T) {
	for _, data := range []string{`{"a":1,"a":2}`, `{"a":1,"A":2}`, `{} {}`, `{"unknown":1}`, `[`} {
		var value struct{ A int }
		if err := localstate.Unmarshal([]byte(data), &value); err == nil {
			t.Fatalf("accepted %s", data)
		}
	}
}
