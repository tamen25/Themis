package cli_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tamen25/themis/internal/cli"
)

func fixture(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs("../../examples/local-http/contract.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCLI(t *testing.T) {
	file := fixture(t)
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("schemaVersion: unknown\n"), 0600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		args   []string
		code   int
		output string
		error  string
	}{
		{"help", []string{"--help"}, 0, "Usage:", ""},
		{"no args", nil, 4, "Usage:", ""},
		{"version", []string{"version"}, 0, "themis test-version\n", ""},
		{"version extra", []string{"version", "extra"}, 4, "", "no arguments"},
		{"validate", []string{"contract", "validate", "-f", file}, 0, "VALID local-checkout sha256:", ""},
		{"plan", []string{"plan", "-f", file, "--output", "json"}, 0, `"planDigest": "sha256:`, ""},
		{"plan default format", []string{"plan", "-f", file}, 0, `"executionAllowed": false`, ""},
		{"command help", []string{"plan", "--help"}, 0, "Usage:", ""},
		{"missing file flag", []string{"plan"}, 4, "", "expected -f"},
		{"missing flag value", []string{"plan", "-f"}, 4, "", "needs an argument"},
		{"unknown flag", []string{"plan", "--unsafe"}, 4, "", "flag provided but not defined"},
		{"unknown output", []string{"plan", "-f", file, "--output", "yaml"}, 4, "", "unsupported output"},
		{"extra positional", []string{"plan", "-f", file, "extra"}, 4, "", "no positional"},
		{"invalid contract", []string{"contract", "validate", "-f", bad}, 4, "", "unsupported schemaVersion"},
		{"invalid plan", []string{"plan", "-f", bad}, 4, "", "unsupported schemaVersion"},
		{"missing input", []string{"plan", "-f", bad + ".missing"}, 6, "", "open contract"},
		{"read error", []string{"plan", "-f", filepath.Dir(bad)}, 6, "", "read contract"},
		{"unknown command", []string{"doctor"}, 4, "", "unknown command"},
		{"run needs approval", []string{"run", "-f", file}, 5, "", "--approve-plan sha256:"},
		{"invalid subcommand", []string{"contract", "apply"}, 4, "", "unknown command"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := cli.Run(tc.args, &stdout, &stderr, "test-version")
			if code != tc.code || !strings.Contains(stdout.String(), tc.output) || !strings.Contains(stderr.String(), tc.error) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if tc.error != "" && stdout.Len() != 0 {
				t.Fatal("error leaked partial successful output")
			}
			if tc.error == "" && stderr.Len() != 0 {
				t.Fatalf("unexpected diagnostics: %s", stderr.String())
			}
		})
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("output unavailable") }

func TestOutputErrors(t *testing.T) {
	file := fixture(t)
	for _, args := range [][]string{{"--help"}, {"version"}, {"plan", "--help"}, {"contract", "validate", "-f", file}, {"plan", "-f", file}} {
		var stderr bytes.Buffer
		if code := cli.Run(args, brokenWriter{}, &stderr, "dev"); code != cli.ExitInfrastructure || !strings.Contains(stderr.String(), "output unavailable") {
			t.Fatalf("args=%v code=%d stderr=%s", args, code, stderr.String())
		}
	}
}

func directorySnapshot(t *testing.T, dir string) map[string][32]byte {
	t.Helper()
	files := make(map[string][32]byte)
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[path] = sha256.Sum256(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestPlanDoesNotMutateOrContactTarget(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	input, err := os.ReadFile(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	t.Chdir(dir)
	file := filepath.Join(dir, "contract.yaml")
	input = bytes.ReplaceAll(input, []byte("http://127.0.0.1:8080/health"), []byte(server.URL))
	if err := os.WriteFile(file, input, 0600); err != nil {
		t.Fatal(err)
	}
	before := directorySnapshot(t, dir)
	var first bytes.Buffer
	for i := 0; i < 2; i++ {
		var stdout, stderr bytes.Buffer
		if code := cli.Run([]string{"plan", "-f", file, "--output", "json"}, &stdout, &stderr, "dev"); code != 0 {
			t.Fatalf("code=%d stderr=%s", code, stderr.String())
		}
		if i == 0 {
			first.Write(stdout.Bytes())
		} else if !bytes.Equal(first.Bytes(), stdout.Bytes()) {
			t.Fatal("CLI plan output was not deterministic")
		}
	}
	if requests.Load() != 0 {
		t.Fatalf("plan contacted the target %d times", requests.Load())
	}
	if !reflect.DeepEqual(before, directorySnapshot(t, dir)) {
		t.Fatal("plan mutated files in its working directory")
	}
}
