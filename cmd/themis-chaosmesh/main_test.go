package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNoExecutionOrLegacyGrantCLI(t *testing.T) {
	for _, args := range [][]string{nil, {"run"}, {"approve"}, {"apply"}, {"cleanup"}, {"provider", "--force"}, {"plan"}, {"admit"}, {"admit", "--authorization", "legacy.json"}} {
		var out, diagnostics bytes.Buffer
		if got := run(context.Background(), args, &out, &diagnostics); got != 4 {
			t.Fatal(args, got)
		}
	}
	path := filepath.Join(t.TempDir(), "untrusted.json")
	if err := os.WriteFile(path, []byte(`{"version":"themis.kubernetes-authorization/v1alpha1","approved":true,"verdict":"PASS"}`), 0600); err != nil {
		t.Fatal(err)
	}
	var out, diagnostics bytes.Buffer
	if got := run(context.Background(), []string{"admit", "-f", path, "--expect-digest", "sha256:untrusted"}, &out, &diagnostics); got != 5 || !strings.Contains(out.String(), `"admission": "DENIED"`) || !strings.Contains(out.String(), `"mutationAttempted": false`) || !strings.Contains(out.String(), `"verdict": "NOT_RUN"`) {
		t.Fatal("legacy authority or claims enabled fault", got, out.String())
	}
	for _, command := range []string{"plan", "admit", "provider"} {
		out.Reset()
		diagnostics.Reset()
		if got := run(context.Background(), []string{command, "--help"}, &out, &diagnostics); got != 0 {
			t.Fatal(command, got)
		}
	}
}
