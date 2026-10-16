package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestCoordinationCLIArgumentsAndUncertainty(t *testing.T) {
	for _, test := range []struct {
		args []string
		exit int
	}{
		{[]string{"coordinate"}, 4}, {[]string{"coordinate", "--help"}, 0},
		{[]string{"coordinate", "unknown"}, 4}, {[]string{"coordinate", "prepare"}, 4},
		{[]string{"coordinate", "approve", "--directory", "missing"}, 4},
		{[]string{"coordinate", "start", "--directory", "missing", "--force"}, 4},
		{[]string{"coordinate", "cancel", "--directory", "missing"}, 7},
		{[]string{"coordinate", "reconcile", "--directory", "missing"}, 7},
		{[]string{"coordinate", "status", "--directory", "missing"}, 6},
		{[]string{"coordinate", "verify", "--directory", "missing"}, 6},
	} {
		var out, diagnostics bytes.Buffer
		if got := run(context.Background(), test.args, &out, &diagnostics); got != test.exit {
			t.Fatalf("%v exit=%d want %d", test.args, got, test.exit)
		}
		if test.exit == 7 && (!strings.Contains(out.String(), "CLEANUP_PENDING") || strings.Contains(out.String(), `"verdict": "PASS"`)) {
			t.Fatal("missing inventory did not preserve uncertainty")
		}
	}
	for _, command := range []string{"preview", "prepare", "approve", "start", "status", "cancel", "reconcile", "verify"} {
		var out, diagnostics bytes.Buffer
		if got := run(context.Background(), []string{"coordinate", command, "--help"}, &out, &diagnostics); got != 0 {
			t.Fatal(command, got)
		}
	}
}
