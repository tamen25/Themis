package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tamen25/themis/internal/cli"
	localrun "github.com/tamen25/themis/internal/run"
)

func TestRunAndReplayCLI(t *testing.T) {
	for _, status := range []int{200, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
			defer server.Close()
			dir := t.TempDir()
			file := filepath.Join(dir, "contract.yaml")
			input := fmt.Sprintf(`schemaVersion: themis.contract/v1alpha1
metadata: {name: local-http-health, owner: test}
spec:
  target: {kind: local-http, name: demo, url: %q}
  execution: {maxDuration: 1s, requireApproval: false}
  scenario: {id: baseline, phases: [{name: observe, duration: 200ms}]}
  assertions:
    - {id: readiness, type: http-ready, deadline: 200ms}
    - {id: error-rate, type: http-success-rate, minSamples: 2, maximumErrorFraction: 0.03}
`, server.URL)
			if err := os.WriteFile(file, []byte(input), 0600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			code := cli.Run([]string{"run", "-f", file, "--runs-dir", dir, "--output", "json"}, &stdout, &stderr, "test")
			wantCode, wantVerdict := cli.ExitOK, "PASS"
			if status == 503 {
				wantCode, wantVerdict = cli.ExitFail, "FAIL"
			}
			var report localrun.Report
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatalf("code=%d stdout=%s stderr=%s err=%v", code, stdout.String(), stderr.String(), err)
			}
			if code != wantCode || string(report.Verdict) != wantVerdict || report.Samples != 2 || stderr.Len() != 0 {
				t.Fatalf("code=%d report=%+v stderr=%s", code, report, stderr.String())
			}
			server.Close() // Offline replay must work after the target disappears.
			var summary, diagnostic bytes.Buffer
			code = cli.Run([]string{"replay", "-f", filepath.Join(dir, report.RunID, "events.jsonl")}, &summary, &diagnostic, "test")
			want := fmt.Sprintf("Contract: local-http-health\nRun:      %s\nSamples:  2\nCoverage: sufficient\n\nReadiness: %s\nError rate: %s\n\nVerdict: %s\n", report.RunID, wantVerdict, wantVerdict, wantVerdict)
			if code != wantCode || summary.String() != want || diagnostic.Len() != 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, summary.String(), diagnostic.String())
			}
		})
	}
}

func TestRunConfigurationAndCancellation(t *testing.T) {
	file := fixture(t)
	for _, args := range [][]string{{"run", "-f", file, "--output", "yaml"}, {"replay", "-f", file, "--output", "yaml"}} {
		var stdout, stderr bytes.Buffer
		if code := cli.Run(args, &stdout, &stderr, "test"); code != 4 || stdout.Len() != 0 {
			t.Fatalf("code=%d stderr=%s", code, stderr.String())
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	healthy, err := filepath.Abs("../../examples/local-http/healthy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if code := cli.RunContext(ctx, []string{"run", "-f", healthy, "--runs-dir", t.TempDir()}, &stdout, &stderr, "test"); code != 3 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
}

func TestDiagnosticsEscapeTerminalControls(t *testing.T) {
	file := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(file, []byte("\"\\x1b[31m\": !audit value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := cli.Run([]string{"contract", "validate", "-f", file}, &stdout, &stderr, "test"); code != 4 || strings.ContainsRune(stderr.String(), '\x1b') {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}
