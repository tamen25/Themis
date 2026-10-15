package experiment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

type cliOutput struct {
	stdout, stderr []byte
	code           int
}

func invokeCLI(arguments ...string) cliOutput {
	cmd := exec.Command(executable, arguments...)
	cmd.Env = append(os.Environ(), "GORACE="+os.Getenv("GORACE")+" atexit_sleep_ms=0")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else {
			code = -1
		}
	}
	return cliOutput{stdout.Bytes(), stderr.Bytes(), code}
}

func TestExternalCLICancellation(t *testing.T) {
	for _, phase := range []State{Baseline, Intervention, Recovery} {
		t.Run(string(phase), func(t *testing.T) {
			_, _, a, root := setup(t, "healthy")
			authorization := filepath.Join(cDirectory(root), "cli-auth.json")
			if err := localstate.WriteNew(authorization, a); err != nil {
				t.Fatal(err)
			}
			contractPath, _ := filepath.Abs("../../examples/owned-latency/experiment.yaml")
			cmd := exec.Command(executable, "experiment", "run", "-f", contractPath, "--fixture", cDirectory(root), "--authorization", authorization, "--runs-dir", filepath.Join(root, "runs"))
			cmd.Env = append(os.Environ(), "GORACE="+os.Getenv("GORACE")+" atexit_sleep_ms=0")
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill() })
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			var directory string
			waitFor(t, func() bool {
				dirs, _ := filepath.Glob(filepath.Join(root, "runs", "run-*"))
				if len(dirs) != 1 {
					return false
				}
				directory = dirs[0]
				return inspectJournalFile(filepath.Join(directory, "events.jsonl")).LastState == phase
			})
			inspection := invokeCLI("experiment", "status", "--run", directory, "--output", "json")
			if inspection.code != 0 {
				t.Fatalf("active status: %s %s", inspection.stdout, inspection.stderr)
			}
			var status StatusReport
			if err := json.Unmarshal(inspection.stdout, &status); err != nil || status.Live.Runner != "RUNNING" {
				t.Fatalf("runner ownership not observed: %s %v", inspection.stdout, err)
			}
			cancelled := invokeCLI("experiment", "cancel", "--run", directory)
			if cancelled.code != 0 {
				t.Fatalf("external cancel: exit %d %s %s", cancelled.code, cancelled.stdout, cancelled.stderr)
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancelled run returned success")
				}
			case <-time.After(6 * time.Second):
				t.Fatal("runner did not acknowledge external cancellation")
			}
			var r Report
			if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
				t.Fatalf("runner output: %s %s %v", stdout.String(), stderr.String(), err)
			}
			if r.Execution.Status != result.Cancelled || r.Verdict == result.Pass || !r.CleanupCompleted {
				t.Fatalf("external cancellation lost: %+v", r)
			}
			if phase == Baseline && (r.FaultAttempted == nil || *r.FaultAttempted || hasState(journalEvents(t, directory), Intent)) {
				t.Fatal("baseline cancellation wrote fault intent")
			}
			before, err := os.ReadFile(filepath.Join(directory, "events.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				again := invokeCLI("experiment", "cancel", "--run", directory)
				if again.code != 0 {
					t.Fatalf("repeated cancel: %s %s", again.stdout, again.stderr)
				}
			}
			after, _ := os.ReadFile(filepath.Join(directory, "events.jsonl"))
			if !bytes.Equal(before, after) {
				t.Fatal("cancellation rewrote execution history")
			}
			t.Logf("external CLI cancellation during %s stopped runner PID %d with %s", phase, cmd.Process.Pid, r.Execution.Status)
		})
	}
}

func TestConcurrentCancelAndCleanup(t *testing.T) {
	c, p, a, root := setup(t, "healthy")
	type outcome struct {
		r   Report
		dir string
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		r, dir, err := Execute(context.Background(), p, a, cDirectory(root), filepath.Join(root, "runs"))
		done <- outcome{r, dir, err}
	}()
	waitFor(t, func() bool { s, err := c.Status(context.Background()); return err == nil && s.ActiveFault != nil })
	dirs, _ := filepath.Glob(filepath.Join(root, "runs", "run-*"))
	if len(dirs) != 1 {
		t.Fatal("missing run")
	}
	directory := dirs[0]
	var group sync.WaitGroup
	outputs := make([]cliOutput, 2)
	for i, command := range []string{"cancel", "cleanup"} {
		group.Go(func() { outputs[i] = invokeCLI("experiment", command, "--run", directory) })
	}
	group.Wait()
	for _, out := range outputs {
		if out.code != 0 {
			t.Fatalf("concurrent action failed: exit %d %s %s", out.code, out.stdout, out.stderr)
		}
	}
	select {
	case got := <-done:
		if got.err != nil || got.r.Execution.Status != result.Cancelled || got.r.Verdict == result.Pass {
			t.Fatalf("raced finalization: %+v %v", got.r, got.err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("runner stuck")
	}
	state, err := Inspect(context.Background(), directory)
	if err != nil || state.ReconciliationNecessary || !state.StopRequested || !residualsClosed(state.Live.Residuals) {
		t.Fatalf("concurrent cancellation state: %+v %v", state, err)
	}
}

func fileHashes(t *testing.T, directory string) map[string][32]byte {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	hashes := map[string][32]byte{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		hashes[entry.Name()] = sha256.Sum256(data)
	}
	return hashes
}

func TestStatusAndCancelAfterCompletion(t *testing.T) {
	_, p, a, root := setup(t, "healthy")
	r, directory, err := Execute(context.Background(), p, a, cDirectory(root), filepath.Join(root, "runs"))
	if err != nil || r.Verdict != result.Pass {
		t.Fatalf("initial experiment: %v %s", err, r.Verdict)
	}
	before := fileHashes(t, directory)
	for range 3 {
		status, err := Inspect(context.Background(), directory)
		if err != nil || status.Live.Runner != "NOT_RUNNING" || status.ReconciliationNecessary || status.History.OriginalVerdict == nil || *status.History.OriginalVerdict != result.Pass {
			t.Fatalf("completed status: %+v %v", status, err)
		}
	}
	after := fileHashes(t, directory)
	if len(before) != len(after) {
		t.Fatal("read-only status created files")
	}
	for name, hash := range before {
		if after[name] != hash {
			t.Fatalf("read-only status changed %s", name)
		}
	}
	journal, _ := os.ReadFile(filepath.Join(directory, "events.jsonl"))
	report, _ := os.ReadFile(filepath.Join(directory, "report.json"))
	for range 2 {
		out := invokeCLI("experiment", "cancel", "--run", directory)
		if out.code != 0 {
			t.Fatalf("completed cancellation: %s %s", out.stdout, out.stderr)
		}
	}
	journalAfter, _ := os.ReadFile(filepath.Join(directory, "events.jsonl"))
	reportAfter, _ := os.ReadFile(filepath.Join(directory, "report.json"))
	if !bytes.Equal(journal, journalAfter) || !bytes.Equal(report, reportAfter) {
		t.Fatal("post-completion cancel changed measured history")
	}
	if _, err := os.Stat(filepath.Join(directory, "stop-request.json")); !os.IsNotExist(err) {
		t.Fatal("post-completion cancellation changed the finalized run")
	}
}

func TestDamagedJournalInventoryAndReplacement(t *testing.T) {
	_, p, a, root := setup(t, "healthy")
	r, directory, err := Execute(context.Background(), p, a, cDirectory(root), filepath.Join(root, "runs"))
	if err != nil || r.Verdict != result.Pass {
		t.Fatal(err)
	}
	journalPath := filepath.Join(directory, "events.jsonl")
	original, _ := os.ReadFile(journalPath)
	for _, damage := range []string{"{torn", "{corrupt}\n"} {
		if err := os.WriteFile(journalPath, append(append([]byte{}, original...), []byte(damage)...), 0600); err != nil {
			t.Fatal(err)
		}
		status, err := Inspect(context.Background(), directory)
		if err != nil || !status.InventoryUsable || status.Journal.Integrity == JournalComplete || status.History.Source != "UNVERIFIED_SAVED_REPORT" {
			t.Fatalf("damaged journal distinction: %+v %v", status, err)
		}
		cleanup, err := Reconcile(directory)
		if err != nil || !cleanup.Completed {
			t.Fatalf("corrupt-history reconciliation: %+v %v", cleanup, err)
		}
	}
	if err := os.WriteFile(journalPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	inventoryPath := filepath.Join(directory, "resources.json")
	inventoryBytes, _ := os.ReadFile(inventoryPath)
	if err := os.Rename(inventoryPath, inventoryPath+".saved"); err != nil {
		t.Fatal(err)
	}
	status, err := Inspect(context.Background(), directory)
	if err != nil || status.InventoryUsable || !status.ReconciliationNecessary || len(status.Live.Residuals) != 0 {
		t.Fatal("missing inventory was guessed")
	}
	if _, err := Reconcile(directory); err == nil {
		t.Fatal("cleanup authorized from journal")
	}
	if err := os.Rename(inventoryPath+".saved", inventoryPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inventoryPath, []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Cancel(context.Background(), directory); err == nil {
		t.Fatal("corrupt inventory authorized cancellation")
	}
	if err := os.WriteFile(inventoryPath, inventoryBytes, 0600); err != nil {
		t.Fatal(err)
	}
	// This listener belongs to the test, not the expired fixture. The reconciler
	// must not send it a control mutation, even though it reused the exact port.
	listener, err := net.Listen("tcp4", strings.TrimPrefix(p.Snapshot().Target.ControlURL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	var posts atomic.Int32
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost {
			posts.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})}
	go server.Serve(listener)
	defer server.Close()
	cleanup, err := Reconcile(directory)
	if err != nil || cleanup.Completed || cleanup.Disposition != Pending || posts.Load() != 0 {
		t.Fatalf("replacement listener controlled or hidden: %+v %v posts=%d", cleanup, err, posts.Load())
	}
}

func TestCleanupCommandCancellation(t *testing.T) {
	_, p, a, root := setup(t, "cleanup-denied")
	_, directory, err := Execute(context.Background(), p, a, cDirectory(root), filepath.Join(root, "runs"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	receipt, err := ReconcileContext(ctx, directory)
	if err != nil || receipt.Completed || receipt.Disposition != Pending || receipt.ReceiptPersisted == nil || !*receipt.ReceiptPersisted {
		t.Fatalf("cancelled cleanup lost pending receipt: %+v %v", receipt, err)
	}
}
