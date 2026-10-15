package experiment

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/contract"
	"github.com/tamen25/themis/internal/fixture"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/plan"
	"github.com/tamen25/themis/internal/result"
	"github.com/tamen25/themis/internal/safety"
)

var executable string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "themis-integration-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	executable = filepath.Join(dir, "themis")
	if runtime.GOOS == "windows" {
		executable += ".exe"
	}
	args := []string{"build"}
	if raceEnabled {
		args = append(args, "-race")
	}
	args = append(args, "-o", executable, "./cmd/themis")
	build := exec.Command("go", args...)
	build.Dir = "../.."
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func setup(t *testing.T, mode string) (*fixture.Client, plan.ExperimentPlan, safety.Authorization, string) {
	t.Helper()
	root := t.TempDir()
	directory := filepath.Join(root, "fixture")
	id, err := fixture.Start(context.Background(), executable, directory, "demo", mode, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ownedProcess, err := os.FindProcess(id.PID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, err := fixture.Open(directory)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = c.Stop(ctx)
			cancel()
			c.Close()
		}
		_ = ownedProcess.Kill()
		_ = ownedProcess.Release()
		if log, err := os.ReadFile(filepath.Join(directory, "worker.log")); err == nil && bytes.Contains(log, []byte("WARNING: DATA RACE")) {
			t.Error("race detector reported a fixture process race")
		}
	})
	c, err := fixture.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	data, err := os.ReadFile("../../examples/owned-latency/experiment.yaml")
	if err != nil {
		t.Fatal(err)
	}
	validated, err := contract.ParseExperiment(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	p, err := plan.CompileExperiment(validated, id)
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.Authorize(context.Background(), p, p.Digest())
	if err != nil {
		t.Fatal(err)
	}
	return c, p, a, root
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition did not become true within 5s")
}

func TestRealScenariosAndReplay(t *testing.T) {
	for _, test := range []struct {
		mode      string
		verdict   result.Verdict
		execution result.ExecutionStatus
		confirmed bool
	}{{"healthy", result.Pass, result.Succeeded, true}, {"buggy", result.Fail, result.Succeeded, true}, {"noop-adapter", result.Inconclusive, result.Succeeded, false}, {"cleanup-denied", result.Inconclusive, result.CleanupPending, true}} {
		t.Run(test.mode, func(t *testing.T) {
			c, p, a, root := setup(t, test.mode)
			r, dir, err := Execute(context.Background(), p, a, cDirectory(root), filepath.Join(root, "runs"))
			if err != nil {
				t.Fatal(err)
			}
			if r.Verdict != test.verdict || r.Execution.Status != test.execution || r.InterventionConfirmed != test.confirmed || !r.RecoveryObserved {
				t.Fatalf("unexpected outcome: %+v", r)
			}
			if r.SufficientObservations != true || len(r.Observations) != 12 {
				t.Fatal("missing real observations")
			}
			if r.FaultAttempted == nil || !*r.FaultAttempted || r.Provenance == nil || r.Provenance.Source != LocallyCollected {
				t.Fatal("acknowledged local collection provenance missing")
			}
			replayed, err := ReplayFile(filepath.Join(dir, "events.jsonl"))
			if err != nil || replayed.Verdict != r.Verdict || replayed.JournalDigest != r.JournalDigest {
				t.Fatalf("replay mismatch: %v", err)
			}
			if replayed.Provenance == nil || replayed.Provenance.Source != UnsignedReplay {
				t.Fatal("replay provenance misclassified")
			}
			if test.mode == "cleanup-denied" {
				s, err := c.Status(context.Background())
				if err != nil || s.ActiveFault != nil {
					t.Fatalf("fault not removed: %v", err)
				}
				process, _ := os.FindProcess(c.Identity.PID)
				if err := process.Kill(); err != nil {
					t.Fatal(err)
				}
				waitFor(t, func() bool { return c.ListenersClosed(context.Background()) })
			}
			for range 2 {
				receipt, err := Reconcile(dir)
				if err != nil || !receipt.Completed || receipt.RecoveryVerified {
					t.Fatalf("idempotent cleanup: %+v %v", receipt, err)
				}
			}
			if test.mode == "healthy" {
				testJournalNegatives(t, dir)
				testLegacyCompatibility(t, dir, r)
			}
		})
	}
}

func cDirectory(root string) string { return filepath.Join(root, "fixture") }

func testJournalNegatives(t *testing.T, dir string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
	var original []Event
	for _, line := range lines {
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatal(err)
		}
		original = append(original, e)
	}
	for _, test := range []struct {
		name    string
		mutate  func([]Event) []Event
		invalid bool
	}{
		{"missing terminal", func(e []Event) []Event { return e[:len(e)-1] }, false},
		{"no proxy traffic", func(events []Event) []Event {
			for i := range events {
				if o := events[i].Observation; o != nil && o.Phase == "intervention" {
					o.Probes[1] = Probe{Kind: "proxy", StartedNS: o.Probes[1].StartedNS, CompletedNS: o.Probes[1].CompletedNS, Outcome: "request-error"}
				}
			}
			return events
		}, false},
		{"missing intervention", func(events []Event) []Event {
			var kept []Event
			for _, e := range events {
				if e.Observation == nil || e.Observation.Phase != "intervention" {
					kept = append(kept, e)
				}
			}
			return kept
		}, false},
		{"missing recovery", func(events []Event) []Event {
			var kept []Event
			for _, e := range events {
				if e.Observation == nil || e.Observation.Phase != "recovery" {
					kept = append(kept, e)
				}
			}
			return kept
		}, false},
		{"forged response", func(events []Event) []Event {
			for i := range events {
				if o := events[i].Observation; o != nil && o.Phase == "intervention" {
					o.Probes[1].Response.ProxyID = "forged"
				}
			}
			return events
		}, false},
		{"wrong digest", func(events []Event) []Event {
			events[0].Manifest.Plan = bytes.Replace(events[0].Manifest.Plan, []byte("sha256:"), []byte("sha257:"), 1)
			return events
		}, true},
		{"wrong run", func(events []Event) []Event { events[2].RunID = localstate.RandomID(); return events }, true},
		{"wrong adapter", func(events []Event) []Event { events[0].Manifest.Handle.AdapterVersion = "wrong"; return events }, true},
		{"out of order", func(events []Event) []Event { events[1].State = Applied; return events }, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var events []Event
			encoded, _ := json.Marshal(original)
			_ = json.Unmarshal(encoded, &events)
			events = test.mutate(events)
			var changed bytes.Buffer
			for i, e := range events {
				e.Sequence = i + 1
				_ = json.NewEncoder(&changed).Encode(e)
			}
			r, err := Replay(&changed)
			if test.invalid {
				if err == nil {
					t.Fatal("corrupt journal accepted")
				}
			} else if err != nil || r.Verdict == result.Pass {
				t.Fatalf("false PASS or unexpected parse failure: %v, %s", err, r.Verdict)
			}
		})
	}
	for _, data := range [][]byte{data[:len(data)-2], []byte("{broken}\n"), append(append([]byte{}, data...), []byte("{}\n")...)} {
		if _, err := Replay(bytes.NewReader(data)); err == nil {
			t.Fatal("partial or corrupt journal accepted")
		}
	}
}

func TestAdmissionDuplicateAndExpiry(t *testing.T) {
	c, p, a, _ := setup(t, "healthy")
	request, _ := http.NewRequest(http.MethodPost, c.Identity.ControlURL+"/apply", strings.NewReader(`{}`))
	httpClient, transport := fixture.NewHTTPClient()
	response, err := httpClient.Do(request)
	transport.CloseIdleConnections()
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("unauthorized mutation accepted")
	}
	original := c.Identity
	c.Identity.InstanceID = localstate.RandomID()
	if _, err := c.Resolve(context.Background()); err == nil {
		t.Fatal("changed runtime identity accepted")
	}
	c.Identity = original
	if _, err := c.Authorize(context.Background(), p, "sha256:wrong"); err == nil {
		t.Fatal("mismatched approval accepted")
	}
	bad := a
	bad.Seal = "forged"
	if _, err := c.Claim(context.Background(), bad, localstate.RandomID()); err == nil {
		t.Fatal("forged authorization accepted")
	}
	bad = a
	bad.ExpiresAt = time.Now().Add(-time.Second)
	if _, err := c.Claim(context.Background(), bad, localstate.RandomID()); err == nil {
		t.Fatal("expired authorization accepted")
	}
	bad = a
	bad.ProxyID = localstate.RandomID()
	if _, err := c.Claim(context.Background(), bad, localstate.RandomID()); err == nil {
		t.Fatal("wrong target accepted")
	}
	h, err := c.Claim(context.Background(), a, localstate.RandomID())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Claim(context.Background(), a, localstate.RandomID()); err == nil {
		t.Fatal("concurrent or reused approval accepted")
	}
	badHandle := h
	badHandle.AdapterVersion = "other"
	if _, err := c.Apply(context.Background(), badHandle); err == nil {
		t.Fatal("wrong adapter mutated")
	}
	s, err := c.Status(context.Background())
	if err != nil || s.ApplyCount != 0 {
		t.Fatal("denial caused a fault mutation")
	}
	first, err := c.Apply(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := c.Apply(context.Background(), h)
	if err != nil || !duplicate.AlreadyApplied || duplicate.FaultExpiresAt != first.FaultExpiresAt {
		t.Fatal("duplicate was not inspect-only")
	}
	waitFor(t, func() bool { s, err := c.Status(context.Background()); return err == nil && s.ActiveFault == nil })
	if _, err := c.Apply(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	s, err = c.Status(context.Background())
	if err != nil || s.ApplyCount != 1 || s.ActiveFault != nil {
		t.Fatal("expired fault reapplied")
	}
	for range 2 {
		if err := c.Remove(context.Background(), h); err != nil {
			t.Fatal(err)
		}
	}
	// Actual post-expiry traffic, with the client absent during the lease.
	response, err = c.DataRequest(context.Background(), "proxy", localstate.RandomID())
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("normal behavior not restored")
	}
}

func TestExpiredUnusedAuthorization(t *testing.T) {
	c, _, a, _ := setup(t, "healthy")
	timer := time.NewTimer(time.Until(a.ExpiresAt) + 20*time.Millisecond)
	defer timer.Stop()
	<-timer.C
	if _, err := c.Claim(context.Background(), a, localstate.RandomID()); err == nil {
		t.Fatal("expired unused authorization admitted")
	}
	s, err := c.Status(context.Background())
	if err != nil || s.ApplyCount != 0 || s.ActiveFault != nil {
		t.Fatal("expired authorization mutated fault state")
	}
}

func TestExpiredClaimLease(t *testing.T) {
	c, _, a, _ := setup(t, "healthy")
	h, err := c.Claim(context.Background(), a, localstate.RandomID())
	if err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(time.Until(h.ExpiresAt) + 20*time.Millisecond)
	defer timer.Stop()
	<-timer.C
	if _, err := c.Apply(context.Background(), h); err == nil {
		t.Fatal("expired claim lease admitted first application")
	}
	s, err := c.Status(context.Background())
	if err != nil || s.ApplyCount != 0 || s.ActiveFault != nil {
		t.Fatalf("expired claim mutated fault: count=%d error=%v", s.ApplyCount, err)
	}
	if clean := cleanup(c, h, 2*time.Second); !clean.Completed {
		t.Fatal("expired claim prevented authorized cleanup")
	}
}

func TestJournalFailureLeavesIndependentExpiry(t *testing.T) {
	c, p, a, root := setup(t, "healthy")
	runID := localstate.RandomID()
	h, err := c.Claim(context.Background(), a, runID)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := localstate.CreateDirectory(filepath.Join(root, "broken-journal"))
	if err != nil {
		t.Fatal(err)
	}
	a.Seal = ""
	m := Manifest{Plan: p.JSON(), Authorization: a, Handle: h, StartedAt: time.Now().UTC()}
	if err := localstate.WriteNew(filepath.Join(dir, "resources.json"), Inventory{Version, cDirectory(root), m}); err != nil {
		t.Fatal(err)
	}
	f, err := localstate.OpenNew(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	j := &journal{file: f, runID: runID, epoch: time.Now()}
	if err := j.append(Event{State: Authorized, Manifest: &m}); err != nil {
		t.Fatal(err)
	}
	if err := collect(context.Background(), c, j, p, Baseline); err != nil {
		t.Fatal(err)
	}
	if err := j.append(Event{State: BaselineCompleted}); err != nil {
		t.Fatal(err)
	}
	if err := j.append(Event{State: Revalidating}); err != nil {
		t.Fatal(err)
	}
	if err := j.append(Event{State: Intent}); err != nil {
		t.Fatal(err)
	}
	receipt, err := c.Apply(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := j.append(Event{State: Applied, Receipt: &receipt}); err == nil {
		t.Fatal("journal write unexpectedly succeeded")
	}
	waitFor(t, func() bool {
		s, err := c.Status(context.Background())
		return err == nil && s.ActiveFault == nil && s.ApplyCount == 1
	})
	r, err := ReplayFile(filepath.Join(dir, "events.jsonl"))
	if err != nil || r.Verdict == result.Pass || r.CleanupCompleted || r.FaultAttempted != nil {
		t.Fatalf("lost acknowledgement trusted: %v", err)
	}
	clean, err := Reconcile(dir)
	if err != nil || !clean.Completed {
		t.Fatalf("cleanup after storage failure: %v", err)
	}
}

func TestCancellationAndTimeout(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(fmt.Sprint(timeout), func(t *testing.T) {
			c, p, a, root := setup(t, "healthy")
			ctx, cancel := context.WithCancel(context.Background())
			if timeout {
				ctx, cancel = context.WithTimeout(context.Background(), 900*time.Millisecond)
			} else {
				go func() {
					for {
						select {
						case <-ctx.Done():
							return
						default:
						}
						s, err := c.Status(ctx)
						if err == nil && s.ActiveFault != nil {
							cancel()
							return
						}
						time.Sleep(10 * time.Millisecond)
					}
				}()
			}
			defer cancel()
			r, _, err := Execute(ctx, p, a, cDirectory(root), filepath.Join(root, "runs"))
			if err != nil {
				t.Fatal(err)
			}
			expected := result.Cancelled
			if timeout {
				expected = result.TimedOut
			}
			if r.Execution.Status != expected || r.Verdict == result.Pass || !r.CleanupCompleted || r.RecoveryObserved {
				t.Fatalf("cancellation result: %+v", r)
			}
		})
	}
}

func TestActualCLIProcessDeath(t *testing.T) {
	c, p, a, root := setup(t, "healthy")
	authPath := filepath.Join(cDirectory(root), "test-authorization.json")
	if err := localstate.WriteNew(authPath, a); err != nil {
		t.Fatal(err)
	}
	contractPath, err := filepath.Abs("../../examples/owned-latency/experiment.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "experiment", "run", "-f", contractPath, "--fixture", cDirectory(root), "--authorization", authPath, "--runs-dir", filepath.Join(root, "runs"))
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	waitFor(t, func() bool { s, err := c.Status(context.Background()); return err == nil && s.ActiveFault != nil })
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	t.Logf("terminated actual CLI PID %d; independent fixture PID %d remains", cmd.Process.Pid, c.Identity.PID)
	if err := cmd.Wait(); err == nil {
		t.Fatal("CLI process unexpectedly succeeded")
	}
	waitFor(t, func() bool {
		s, err := c.Status(context.Background())
		return err == nil && s.ActiveFault == nil && s.ApplyCount == 1
	})
	t.Log("guardian independently expired the fault after CLI termination")
	dirs, err := filepath.Glob(filepath.Join(root, "runs", "run-*"))
	if err != nil || len(dirs) != 1 {
		t.Fatal("missing crash inventory")
	}
	dir := dirs[0]
	status, err := Inspect(context.Background(), dir)
	if err != nil || status.Live.Runner != "NOT_RUNNING" || status.History.OriginalReport != nil && status.History.OriginalReport.RecoveryObserved {
		t.Fatalf("process death inspection: runner=%s history=%s error=%v", status.Live.Runner, status.History.Source, err)
	}
	r, err := ReplayFile(filepath.Join(dir, "events.jsonl"))
	if err != nil || r.Verdict == result.Pass || r.Execution.Status != result.CleanupPending {
		t.Fatalf("interrupted replay: %s %v", r.Verdict, err)
	}
	// The guardian survives the CLI and has actually restored proxy response time.
	start := time.Now()
	response, err := c.DataRequest(context.Background(), "proxy", localstate.RandomID())
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if time.Since(start) > 150*time.Millisecond {
		t.Fatal("fault still affects traffic after expiry")
	}
	if _, err := c.Authorize(context.Background(), p, p.Digest()); err != nil {
		t.Fatal(err)
	} // identity remains authentic
	// Corrupt audit history is preserved; cleanup uses the previously durable,
	// private resource inventory instead of guessing external actions.
	f, err := os.OpenFile(filepath.Join(dir, "events.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("{partial")
	_ = f.Close()
	if _, err := ReplayFile(filepath.Join(dir, "events.jsonl")); err == nil {
		t.Fatal("corruption accepted")
	}
	clean, err := Cancel(context.Background(), dir)
	if err != nil || !clean.Completed || clean.RecoveryVerified {
		t.Fatalf("crash reconciliation %+v %v", clean, err)
	}
}

func TestActualProxyProcessDeath(t *testing.T) {
	c, p, a, root := setup(t, "healthy")
	type outcome struct {
		r   Report
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		r, _, err := Execute(context.Background(), p, a, cDirectory(root), filepath.Join(root, "runs"))
		done <- outcome{r, err}
	}()
	waitFor(t, func() bool { s, err := c.Status(context.Background()); return err == nil && s.ActiveFault != nil })
	process, err := os.FindProcess(c.Identity.PID)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Kill(); err != nil {
		t.Fatal(err)
	}
	t.Logf("terminated actual fixture/proxy PID %d", c.Identity.PID)
	select {
	case got := <-done:
		if got.err != nil || got.r.Verdict == result.Pass || got.r.RecoveryObserved || !got.r.CleanupCompleted {
			t.Fatalf("dead proxy treated as recovery: %+v %v", got.r, got.err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("runner stuck after proxy death")
	}
}

func TestStrictResponseSignature(t *testing.T) {
	c, _, _, _ := setup(t, "healthy")
	id := localstate.RandomID()
	response, err := c.DataRequest(context.Background(), "proxy", id)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body fixture.DataResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if !fixture.VerifyData(body, c.Identity, id, "proxy") {
		t.Fatal("real response signature failed")
	}
	body.RequestID = localstate.RandomID()
	if fixture.VerifyData(body, c.Identity, body.RequestID, "proxy") {
		t.Fatal("forged correlation accepted")
	}
	if strings.Contains(fmt.Sprint(body), "Bearer") {
		t.Fatal("credential leak")
	}
}
