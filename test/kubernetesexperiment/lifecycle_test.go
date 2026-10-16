package kubernetesexperiment_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/kubeexperiment"
	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

func lifecycleHarness(t *testing.T) *harness {
	t.Helper()
	if os.Getenv("THEMIS_KIND_LIFECYCLE") != "1" {
		t.Skip("NOT EXECUTED: explicit T2.2 owned Kind lifecycle opt-in required")
	}
	state, binary := os.Getenv("THEMIS_KIND_EXPERIMENT_STATE"), os.Getenv("THEMIS_KUBE_RUNNER_BINARY")
	if state == "" || binary == "" {
		t.Fatal("explicit owned state and runner required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	t.Cleanup(cancel)
	c, err := kubeexperiment.Open(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, ctx: ctx, cluster: c, state: state, binary: binary, evidence: filepath.Join(os.Getenv("THEMIS_KIND_EXPERIMENT_EVIDENCE"), t.Name()), repository: filepath.Dir(filepath.Dir(state))}
	if root := os.Getenv("THEMIS_KIND_EXPERIMENT_EVIDENCE"); root == "" {
		h.evidence = ""
	} else if err := os.MkdirAll(h.evidence, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.save("commands", h.commands) })
	return h
}

type activeRunner struct {
	cmd            *exec.Cmd
	stdout, stderr bytes.Buffer
	args           []string
	started        time.Time
	waited         bool
}

func (h *harness) start(p prepared) *activeRunner {
	h.t.Helper()
	r := &activeRunner{args: []string{"run", "--state", h.state, "-f", p.planFile, "--authorization", p.authFile, "--runs", p.root}, started: time.Now()}
	r.cmd = exec.CommandContext(h.ctx, h.binary, r.args...)
	r.cmd.Dir = h.repository
	r.cmd.Stdout = &r.stdout
	r.cmd.Stderr = &r.stderr
	if err := r.cmd.Start(); err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() {
		if !r.waited {
			_ = r.cmd.Process.Kill()
			_ = r.cmd.Wait()
		}
	})
	return r
}

func (h *harness) await(p prepared, event string) []kubeexperiment.Event {
	h.t.Helper()
	for start := time.Now(); time.Since(start) < 8*time.Second; {
		events, err := kubeexperiment.ReadJournal(filepath.Join(p.runDir, "events.jsonl"))
		if err == nil {
			for _, e := range events {
				if e.Type == event {
					return events
				}
			}
		}
		time.Sleep(time.Millisecond)
	}
	h.t.Fatal("real runner did not reach", event)
	return nil
}

func (h *harness) finish(label string, r *activeRunner) (int, kubeexperiment.Report) {
	h.t.Helper()
	err := r.cmd.Wait()
	r.waited = true
	code := exitCode(err)
	h.commands = append(h.commands, map[string]any{"label": label, "program": h.binary, "arguments": r.args, "exitCode": code, "elapsedMS": time.Since(r.started).Milliseconds(), "stdout": r.stdout.String(), "stderr": r.stderr.String()})
	var output struct {
		Directory string                `json:"directory"`
		Report    kubeexperiment.Report `json:"report"`
	}
	if json.Unmarshal(r.stdout.Bytes(), &output) != nil {
		h.t.Fatal("runner did not emit a structured result", code, r.stderr.String())
	}
	return code, output.Report
}

func TestOwnedKindCrossProcessCancellation(t *testing.T) {
	h := lifecycleHarness(t)
	for _, trigger := range []string{"BASELINE", "INTENT", "APPLIED", "REMOVED", "RECOVERY", "FINAL"} {
		p := h.prepare("cancel-"+trigger, "healthy")
		runner := h.start(p)
		h.await(p, trigger)
		output := h.command("cancel-"+trigger, 0, "cancel", "--run-directory", p.runDir)
		var receipt kubeexperiment.CleanupReceipt
		if json.Unmarshal(output, &receipt) != nil || receipt.Action == nil || !receipt.RecoveryVerified {
			t.Fatal("invalid real cancellation receipt", trigger)
		}
		code, report := h.finish("runner-cancel-"+trigger, runner)
		if !receipt.Action.AlreadyFinalized {
			if report.Verdict == result.Pass || !report.CancellationAccepted || report.Execution != result.Cancelled || code != 3 {
				t.Fatal("acknowledged cancellation before finalization produced unsafe result", trigger, code, report.Execution, report.Unknowns)
			}
		} else if report.Verdict != result.Pass || code != 0 {
			t.Fatal("late action rewrote historical completion", trigger, code, report.Unknowns)
		}
		before, _ := os.ReadFile(filepath.Join(p.runDir, "events.jsonl"))
		h.command("cancel-repeat-"+trigger, 0, "cancel", "--run-directory", p.runDir)
		after, _ := os.ReadFile(filepath.Join(p.runDir, "events.jsonl"))
		if !bytes.Equal(before, after) {
			t.Fatal("repeat cancellation rewrote historical events")
		}
		h.copy("cancel-"+trigger+"-events.jsonl", filepath.Join(p.runDir, "events.jsonl"))
		h.save("cancel-"+trigger+"-report", report)
		status := h.command("status-"+trigger, 0, "status", "--run-directory", p.runDir)
		var inspection kubeexperiment.Inspection
		if json.Unmarshal(status, &inspection) != nil || inspection.Current.ResidualIntervention != "ABSENT" || !inspection.JournalComplete {
			t.Fatal("status did not separate current and history", trigger)
		}
		t.Logf("REAL KIND separate CLI cancellation triggered at %s: acceptedAfterFinal=%v runnerExit=%d historical=%s", trigger, receipt.Action.AlreadyFinalized, code, report.Verdict)
	}
	// Deliberately denied immediate removal remains exit 7; monotonic expiry
	// later permits reconciliation, without promoting the original result.
	p := h.prepare("cancel-expiry-race", "cleanup-denied")
	runner := h.start(p)
	events := h.await(p, "APPLIED")
	var expires time.Time
	for _, e := range events {
		if e.Type == "APPLIED" {
			expires = e.Status.ExpiresAt
		}
	}
	h.command("cancel-active-cleanup-denied", 7, "cancel", "--run-directory", p.runDir)
	_, historical := h.finish("cancel-cleanup-denied-runner", runner)
	if historical.Verdict == result.Pass {
		t.Fatal("cancellation with denied cleanup passed")
	}
	if wait := time.Until(expires) + 50*time.Millisecond; wait > 0 {
		time.Sleep(wait)
	}
	h.command("cancel-after-independent-expiry", 0, "reconcile", "--run-directory", p.runDir)
	var recorded kubeexperiment.Report
	if localstate.Read(filepath.Join(p.runDir, "report.json"), &recorded) != nil || recorded.Verdict != historical.Verdict || recorded.Execution != historical.Execution {
		t.Fatal("later cleanup promoted the historical result")
	}
	h.copy("cancel-expiry-original-events.jsonl", filepath.Join(p.runDir, "events.jsonl"))
	// New offline verifier is network-independent and cannot output trusted PASS.
	verified := h.command("offline-verification", 3, "verify", "-f", filepath.Join(p.runDir, "events.jsonl"), "--expect-plan-digest", p.plan.Digest())
	var verification kubeexperiment.EvidenceVerification
	if json.Unmarshal(verified, &verification) != nil || verification.TrustedExecutionVerdict == result.Pass {
		t.Fatal("offline journal became trusted execution evidence")
	}
}

func TestOwnedKindPortForwardLossAndDeadRunnerCancellation(t *testing.T) {
	h := lifecycleHarness(t)
	p := h.prepare("closed-portforward", "healthy")
	dir, err := localstate.CreateDirectory(p.runDir)
	if err != nil {
		t.Fatal(err)
	}
	if err = localstate.WriteNew(filepath.Join(dir, "inventory.json"), map[string]any{"version": kubeexperiment.InventoryVersion, "plan": p.plan, "authorization": p.auth, "stateDirectory": h.state}); err != nil {
		t.Fatal(err)
	}
	s, err := h.cluster.Connect(h.ctx, p.plan)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := s.Client.Control(h.ctx, p.auth, "apply")
	if err != nil {
		t.Fatal(err)
	}
	s.Close() // close an actual SPDY port-forward while the fixture is active
	h.save("portforward-disconnected-active", applied)
	if wait := time.Until(applied.ExpiresAt) + 60*time.Millisecond; wait > 0 {
		time.Sleep(wait)
	}
	s, err = h.cluster.Connect(h.ctx, p.plan)
	if err != nil {
		t.Fatal(err)
	}
	status, err := s.Client.Control(h.ctx, p.auth, "status")
	s.Close()
	if err != nil || status.Active || status.Reason != "expired" {
		t.Fatal("port-forward loss extended fault", err)
	}
	h.save("portforward-loss-independent-expiry", status)
	output := h.command("portforward-loss-cancel", 0, "cancel", "--run-directory", dir)
	var receipt kubeexperiment.CleanupReceipt
	if json.Unmarshal(output, &receipt) != nil || !receipt.RecoveryVerified {
		t.Fatal("application recovery after port-forward loss unproven")
	}
	h.command("portforward-loss-readonly-status", 0, "status", "--run-directory", dir)
	// Actual CLI process termination; cancel runs from a new process afterwards.
	dead := h.prepare("cancel-dead-runner", "healthy")
	runner := h.start(dead)
	h.await(dead, "APPLIED")
	if err = runner.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err = runner.cmd.Wait()
	runner.waited = true
	h.commands = append(h.commands, map[string]any{"label": "actual-runner-killed-after-Apply", "program": h.binary, "arguments": runner.args, "exitCode": exitCode(err), "stdout": runner.stdout.String(), "stderr": runner.stderr.String()})
	output = h.command("cancel-with-runner-dead", 0, "cancel", "--run-directory", dead.runDir)
	if json.Unmarshal(output, &receipt) != nil || !receipt.RecoveryVerified {
		t.Fatal("dead runner cancellation did not recover")
	}
	h.copy("dead-runner-original-prefix.jsonl", filepath.Join(dead.runDir, "events.jsonl"))
	inspection, err := h.cluster.Inspect(h.ctx, dead.runDir)
	if err != nil || inspection.JournalComplete || inspection.RecordedVerdict == result.Pass || inspection.Current.ResidualIntervention != "ABSENT" {
		t.Fatal("cleanup fabricated completed history", err)
	}
	h.save("dead-runner-current-and-history", inspection)
	// Missing or corrupt private inventory must never be guessed from a journal.
	inventoryPath := filepath.Join(dead.runDir, "inventory.json")
	saved := filepath.Join(dead.runDir, "inventory.saved-private")
	if err = os.Rename(inventoryPath, saved); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := os.Stat(saved); err == nil {
			_ = os.Remove(inventoryPath)
			_ = os.Rename(saved, inventoryPath)
		}
	}()
	h.command("missing-inventory-cancel-pending", 7, "cancel", "--run-directory", dead.runDir)
	if err = localstate.WriteNew(inventoryPath, map[string]string{"version": "corrupt"}); err != nil {
		t.Fatal(err)
	}
	h.command("corrupt-inventory-cancel-pending", 7, "cancel", "--run-directory", dead.runDir)
	if err = os.Remove(inventoryPath); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(saved, inventoryPath); err != nil {
		t.Fatal(err)
	}
	h.command("intact-inventory-idempotent-cancel", 0, "cancel", "--run-directory", dead.runDir)
	// Authentic fixture rejects the invocation key on the cleanup command path.
	bad := h.prepare("cleanup-key-rejected", "healthy")
	if _, err = localstate.CreateDirectory(bad.runDir); err != nil {
		t.Fatal(err)
	}
	if err = localstate.WriteNew(filepath.Join(bad.runDir, "inventory.json"), map[string]any{"version": kubeexperiment.InventoryVersion, "plan": bad.plan, "authorization": bad.auth, "stateDirectory": h.state}); err != nil {
		t.Fatal(err)
	}
	s, err = h.cluster.Connect(h.ctx, bad.plan)
	if err != nil {
		t.Fatal(err)
	}
	applied, err = s.Client.Control(h.ctx, bad.auth, "apply")
	if err != nil {
		t.Fatal(err)
	}
	wrong := bad.auth
	wrong.CleanupKey = wrong.InvocationKey
	_, err = s.Client.Control(h.ctx, wrong, "remove")
	if !errors.Is(err, kubefault.ErrDenied) {
		t.Fatal("fixture accepted wrong cleanup credential", err)
	}
	if wait := time.Until(applied.ExpiresAt) + 50*time.Millisecond; wait > 0 {
		time.Sleep(wait)
	}
	status, err = s.Client.Control(h.ctx, bad.auth, "status")
	if err != nil || status.Active || status.Reason != "expired" {
		t.Fatal("cleanup authentication failure extended fault", err)
	}
	s.Close()
	h.save("cleanup-key-denial-independent-expiry", status)
	output = h.command("cleanup-key-denial-later-recovery", 0, "cancel", "--run-directory", bad.runDir)
	if json.Unmarshal(output, &receipt) != nil || !receipt.RecoveryVerified {
		t.Fatal("application recovery after cleanup key denial unproven")
	}
}
