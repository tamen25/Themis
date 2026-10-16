package kubernetesexperiment_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/kube"
	"github.com/tamen25/themis/internal/kubeexperiment"
	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type coordinated struct {
	directory string
	record    kubeexperiment.CoordinationRecord
	execution prepared
}

func coordinationHarness(t *testing.T) *harness {
	if os.Getenv("THEMIS_KIND_COORDINATION") != "1" {
		t.Skip("NOT EXECUTED: explicit T2.3 owned Kind coordination opt-in required")
	}
	return lifecycleHarness(t)
}

func (h *harness) coordinate(label, scenario string, approve bool) coordinated {
	h.t.Helper()
	dir := filepath.Join(h.state, "coord-"+label+"-"+kubefault.RandomID()[:12])
	data := h.command(label+"-prepare", 0, "coordinate", "prepare", "--state", h.state, "--directory", dir, "--scenario", scenario)
	r, err := kubeexperiment.DecodeCoordinationRecord(data)
	if err != nil {
		h.t.Fatal(err)
	}
	if approve {
		data = h.command(label+"-approve", 0, "coordinate", "approve", "--directory", dir, "--approve-digest", r.Proposal.PlanDigest)
		r, err = kubeexperiment.DecodeCoordinationRecord(data)
		if err != nil {
			h.t.Fatal(err)
		}
	}
	p := prepared{plan: r.Proposal.Plan, root: filepath.Join(dir, "runs")}
	if approve {
		p.runDir = filepath.Join(dir, filepath.FromSlash(r.References.RunDirectory))
		if err = localstate.Read(filepath.Join(dir, "authorization.json"), &p.auth); err != nil {
			h.t.Fatal(err)
		}
	}
	return coordinated{dir, r, p}
}

func (h *harness) startCoordinate(p coordinated) *activeRunner {
	h.t.Helper()
	r := &activeRunner{args: []string{"coordinate", "start", "--directory", p.directory}, started: time.Now()}
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

func (h *harness) finishCoordinate(label string, r *activeRunner, want int) kubeexperiment.CoordinationRecord {
	h.t.Helper()
	err := r.cmd.Wait()
	r.waited = true
	code := exitCode(err)
	h.commands = append(h.commands, map[string]any{"label": label, "program": h.binary, "arguments": r.args, "exitCode": code, "elapsedMS": time.Since(r.started).Milliseconds(), "stdout": r.stdout.String(), "stderr": r.stderr.String()})
	if code != want {
		h.t.Fatal(label, "exit", code, "want", want, r.stderr.String())
	}
	record, err := kubeexperiment.DecodeCoordinationRecord(r.stdout.Bytes())
	if err != nil {
		h.t.Fatal(label, err)
	}
	return record
}

func (h *harness) coordinatedResult(label string, p coordinated, r kubeexperiment.CoordinationRecord, want result.Verdict) {
	h.t.Helper()
	if r.LiveResult == nil || r.LiveResult.Verdict != want || r.InvocationID != p.record.InvocationID || r.LiveResult.PlanDigest != p.record.Proposal.PlanDigest || len(r.LiveResult.Observations) == 0 {
		h.t.Fatal(label, "missing real execution result")
	}
	h.copy(label+"-events.jsonl", filepath.Join(p.execution.runDir, "events.jsonl"))
	h.save(label+"-coordination", r)
	verification, err := kubeexperiment.VerifyEvidence(filepath.Join(p.execution.runDir, "events.jsonl"), p.record.Proposal.PlanDigest)
	if err != nil || !verification.BindingsValid || verification.TrustedExecutionVerdict == result.Pass || verification.Report.CandidateVerdict != want {
		h.t.Fatal(label, "evidence mismatch", err)
	}
	h.save(label+"-verification", verification)
}

func TestOwnedKindCoordinatedMeasuredVerdicts(t *testing.T) {
	h := coordinationHarness(t)
	for _, test := range []struct {
		label, scenario string
		exit            int
		verdict         result.Verdict
	}{{"A-healthy", "healthy", 0, result.Pass}, {"B-buggy", "buggy", 2, result.Fail}, {"C-noop", "noop", 3, result.Inconclusive}, {"D-cleanup-denied", "cleanup-denied", 7, result.Inconclusive}} {
		p := h.coordinate(test.label, test.scenario, true)
		runner := h.startCoordinate(p)
		if test.scenario == "healthy" {
			h.await(p.execution, "APPLIED")
			h.command("G-duplicate-start-active", 5, "coordinate", "start", "--directory", p.directory)
		}
		r := h.finishCoordinate(test.label, runner, test.exit)
		h.coordinatedResult(test.label, p, r, test.verdict)
		if test.scenario == "healthy" {
			s, err := h.cluster.Connect(h.ctx, p.execution.plan)
			if err != nil {
				t.Fatal(err)
			}
			status, err := s.Client.Control(h.ctx, p.execution.auth, "status")
			s.Close()
			if err != nil || status.ApplyCount != 1 || status.Active {
				t.Fatal("duplicate caused more than one intervention", err)
			}
			h.save("G-one-intervention", status)
		}
		if test.scenario == "cleanup-denied" {
			if r.LiveResult.Execution != result.CleanupPending {
				t.Fatal("cleanup denial not pending")
			}
			before, _ := os.ReadFile(filepath.Join(p.execution.runDir, "events.jsonl"))
			events, err := kubeexperiment.ReadJournal(filepath.Join(p.execution.runDir, "events.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			var deadline time.Time
			for _, event := range events {
				if event.Type == "APPLIED" {
					deadline = event.Status.ExpiresAt
				}
			}
			if deadline.IsZero() {
				t.Fatal("cleanup-denied invocation has no recorded deadline")
			}
			if delay := time.Until(deadline) + 60*time.Millisecond; delay > 0 {
				time.Sleep(delay)
			}
			h.command("D-reconcile-independent-expiry", 0, "coordinate", "reconcile", "--directory", p.directory)
			after, _ := os.ReadFile(filepath.Join(p.execution.runDir, "events.jsonl"))
			if !bytes.Equal(before, after) {
				t.Fatal("later cleanup changed historical result")
			}
		}
		verifyExit := 3
		if test.verdict == result.Fail {
			verifyExit = 2
		}
		h.command(test.label+"-offline-verify", verifyExit, "coordinate", "verify", "--directory", p.directory)
		h.command(test.label+"-status", 0, "coordinate", "status", "--directory", p.directory)
		t.Logf("REAL KIND %s: actual coordinate CLI exit %d, measured %s, unsigned history cannot become trusted PASS", test.label, test.exit, test.verdict)
	}
}

func TestOwnedKindCoordinationDriftAndUnusedApproval(t *testing.T) {
	h := coordinationHarness(t)
	admin := h.admin()
	p := h.coordinate("E-request-drift", "healthy", true)
	run := kube.RunObject()
	key := client.ObjectKey{Namespace: kube.Namespace, Name: "latency-request"}
	if err := admin.Get(h.ctx, key, run); err != nil {
		t.Fatal(err)
	}
	run.Object["spec"].(map[string]any)["contract"].(map[string]any)["name"] = "changed-" + kubefault.RandomID()[:12]
	h.guard(admin)
	if err := admin.Update(h.ctx, run); err != nil {
		t.Fatal(err)
	}
	h.command("E-changed-request-start-denied", 5, "coordinate", "start", "--directory", p.directory)
	if err := admin.Get(h.ctx, key, run); err != nil {
		t.Fatal(err)
	}
	run.Object["spec"].(map[string]any)["contract"].(map[string]any)["name"] = p.record.Proposal.Requested.Contract.Name
	h.guard(admin)
	if err := admin.Update(h.ctx, run); err != nil {
		t.Fatal(err)
	}
	h.command("E-reverted-request-original-still-denied", 5, "coordinate", "start", "--directory", p.directory)
	h.resetRequest(admin)
	p = h.coordinate("F-pod-replacement", "healthy", true)
	pod := &corev1.Pod{}
	if err := admin.Get(h.ctx, client.ObjectKey{Namespace: kube.Namespace, Name: p.execution.plan.Target.Fixture.PodName}, pod); err != nil {
		t.Fatal(err)
	}
	h.guard(admin)
	uid := pod.UID
	if err := admin.Delete(h.ctx, pod, client.Preconditions{UID: &uid}); err != nil {
		t.Fatal(err)
	}
	replacement := h.waitReady(admin, string(uid), "")
	h.exactForwardRole(admin, replacement)
	h.command("F-original-invocation-replacement-denied", 5, "coordinate", "start", "--directory", p.directory)
	h.resetRequest(admin)
	fresh := h.coordinate("F-replacement-zero-apply", "healthy", true)
	s, err := h.cluster.Connect(h.ctx, fresh.execution.plan)
	if err != nil {
		t.Fatal(err)
	}
	status, err := s.Client.Control(h.ctx, fresh.execution.auth, "status")
	s.Close()
	if err != nil || status.Active || status.Applied {
		t.Fatal("replacement target faulted", err)
	}
	h.save("F-replacement-zero-apply", status)
	h.command("unused-approved-cancel", 0, "coordinate", "cancel", "--directory", fresh.directory)
	h.command("unused-approved-start-refused", 5, "coordinate", "start", "--directory", fresh.directory)
	unapproved := h.coordinate("operator-death-before-approval", "healthy", false)
	h.command("unapproved-status", 0, "coordinate", "status", "--directory", unapproved.directory)
	h.command("unapproved-cancel", 0, "coordinate", "cancel", "--directory", unapproved.directory)
	h.command("unapproved-late-approval-refused", 5, "coordinate", "approve", "--directory", unapproved.directory, "--approve-digest", unapproved.record.Proposal.PlanDigest)
	expired := h.coordinate("expired-unused-approval", "healthy", true)
	time.Sleep(time.Until(expired.execution.auth.Grant.ApplyBefore) + 30*time.Millisecond)
	h.command("expired-unused-status", 0, "coordinate", "status", "--directory", expired.directory)
	h.command("expired-unused-start-denied", 5, "coordinate", "start", "--directory", expired.directory)
	h.command("expired-unused-cleanup", 7, "coordinate", "cancel", "--directory", expired.directory)
	t.Log("REAL KIND E/F: changed VerificationRun and replaced Pod denied; observed/reverted request cannot revive original invocation; unused/cancelled and expired approval cannot start")
}

func TestOwnedKindCoordinatedDeathRestartAndCancellation(t *testing.T) {
	h := coordinationHarness(t)
	p := h.coordinate("H-runner-death", "healthy", true)
	runner := h.startCoordinate(p)
	events := h.await(p.execution, "APPLIED")
	var applied kubefault.Status
	for _, e := range events {
		if e.Type == "APPLIED" {
			applied = *e.Status
		}
	}
	if err := runner.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err := runner.cmd.Wait()
	runner.waited = true
	h.commands = append(h.commands, map[string]any{"label": "H-actual-runner-killed", "program": h.binary, "arguments": runner.args, "exitCode": exitCode(err), "stdout": runner.stdout.String(), "stderr": runner.stderr.String()})
	if delay := time.Until(applied.ExpiresAt) + 60*time.Millisecond; delay > 0 {
		time.Sleep(delay)
	}
	s, err := h.cluster.Connect(h.ctx, p.execution.plan)
	if err != nil {
		t.Fatal(err)
	}
	status, err := s.Client.Control(h.ctx, p.execution.auth, "status")
	s.Close()
	if err != nil || status.Active || status.Reason != "expired" || status.ApplyCount != 1 {
		t.Fatal("runner death did not independently expire", err)
	}
	h.save("H-independent-expiry", status)
	h.command("H-status-interrupted", 0, "coordinate", "status", "--directory", p.directory)
	h.command("H-no-resume-after-death", 5, "coordinate", "start", "--directory", p.directory)
	h.command("H-reconcile-original-inventory", 0, "coordinate", "reconcile", "--directory", p.directory)
	h.copy("H-incomplete-events.jsonl", filepath.Join(p.execution.runDir, "events.jsonl"))
	h.command("H-incomplete-offline-verification", 3, "coordinate", "verify", "--directory", p.directory)
	p = h.coordinate("I-controller-restart", "healthy", true)
	runner = h.startCoordinate(p)
	h.await(p.execution, "APPLIED")
	program := "powershell"
	if runtime.GOOS != "windows" {
		program = "pwsh"
	}
	arguments := []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/kind-experiment.ps1", "-Action", "restart-controller"}
	if proxy := os.Getenv("THEMIS_TEST_COMMAND_PROXY"); proxy != "" {
		arguments = append(arguments, "-CommandProxy", proxy)
	}
	h.tool("I-restart-only-owned-controller", program, arguments...)
	r := h.finishCoordinate("I-original-runner", runner, 0)
	h.coordinatedResult("I-controller-restart", p, r, result.Pass)
	s, err = h.cluster.Connect(h.ctx, p.execution.plan)
	if err != nil {
		t.Fatal(err)
	}
	status, err = s.Client.Control(h.ctx, p.execution.auth, "status")
	s.Close()
	if err != nil || status.ApplyCount != 1 || status.Active {
		t.Fatal("controller restart repeated intervention", err)
	}
	h.save("I-no-reexecution", status)
	p = h.coordinate("J-separate-cancel", "healthy", true)
	runner = h.startCoordinate(p)
	h.await(p.execution, "APPLIED")
	h.command("J-cancel-independent-cli", 0, "coordinate", "cancel", "--directory", p.directory)
	r = h.finishCoordinate("J-conservatively-cancelled-runner", runner, 3)
	if r.LiveResult == nil || r.LiveResult.Verdict == result.Pass || !r.LiveResult.CancellationAccepted {
		t.Fatal("accepted cancellation passed")
	}
	h.copy("J-cancel-events.jsonl", filepath.Join(p.execution.runDir, "events.jsonl"))
	h.command("J-independent-status", 0, "coordinate", "status", "--directory", p.directory)
	t.Log("REAL KIND H/I/J: actual runner killed; independent expiry and original-inventory cleanup; controller restarted with one Apply; independent CLI cancellation prevents PASS")
}

func TestOwnedKindCoordinatedAPIOutageAndMissingInventory(t *testing.T) {
	h := coordinationHarness(t)
	admin := h.admin()
	p := h.coordinate("L-missing-inventory", "healthy", true)
	runner := h.startCoordinate(p)
	h.await(p.execution, "APPLIED")
	if err := runner.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	killed := runner.cmd.Wait()
	runner.waited = true
	h.commands = append(h.commands, map[string]any{"label": "L-killed-before-inventory-withheld", "program": h.binary, "arguments": runner.args, "exitCode": exitCode(killed), "stdout": runner.stdout.String(), "stderr": runner.stderr.String()})
	path := filepath.Join(p.execution.runDir, "inventory.json")
	if err := os.Rename(path, filepath.Join(p.execution.runDir, "withheld-inventory.json")); err != nil {
		t.Fatal(err)
	}
	h.command("L-missing-execution-inventory-status", 0, "coordinate", "status", "--directory", p.directory)
	h.command("L-missing-execution-inventory-no-guess", 7, "coordinate", "cancel", "--directory", p.directory)
	if err := os.Rename(filepath.Join(p.execution.runDir, "withheld-inventory.json"), path); err != nil {
		t.Fatal(err)
	}
	h.command("L-restored-original-inventory-cleanup", 0, "coordinate", "reconcile", "--directory", p.directory)
	h.copy("L-missing-inventory-events.jsonl", filepath.Join(p.execution.runDir, "events.jsonl"))
	p = h.coordinate("L-api-outage", "healthy", true)
	h.nodeGuard(admin)
	listing := h.tool("L-owned-api-container", "docker", "exec", "themis-t21-control-plane", "crictl", "ps", "--name", "kube-apiserver", "-o", "json")
	var data struct {
		Containers []struct {
			ID     string            `json:"id"`
			Labels map[string]string `json:"labels"`
		} `json:"containers"`
	}
	if json.Unmarshal(listing, &data) != nil || len(data.Containers) != 1 || data.Containers[0].Labels["io.kubernetes.pod.namespace"] != "kube-system" {
		t.Fatal("exact owned API task unavailable")
	}
	id := data.Containers[0].ID
	runner = h.startCoordinate(p)
	h.await(p.execution, "APPLIED")
	h.nodeGuard(admin)
	h.tool("L-pause-only-owned-api", "docker", "exec", "themis-t21-control-plane", "ctr", "-n", "k8s.io", "tasks", "pause", id)
	resumed := false
	defer func() {
		if !resumed {
			h.tool("L-restore-owned-api", "docker", "exec", "themis-t21-control-plane", "ctr", "-n", "k8s.io", "tasks", "resume", id)
		}
	}()
	output := h.command("L-outage-independent-status", 0, "coordinate", "status", "--directory", p.directory)
	if !bytes.Contains(output, []byte(`"residualIntervention": "UNKNOWN"`)) {
		t.Fatal("outage status guessed current state")
	}
	h.command("L-outage-accepted-cancel-pending", 7, "coordinate", "cancel", "--directory", p.directory)
	h.tool("L-resume-only-owned-api", "docker", "exec", "themis-t21-control-plane", "ctr", "-n", "k8s.io", "tasks", "resume", id)
	resumed = true
	// The runner can finish before the cancellation process reaches its gate;
	// even then the API failure must prevent a measured PASS.
	err := runner.cmd.Wait()
	runner.waited = true
	h.commands = append(h.commands, map[string]any{"label": "L-outage-runner", "program": h.binary, "arguments": runner.args, "exitCode": exitCode(err), "stdout": runner.stdout.String(), "stderr": runner.stderr.String()})
	var record kubeexperiment.CoordinationRecord
	if json.Unmarshal(runner.stdout.Bytes(), &record) == nil && record.LiveResult != nil && record.LiveResult.Verdict == result.Pass {
		t.Fatal("API outage passed")
	}
	h.command("L-api-restored-reconcile", 0, "coordinate", "reconcile", "--directory", p.directory)
	h.copy("L-api-outage-events.jsonl", filepath.Join(p.execution.runDir, "events.jsonl"))
	t.Log("REAL KIND L: missing inventory did not cause guessed cleanup; paused owned API returned UNKNOWN/pending, exact original inventory reconciled after restoration")
}

func TestOwnedKindStatusPollingCannotStarveCleanup(t *testing.T) {
	h := coordinationHarness(t)
	admin := h.admin()
	// Start from a fresh synthetic boot so this test controls the exact read
	// budget. This is installer-owned test setup, never a fault adapter action.
	reset := func() {
		p := h.cluster.Owner
		pod := h.waitReady(admin, "", "")
		h.nodeGuard(admin)
		container := strings.TrimPrefix(pod.Status.ContainerStatuses[0].ContainerID, "containerd://")
		if len(container) != 64 || string(pod.UID) == "" || p.DeploymentUID == "" {
			t.Fatal("owned fixture identity unavailable")
		}
		h.tool("K-installer-restart-exact-fixture-boot", "docker", "exec", "themis-t21-control-plane", "crictl", "stop", container)
		h.waitReady(admin, "", pod.Status.ContainerStatuses[0].ContainerID)
		h.resetRequest(admin)
	}
	reset()
	defer reset()
	p := h.coordinate("K-poll-budget", "healthy", true)
	s, err := h.cluster.Connect(h.ctx, p.execution.plan)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var last kubefault.Status
	start := time.Now()
	for i := 0; i < 4095; i++ {
		last, err = s.Client.Control(h.ctx, p.execution.auth, "status")
		if err != nil {
			t.Fatal("actual signed poll", i, err)
		}
	}
	h.save("K-poll-prefill", map[string]any{"actualSignedStatusRequests": 4095, "elapsedMS": time.Since(start).Milliseconds(), "lastSignedStatus": last})
	fresh := h.coordinate("K-active-at-capacity", "healthy", true)
	applied, err := s.Client.Control(h.ctx, fresh.execution.auth, "apply")
	if err != nil || !applied.Active {
		t.Fatal("status polling blocked Apply", err)
	}
	last, err = s.Client.Control(h.ctx, fresh.execution.auth, "status")
	if err != nil || !last.Active {
		t.Fatal("last active signed status", err)
	}
	h.save("K-active-last-status", last)
	if _, err = s.Client.Control(h.ctx, fresh.execution.auth, "status"); !errors.Is(err, kubefault.ErrDenied) {
		t.Fatal("status registry unbounded", err)
	}
	removed, err := s.Client.Control(h.ctx, fresh.execution.auth, "remove")
	if err != nil || removed.Active || removed.ApplyCount != 1 || removed.ExpiresAt != applied.ExpiresAt {
		t.Fatal("poll capacity denied cleanup or renewed deadline", err)
	}
	h.save("K-remove-after-status-exhaustion", removed)
	// No coordinated execution was claimed. Cleanup records explicitly identify
	// this direct protocol test instead of inventing a historical execution.
	h.command("K-fence-direct-protocol-invocation", 0, "coordinate", "cancel", "--directory", fresh.directory)
	t.Log("REAL KIND K: 4096 actual signed status requests, final request during active intervention, next poll denied; authenticated Remove succeeded with unchanged deadline and one Apply")
}
