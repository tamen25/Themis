package liveobservation_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/kubeexperiment"
	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/livewitness"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/pkg/evidence"
	obs "github.com/tamen25/themis/pkg/liveobservation"
)

type child struct {
	cmd            *exec.Cmd
	stdout, stderr bytes.Buffer
	start          time.Time
	waited         bool
}

func (h *harness) startChild(binary string, args ...string) *child {
	h.t.Helper()
	c := &child{start: time.Now()}
	c.cmd = exec.CommandContext(h.ctx, binary, args...)
	c.cmd.Dir = h.repository
	c.cmd.Stdout = &c.stdout
	c.cmd.Stderr = &c.stderr
	if e := c.cmd.Start(); e != nil {
		h.t.Fatal(e)
	}
	h.t.Cleanup(func() {
		if !c.waited {
			_ = c.cmd.Process.Kill()
			_ = c.cmd.Wait()
		}
	})
	return c
}
func (h *harness) finishChild(label string, c *child) int {
	h.t.Helper()
	e := c.cmd.Wait()
	c.waited = true
	code := exitCode(e)
	h.commands = append(h.commands, command{label, c.cmd.Path, c.cmd.Args[1:], code, c.stdout.String(), c.stderr.String(), time.Since(c.start).Milliseconds()})
	return code
}
func (h *harness) tool(label, program string, args ...string) []byte {
	h.t.Helper()
	c := h.startChild(program, args...)
	if code := h.finishChild(label, c); code != 0 {
		h.t.Fatalf("installer tool %s exit %d: %s", label, code, c.stderr.String())
	}
	return c.stdout.Bytes()
}
func (h *harness) admin(label string, args ...string) []byte {
	h.t.Helper()
	var owner kubeexperiment.Ownership
	if localstate.Read(filepath.Join(h.state, "execution-owner.json"), &owner) != nil || !strings.HasPrefix(owner.ClusterName, "themis-t41-") {
		h.t.Fatal("owned new cluster required")
	}
	base := []string{"--kubeconfig", filepath.Join(h.state, "admin-kubeconfig"), "--context", owner.Context}
	return h.tool(label, "kubectl", append(base, args...)...)
}
func (h *harness) guardOwnedNode() kubeexperiment.Ownership {
	h.t.Helper()
	var owner kubeexperiment.Ownership
	if localstate.Read(filepath.Join(h.state, "execution-owner.json"), &owner) != nil {
		h.t.Fatal("owner")
	}
	cluster, e := kubeexperiment.Open(h.ctx, h.state)
	if e != nil || cluster.CheckEnvironment(h.ctx) != nil {
		h.t.Fatal("original UID ownership unavailable", e)
	}
	raw := h.tool("original-owned-node-check", "docker", "inspect", "--format", `{{.Id}} {{index .Config.Labels "io.x-k8s.kind.cluster"}}`, owner.ClusterName+"-control-plane")
	fields := strings.Fields(string(raw))
	if len(fields) != 2 || fields[1] != owner.ClusterName || len(fields[0]) != 64 {
		h.t.Fatal("exact owned node identity missing")
	}
	h.save("owned-node-identity.json", struct {
		Cluster string `json:"cluster"`
		NodeID  string `json:"nodeId"`
	}{owner.ClusterName, fields[0]})
	return owner
}

func (h *harness) prepareLifecycle(label string) (string, string, obs.Registration, *child) {
	h.t.Helper()
	dir := filepath.Join(h.state, "witness-"+label+"-"+localstate.RandomID()[:12])
	record, e := kubeexperiment.DecodeCoordinationRecord(h.call(label+"-prepare", 0, "coordinate", "prepare", "--state", h.state, "--directory", dir))
	if e != nil {
		h.t.Fatal(e)
	}
	record, e = kubeexperiment.DecodeCoordinationRecord(h.call(label+"-approve", 0, "coordinate", "approve", "--directory", dir, "--approve-digest", record.Proposal.PlanDigest))
	if e != nil {
		h.t.Fatal(e)
	}
	var auth kubefault.Authorization
	if localstate.Read(filepath.Join(dir, "authorization.json"), &auth) != nil {
		h.t.Fatal("private operator approval")
	}
	runnerKey, _ := hex.DecodeString(auth.Grant.InvocationKey)
	cleanupKey, _ := hex.DecodeString(auth.Grant.CleanupKey)
	session := filepath.Join(h.private, label)
	r, e := livewitness.Register(record, h.keyDir, session, record.Proposal.PlanDigest, evidence.Hash(runnerKey), evidence.Hash(cleanupKey), 150, time.Now())
	if e != nil {
		h.t.Fatal(e)
	}
	h.save(label+"-registration.json", r)
	child := h.startChild(h.witness, "observe", "--state", h.witnessState, "--session", session, "--key-dir", h.keyDir)
	ready := false
	for until := time.Now().Add(6 * time.Second); time.Now().Before(until); time.Sleep(10 * time.Millisecond) {
		var start obs.Record
		if localstate.Read(filepath.Join(session, "ready.json"), &start) == nil && obs.VerifyRecord(start, r.PublicKey) && start.RegistrationDigest == obs.RegistrationDigest(r) {
			ready = true
			break
		}
	}
	if !ready {
		_ = child.cmd.Process.Kill()
		h.finishChild(label+"-witness-not-ready", child)
		h.t.Fatal("witness registration readiness unavailable", child.stdout.String())
	}
	return dir, session, r, child
}
func (h *harness) awaitApplied(dir, invocation string) {
	h.t.Helper()
	path := filepath.Join(dir, "runs", "run-"+invocation, "events.jsonl")
	for until := time.Now().Add(5 * time.Second); time.Now().Before(until); time.Sleep(5 * time.Millisecond) {
		events, e := kubeexperiment.ReadJournal(path)
		if e == nil {
			for _, event := range events {
				if event.Type == "APPLIED" {
					h.save("actual-application-before-interruption.json", event)
					return
				}
			}
		}
	}
	h.t.Fatal("actual runner never applied approved intervention")
}
func (h *harness) saveLifecycle(label, dir, session string, r obs.Registration) {
	h.t.Helper()
	journal, e := os.ReadFile(filepath.Join(session, "observations.jsonl"))
	if e != nil {
		h.t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(h.output, label+"-witness.jsonl"), journal, 0600); e != nil {
		h.t.Fatal(e)
	}
	events, e := os.ReadFile(filepath.Join(dir, "runs", "run-"+r.InvocationID, "events.jsonl"))
	if e != nil {
		h.t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(h.output, label+"-runner.jsonl"), events, 0600); e != nil {
		h.t.Fatal(e)
	}
	f, _ := obs.Analyze(r, journal, nil, time.Now())
	h.save(label+"-finding-untrusted-without-policy.json", f)
	h.call(label+"-independent-reconcile", 0, "coordinate", "reconcile", "--directory", dir)
	after, _ := os.ReadFile(filepath.Join(dir, "runs", "run-"+r.InvocationID, "events.jsonl"))
	if !bytes.Equal(events, after) {
		h.t.Fatal("reconcile rewrote historical execution")
	}
}

func TestOwnedKindRunnerDeathDoesNotStopWitnessOrExpiry(t *testing.T) {
	h := newHarness(t)
	dir, session, reg, witness := h.prepareLifecycle("G-runner-death")
	runner := h.startChild(h.runner, "coordinate", "start", "--directory", dir)
	h.awaitApplied(dir, reg.InvocationID)
	if e := runner.cmd.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	if h.finishChild("G-actual-runner-death", runner) == 0 {
		t.Fatal("runner did not die")
	}
	code := h.finishChild("G-witness-observed-independent-expiry", witness)
	if code != 0 && code != 8 {
		t.Fatal("witness failed after runner death", witness.stdout.String())
	}
	h.saveLifecycle("G-runner-death", dir, session, reg)
	t.Log("REAL KIND runner process killed after Apply; witness continued, fixture expired independently, exact original cleanup reconciled without rewriting history")
}

func TestOwnedKindControllerRestartDoesNotSupplyObservationAuthority(t *testing.T) {
	h := newHarness(t)
	h.guardOwnedNode()
	before := h.admin("H-controller-before", "get", "pods", "-n", "themis-test", "-l", "app=themis-controller", "-o", "json")
	dir, session, reg, witness := h.prepareLifecycle("H-controller-restart")
	h.admin("H-restart-only-owned-controller", "rollout", "restart", "deployment/themis-controller", "-n", "themis-test")
	h.call("H-original-runner", 0, "coordinate", "start", "--directory", dir)
	if code := h.finishChild("H-independent-witness", witness); code != 0 {
		t.Fatal("witness lost observations during controller restart", code, witness.stdout.String())
	}
	h.admin("H-controller-restored", "rollout", "status", "deployment/themis-controller", "-n", "themis-test", "--timeout=90s")
	after := h.admin("H-controller-after", "get", "pods", "-n", "themis-test", "-l", "app=themis-controller", "-o", "json")
	h.save("H-controller-rollout-observed.json", struct {
		Before json.RawMessage `json:"before"`
		After  json.RawMessage `json:"after"`
	}{before, after})
	h.saveLifecycle("H-controller-restart", dir, session, reg)
	t.Log("REAL KIND owned controller restarted while independent witness was live; runner and witness measured application and cleanup remained operational")
}

func TestOwnedKindAPIOutageKeepsWitnessEvidenceIncomplete(t *testing.T) {
	h := newHarness(t)
	owner := h.guardOwnedNode()
	node := owner.ClusterName + "-control-plane"
	var listing struct {
		Containers []struct {
			ID     string            `json:"id"`
			Labels map[string]string `json:"labels"`
		} `json:"containers"`
	}
	if json.Unmarshal(h.tool("I-owned-api-container", "docker", "exec", node, "crictl", "ps", "--name", "kube-apiserver", "-o", "json"), &listing) != nil || len(listing.Containers) != 1 || listing.Containers[0].Labels["io.kubernetes.pod.namespace"] != "kube-system" {
		t.Fatal("owned API task unavailable")
	}
	id := listing.Containers[0].ID
	dir, session, reg, witness := h.prepareLifecycle("I-api-outage")
	runner := h.startChild(h.runner, "coordinate", "start", "--directory", dir)
	h.awaitApplied(dir, reg.InvocationID)
	h.tool("I-pause-only-owned-api", "docker", "exec", node, "ctr", "-n", "k8s.io", "tasks", "pause", id)
	resumed := false
	defer func() {
		if !resumed {
			h.tool("I-emergency-resume-owned-api", "docker", "exec", node, "ctr", "-n", "k8s.io", "tasks", "resume", id)
		}
	}()
	h.call("I-cancel-during-api-outage", 7, "coordinate", "cancel", "--directory", dir)
	h.tool("I-resume-only-owned-api", "docker", "exec", node, "ctr", "-n", "k8s.io", "tasks", "resume", id)
	resumed = true
	if h.finishChild("I-runner-after-api-outage", runner) == 0 {
		t.Fatal("cancelled API-outage runner reported PASS")
	}
	if code := h.finishChild("I-witness-api-interruption", witness); code != 8 {
		t.Fatal("API outage did not preserve incomplete witness", code, witness.stdout.String())
	}
	h.saveLifecycle("I-api-outage", dir, session, reg)
	t.Log("REAL KIND only the new owned API task paused; witness identity checks failed closed, cleanup uncertainty persisted, API restored and original resources reconciled")
}
