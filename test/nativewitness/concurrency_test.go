package nativewitness_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	adapter "github.com/tamen25/themis/internal/dependencyexperiment"
	wire "github.com/tamen25/themis/internal/dependencyhttp"
	"github.com/tamen25/themis/internal/localstate"
	witness "github.com/tamen25/themis/internal/nativewitness"
	obs "github.com/tamen25/themis/pkg/nativeobservation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (h *harness) managerTask(c *adapter.Cluster) string {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pods, err := c.API.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{LabelSelector: "component=kube-controller-manager"})
	if err != nil || len(pods.Items) != 1 || pods.Items[0].Spec.NodeName != c.Owner.ClusterName+"-control-plane" || len(pods.Items[0].Status.ContainerStatuses) != 1 {
		h.t.Fatal("exact newly owned controller-manager task unavailable", err)
	}
	task := strings.TrimPrefix(pods.Items[0].Status.ContainerStatuses[0].ContainerID, "containerd://")
	if len(task) != 64 {
		h.t.Fatal("controller-manager task identity missing")
	}
	h.save("original-controller-manager.json", struct{ Pod, UID, Task string }{pods.Items[0].Name, string(pods.Items[0].UID), task})
	return task
}

func TestOwnedKindConcurrentStartsPollingAndPublication(t *testing.T) {
	h := newHarness(t)
	p := h.prepare("concurrent", "delay", 500)
	conn := h.proxy()
	firstRunner := h.runner("concurrent-runner-one", p)
	secondRunner := h.runner("concurrent-runner-two", p)
	first := h.active(p, conn)
	// Export while both the actual witness and original runner are appending.
	export := filepath.Join(h.public, "live-prefix-export")
	child := h.start("export-while-real-journals-append", "themis-evidence", "export", "--engine", obs.Engine, "--state", p.directory, "--witness-session", p.session, "--out", export)
	exported, exportExit := h.wait(child)
	if exportExit != 0 && exportExit != 6 {
		t.Fatal("concurrent export did not fail conservatively", exportExit)
	}
	if exportExit == 0 {
		var description struct {
			Source struct{ CandidateVerdict string } `json:"source"`
		}
		if json.Unmarshal(exported, &description) != nil || description.Source.CandidateVerdict != "INCONCLUSIVE" {
			t.Fatal("unfinished real execution was exported as candidate success")
		}
	}
	h.effect(p, 3)
	duplicate, err := adapter.Control(context.Background(), conn, p.authorization, "apply")
	if err != nil || duplicate.State.DeadlineNS != first.State.DeadlineNS || duplicate.State.ApplyCount != 1 {
		t.Fatal("duplicate Apply changed original epoch", err)
	}
	h.save("actual-duplicate-Apply.json", duplicate)
	var polls []wire.Reply
	for range 1000 {
		r, err := adapter.Control(context.Background(), conn, p.authorization, "status")
		if err != nil || r.State.DeadlineNS != first.State.DeadlineNS || r.State.ApplyCount != 1 {
			t.Fatal("actual status polling renewed or lost invocation", len(polls), err)
		}
		polls = append(polls, r)
	}
	h.save("actual-1000-signed-status-responses.json", polls)
	_, firstExit := h.wait(firstRunner)
	_, secondExit := h.wait(secondRunner)
	if !((firstExit == 0 && secondExit == 5) || (firstExit == 5 && secondExit == 0)) {
		t.Fatal("concurrent admission did not consume exactly one runner", firstExit, secondExit)
	}
	_, _ = h.wait(p.observer)
	_, _ = h.wait(p.witness)
	result, _ := h.publish("concurrent", p, "", 0)
	if result.Evidence.Source.CandidateVerdict != "PASS" || result.NativeObservationCorroboration.ApplicationVerdict != "PASS" {
		t.Fatal("original measured outcome changed", result)
	}
	// Two independent publisher processes contend for one final path. Exactly one
	// may publish complete bytes; the loser must not replace or truncate them.
	final := filepath.Join(h.public, "contended-final.zip")
	args := []string{"bundle", "--engine", obs.Engine, "--source", filepath.Join(h.public, "concurrent-export"), "--out", final, "--key-dir", h.publisherDir, "--publisher", h.publisher.Name}
	one, two := h.start("publisher-one", "themis-evidence", args...), h.start("publisher-two", "themis-evidence", args...)
	_, a := h.wait(one)
	_, b := h.wait(two)
	if !((a == 0 && b == 3) || (a == 3 && b == 0)) {
		t.Fatal("exclusive final archive contention", a, b)
	}
	h.call("verify-contended-complete-archive", "themis-evidence", 0, "verify", "--bundle", final, "--trust-policy", h.publisherPolicy, "--witness-policy", p.policy)
	t.Log("REAL KIND two concurrent runners consumed one invocation; 1000 signed status reads and duplicate Apply retained deadline; real append/export remained incomplete; two publishers exposed exactly one complete archive")
}

func TestOwnedKindRunnerDeathBeforeApplyAndConcurrentInspection(t *testing.T) {
	h := newHarness(t)
	p := h.prepare("before-apply-death", "delay", 500)
	lock, err := localstate.OpenLock(filepath.Join(p.directory, "lifecycle.lock"), true)
	if err != nil || lock.Acquire(context.Background()) != nil {
		t.Fatal("test could not hold actual pre-Apply gate", err)
	}
	defer lock.Close()
	runner := h.runner("before-apply-actual-runner", p)
	h.ready(filepath.Join(p.directory, "runner-intent.json"))
	h.runnerEvent(p, "CLAIMED")
	policyBytes, _ := os.ReadFile(p.policy)
	policy, err := obs.ReadPolicy(policyBytes)
	if err != nil {
		t.Fatal(err)
	}
	var inspections []obs.Finding
	for range 8 {
		finding, err := witness.Inspect(p.session, &policy, h.publisher, time.Now())
		if err != nil || finding.TrustedExecutionVerdict != "INCONCLUSIVE" {
			t.Fatal("inspection while actual witness appended", err)
		}
		inspections = append(inspections, finding)
		time.Sleep(15 * time.Millisecond)
	}
	h.save("actual-concurrent-witness-inspections.json", inspections)
	if err := runner.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if _, code := h.wait(runner); code == 0 {
		t.Fatal("actual runner was not terminated")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	_, _ = h.wait(p.witness)
	_, _ = h.wait(p.observer)
	receipt := h.reconcile("before-apply-independent-fence", p)
	result, _ := h.publish("before-apply-death", p, receipt, 8)
	if result.Evidence.Source.Execution != "INTERRUPTED" || result.NativeObservationCorroboration.Active != 0 || result.NativeObservationCorroboration.ApplicationVerdict == "PASS" {
		t.Fatal("pre-Apply death invented an intervention or report", result)
	}
	t.Log("REAL KIND direct runner child killed while test held actual pre-Apply gate; no intervention, witness retained independent observations, original capability fenced without invented history")
}

func TestOwnedKindSignedWitnessControllerManagerRestart(t *testing.T) {
	h := newHarness(t)
	p := h.prepare("manager-restart", "delay", 500)
	c := h.cluster()
	task := h.managerTask(c)
	runner := h.runner("manager-restart-runner", p)
	first := h.active(p, h.proxy())
	h.taskAction(c, "kill-only-owned-controller-manager", "kill", task)
	if _, code := h.wait(runner); code != 0 {
		t.Fatal("native runner depended on controller-manager liveness", code)
	}
	_, _ = h.wait(p.observer)
	_, _ = h.wait(p.witness)
	result, _ := h.publish("manager-restart", p, "", 0)
	if result.Evidence.Source.CandidateVerdict != "PASS" || result.NativeObservationCorroboration.Recovery < 3 {
		t.Fatal("controller restart lost actual signed recovery")
	}
	current, err := adapter.Control(context.Background(), h.proxy(), p.authorization, "status")
	if err != nil || current.State.Active || current.State.DeadlineNS != first.State.DeadlineNS {
		t.Fatal("controller restart changed local deadline", err)
	}
	h.save("manager-independent-local-expiry.json", current)
	t.Log("REAL KIND only exact owned controller-manager task restarted; original native deadline, independently signed effect and traffic recovery preserved")
}

func TestOwnedKindLatePostFinalCancellationPreservesHistory(t *testing.T) {
	h := newHarness(t)
	p := h.prepare("post-final-cancel", "delay", 500)
	if _, code := h.wait(h.runner("post-final-original-runner", p)); code != 0 {
		t.Fatal("original run did not complete", code)
	}
	_, _ = h.wait(p.observer)
	_, _ = h.wait(p.witness)
	before, _ := os.ReadFile(filepath.Join(p.directory, "report.json"))
	journal, _ := os.ReadFile(filepath.Join(p.directory, "events.jsonl"))
	statement, _ := os.ReadFile(filepath.Join(p.directory, "runner-final.json"))
	h.call("post-final-stop-accepted", "themis-dependency", 0, "cancel", "--state", filepath.Join(h.state, "runner"), "--directory", p.directory)
	for name, original := range map[string][]byte{"report.json": before, "events.jsonl": journal, "runner-final.json": statement} {
		now, err := os.ReadFile(filepath.Join(p.directory, name))
		if err != nil || string(original) != string(now) {
			t.Fatal("post-final cancellation rewrote immutable completed history", name, err)
		}
	}
	result, _ := h.publish("post-final-cancel", p, "", 0)
	if result.Evidence.Source.CandidateVerdict != "PASS" || result.Evidence.Source.Execution != "SUCCEEDED" {
		t.Fatal("later current-state action changed completed source result")
	}
	t.Log("REAL KIND post-final cancellation kept report, journal and original runner assertion byte-identical; historical completion and later cleanup remain separate")
}
