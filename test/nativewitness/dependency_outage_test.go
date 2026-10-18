package nativewitness_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	adapter "github.com/tamen25/themis/internal/dependencyexperiment"
	wire "github.com/tamen25/themis/internal/dependencyhttp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (h *harness) waitReplacement(conn *adapter.Connection, original wire.Process) wire.Reply {
	h.t.Helper()
	for start := time.Now(); time.Since(start) < 40*time.Second; {
		nonce := wire.ID()
		r, err := wire.Fetch(context.Background(), conn.Client, conn.Base+"/identity?nonce="+nonce)
		if err == nil && r.Identity.Boot != original.Boot && r.Identity.Key != original.Key && r.Verified(r.Identity, nonce, "identity") {
			return r
		}
		time.Sleep(100 * time.Millisecond)
	}
	h.t.Fatal("exact owned replacement failed to establish a new boot and key")
	return wire.Reply{}
}

func (h *harness) killOriginalTask(c *adapter.Cluster, label string, original wire.Workload) {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pod, err := c.API.CoreV1().Pods(c.Owner.Namespace).Get(ctx, original.Pod, metav1.GetOptions{})
	if err != nil || string(pod.UID) != original.Process.PodUID || len(pod.Status.ContainerStatuses) != 1 || pod.Status.ContainerStatuses[0].ContainerID != original.ContainerID {
		h.t.Fatal("exact original Pod UID and container identity required", err)
	}
	h.save(label+"-original-identity.json", original)
	h.taskAction(c, label, "kill", strings.TrimPrefix(original.ContainerID, "containerd://"))
}

func TestOwnedKindSignedWitnessActualDependencyOutage(t *testing.T) {
	h := newHarness(t)
	p := h.prepare("dependency-outage", "delay", 500)
	c, conn := h.cluster(), h.proxy()
	runner := h.runner("dependency-outage-runner", p)
	first := h.active(p, conn)
	h.effect(p, 3)
	h.killOriginalTask(c, "kill-only-original-owned-dependency", p.plan.Binding.Target.Dependency)
	raw, code := h.wait(runner)
	var report adapter.Report
	if code == 0 || json.Unmarshal(raw, &report) != nil || report.Verdict == "PASS" {
		t.Fatal("unavailable dependency became source success", code)
	}
	_, _ = h.wait(p.observer)
	_, _ = h.wait(p.witness)
	result, _ := h.publish("dependency-outage", p, "", 8)
	if result.NativeObservationCorroboration.ApplicationVerdict == "PASS" || result.NativeObservationCorroboration.Recovery != 0 {
		t.Fatal("expired fault was mistaken for successful application recovery", result)
	}
	state, err := adapter.Control(context.Background(), conn, p.authorization, "status")
	if err != nil || state.State.Active || state.State.ApplyCount != 1 || state.State.DeadlineNS != first.State.DeadlineNS {
		t.Fatal("dependency outage changed independent original expiry", err)
	}
	h.save("dependency-outage-original-expiry.json", state)
	// A restarted dependency has a new key. Restore this disposable fixture with
	// an explicit new proxy boot and installer rebind, never adoption by the old
	// run. The retained history above stays unchanged.
	h.killOriginalTask(c, "restore-by-restarting-only-original-proxy", p.plan.Binding.Target.Proxy)
	h.save("restoration-new-proxy-identity.json", h.waitReplacement(conn, p.plan.Binding.Target.Proxy.Process))
	h.external("explicit-owned-restoration-rebind", "powershell", 0, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", filepath.Join(h.repo, "scripts", "kind-native-witness.ps1"), "-Action", "refresh", "-ClusterName", c.Owner.ClusterName, "-CommandProxy", "rtk")
	t.Log("REAL KIND original dependency task killed; independent expiry held, signed unavailable application traffic produced no recovery PASS; later explicit owned rebind was a separate current-state restoration")
}

func TestOwnedKindProxyReplacementAfterReadyBeforeApply(t *testing.T) {
	h := newHarness(t)
	p := h.prepare("ready-proxy-replacement", "delay", 500)
	c, conn := h.cluster(), h.proxy()
	h.killOriginalTask(c, "kill-original-proxy-after-signed-ready", p.plan.Binding.Target.Proxy)
	replacement := h.waitReplacement(conn, p.plan.Binding.Target.Proxy.Process)
	h.save("pre-Apply-replacement-identity.json", replacement)
	_, code := h.wait(h.runner("old-ready-runner-denied", p))
	if code == 0 {
		t.Fatal("old READY admitted a replacement proxy")
	}
	cmd := wire.NewCommand("apply", p.authorization, time.Now())
	reply, _ := adapter.Post(context.Background(), conn, "/control", cmd, cmd.Nonce, replacement.Identity)
	if reply.Code != 403 || !reply.Verified(replacement.Identity, cmd.Nonce, "control") || reply.State.Applied {
		t.Fatal("replacement inherited old otherwise authentic authority")
	}
	h.save("pre-Apply-old-authority-denied.json", reply)
	_, _ = h.wait(p.observer)
	_, _ = h.wait(p.witness)
	h.external("explicit-owned-pre-Apply-rebind", "powershell", 0, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", filepath.Join(h.repo, "scripts", "kind-native-witness.ps1"), "-Action", "refresh", "-ClusterName", c.Owner.ClusterName, "-CommandProxy", "rtk")
	t.Logf("REAL KIND proxy replaced after signed READY before Apply; old runner exit=%d; new boot signed denial and did not inherit invocation", code)
}
