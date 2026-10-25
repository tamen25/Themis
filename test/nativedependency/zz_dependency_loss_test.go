package nativedependency_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	adapter "github.com/tamen25/themis/internal/dependencyexperiment"
	wire "github.com/tamen25/themis/internal/dependencyhttp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Last in the opt-in suite: deliberately changes only this disposable dependency
// boot. The immutable original plan must never adopt the restarted dependency.
func TestOwnedKindLostDependencyDoesNotBecomeRecoveredTraffic(t *testing.T) {
	h := newHarness(t)
	p := h.prepare("dependency-loss", "delay", 500)
	c := h.cluster()
	conn := h.proxy()
	runner := h.runner("dependency-loss-runner", p)
	h.active(p, conn)
	target := p.plan.Binding.Target.Dependency
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	pod, e := c.API.CoreV1().Pods(c.Owner.Namespace).Get(ctx, target.Pod, metav1.GetOptions{})
	cancel()
	if e != nil || string(pod.UID) != target.Process.PodUID || len(pod.Status.ContainerStatuses) != 1 || pod.Status.ContainerStatuses[0].ContainerID != target.ContainerID {
		t.Fatal("original dependency identity drift before guarded test")
	}
	h.taskAction(c, "kill-only-owned-original-dependency-container", "kill", strings.TrimPrefix(target.ContainerID, "containerd://"))
	app, e := c.Data("application")
	if e != nil {
		t.Fatal(e)
	}
	defer app.Close()
	app.Client.Timeout = 1500 * time.Millisecond
	nonce := wire.ID()
	response, e := wire.Fetch(context.Background(), app.Client, app.Base+"/value?nonce="+nonce)
	if e != nil || !response.Verified(p.plan.Binding.Target.Application.Process, nonce, "value") || response.Code == 200 {
		t.Fatal("lost dependency did not produce genuine application disruption")
	}
	h.save("dependency-loss-actual-application.json", response)
	raw, code := h.wait(runner)
	if code == 0 {
		t.Fatal("lost dependency became PASS")
	}
	var report adapter.Report
	if json.Unmarshal(raw, &report) != nil || report.Verdict != "INCONCLUSIVE" || report.Cleanup != "COMPLETE" {
		t.Fatal("dependency loss/cleanup uncertainty conflated")
	}
	if _, code = h.wait(p.observer); code != 0 {
		t.Fatal("observer failed to retain dependency loss")
	}
	h.publish("dependency-loss", p, report)
	inactive, e := adapter.Control(context.Background(), conn, p.authorization, "status")
	if e != nil || inactive.State.Active || !inactive.State.Fenced {
		t.Fatal("actuator fault remained active despite original cleanup")
	}
	h.save("dependency-loss-inactive-proxy-is-not-recovery.json", inactive)
	t.Log("REAL KIND dependency process terminated: original proxy injection stopped and cleanup confirmed, but actual application dependency traffic remained unavailable and verdict stayed INCONCLUSIVE")
}
