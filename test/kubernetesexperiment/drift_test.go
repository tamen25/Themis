package kubernetesexperiment_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/kube"
	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/localstate"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (h *harness) guard(admin client.Client) {
	h.t.Helper()
	var owner struct {
		Version          string   `json:"version"`
		ClusterName      string   `json:"clusterName"`
		Context          string   `json:"context"`
		ClusterUID       string   `json:"clusterUID"`
		NamespaceUID     string   `json:"namespaceUID"`
		PreviousClusters []string `json:"previousClusters"`
	}
	if localstate.Read(filepath.Join(h.state, "bootstrap-owner.json"), &owner) != nil || owner.Version != "themis.kind-bootstrap/t2.1-v1" || owner.ClusterName != "themis-t21" || owner.Context != "kind-themis-t21" || owner.ClusterUID != h.cluster.Owner.ClusterUID || owner.NamespaceUID != h.cluster.Owner.NamespaceUID {
		h.t.Fatal("fresh trusted installer ownership required")
	}
	for name, uid := range map[string]string{"kube-system": owner.ClusterUID, "themis-test": owner.NamespaceUID} {
		ns := &corev1.Namespace{}
		if admin.Get(h.ctx, client.ObjectKey{Name: name}, ns) != nil || string(ns.UID) != uid {
			h.t.Fatal("owned cluster/namespace UID differs; no mutation authorized")
		}
	}
	dep := &appsv1.Deployment{}
	if admin.Get(h.ctx, client.ObjectKey{Namespace: "themis-test", Name: "latency-fixture"}, dep) != nil || string(dep.UID) != h.cluster.Owner.DeploymentUID || dep.Labels["verification.themis.dev/synthetic"] != "true" {
		h.t.Fatal("owned synthetic workload differs; no mutation authorized")
	}
}

func (h *harness) admin() client.Client {
	h.t.Helper()
	path := filepath.Join(h.state, "admin-kubeconfig")
	if err := localstate.Check(path); err != nil {
		h.t.Fatal(err)
	}
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(&clientcmd.ClientConfigLoadingRules{ExplicitPath: path}, &clientcmd.ConfigOverrides{CurrentContext: "kind-themis-t21"}).ClientConfig()
	if err != nil {
		h.t.Fatal(err)
	}
	config.Timeout = 4 * time.Second
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	c, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		h.t.Fatal(err)
	}
	h.guard(c)
	return c
}

func (h *harness) waitReady(admin client.Client, oldUID, oldContainer string) *corev1.Pod {
	h.t.Helper()
	for start := time.Now(); time.Since(start) < 90*time.Second; {
		pods := &corev1.PodList{}
		if admin.List(h.ctx, pods, client.InNamespace("themis-test"), client.MatchingLabels{"app": "themis-latency-fixture"}) == nil && len(pods.Items) == 1 {
			p := pods.Items[0]
			if p.DeletionTimestamp.IsZero() && (oldUID == "" || string(p.UID) != oldUID) && len(p.Status.ContainerStatuses) == 1 {
				c := p.Status.ContainerStatuses[0]
				if c.Ready && c.State.Running != nil && (oldContainer == "" || c.ContainerID != oldContainer) {
					return &p
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	h.t.Fatal("owned synthetic fixture did not return to a known ready state")
	return nil
}

func (h *harness) resetRequest(admin client.Client) {
	h.t.Helper()
	h.guard(admin)
	dep := &appsv1.Deployment{}
	if err := admin.Get(h.ctx, client.ObjectKey{Namespace: "themis-test", Name: "latency-fixture"}, dep); err != nil {
		h.t.Fatal(err)
	}
	old := kube.RunObject()
	key := client.ObjectKey{Namespace: "themis-test", Name: "latency-request"}
	if err := admin.Get(h.ctx, key, old); err != nil {
		h.t.Fatal(err)
	}
	fresh := kube.RunObject()
	fresh.SetName(key.Name)
	fresh.SetNamespace(key.Namespace)
	fresh.Object["spec"] = runtime.DeepCopyJSONValue(old.Object["spec"])
	fresh.Object["spec"].(map[string]any)["target"].(map[string]any)["generation"] = dep.Generation
	uid := old.GetUID()
	if err := admin.Delete(h.ctx, old, client.Preconditions{UID: &uid}); err != nil {
		h.t.Fatal(err)
	}
	for start := time.Now(); ; {
		err := admin.Get(h.ctx, key, kube.RunObject())
		if apierrors.IsNotFound(err) {
			break
		}
		if time.Since(start) > 10*time.Second {
			h.t.Fatal("old preview not deleted")
		}
		time.Sleep(50 * time.Millisecond)
	}
	h.guard(admin)
	if err := admin.Create(h.ctx, fresh); err != nil {
		h.t.Fatal(err)
	}
	for start := time.Now(); time.Since(start) < 20*time.Second; {
		if _, err := h.cluster.Plan(h.ctx, "latency-request", "healthy"); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	h.t.Fatal("fresh preview did not become valid")
}

func (h *harness) exactForwardRole(admin client.Client, pod *corev1.Pod) {
	h.t.Helper()
	h.guard(admin)
	owner := metav1.GetControllerOf(pod)
	if owner == nil || owner.Kind != "ReplicaSet" {
		h.t.Fatal("new fixture owner unavailable")
	}
	role := &rbacv1.Role{}
	if err := admin.Get(h.ctx, client.ObjectKey{Namespace: "themis-test", Name: "themis-runner"}, role); err != nil {
		h.t.Fatal(err)
	}
	for i := range role.Rules {
		rule := &role.Rules[i]
		for _, resource := range rule.Resources {
			if resource == "pods/portforward" {
				rule.ResourceNames = []string{pod.Name}
			}
			if resource == "replicasets" {
				rule.ResourceNames = []string{owner.Name}
			}
		}
	}
	if err := admin.Update(h.ctx, role); err != nil {
		h.t.Fatal(err)
	}
	h.save("installer-restored-exact-pod-rbac", role)
}

func (h *harness) tool(label, program string, args ...string) []byte {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(h.ctx, 30*time.Second)
	defer cancel()
	executable, arguments := program, args
	if proxy := os.Getenv("THEMIS_TEST_COMMAND_PROXY"); proxy != "" {
		executable = proxy
		arguments = append([]string{"proxy", program}, args...)
	}
	cmd := exec.CommandContext(ctx, executable, arguments...)
	cmd.Dir = h.repository
	var diagnostics bytes.Buffer
	cmd.Stderr = &diagnostics
	output, err := cmd.Output()
	h.commands = append(h.commands, map[string]any{"label": label, "program": program, "arguments": args, "exitCode": exitCode(err), "stdout": string(output), "stderr": diagnostics.String()})
	if err != nil {
		h.t.Fatal(label, err, diagnostics.String())
	}
	return output
}

func (h *harness) nodeGuard(admin client.Client) {
	h.guard(admin)
	label := h.tool("owned-kind-node-label", "docker", "inspect", "--format", `{{index .Config.Labels "io.x-k8s.kind.cluster"}}`, "themis-t21-control-plane")
	if strings.TrimSpace(string(label)) != "themis-t21" {
		h.t.Fatal("node is not in the owned Kind cluster")
	}
}

func TestOwnedKindLiveTargetDrift(t *testing.T) {
	h := lifecycleHarness(t)
	admin := h.admin()
	// Changing paused increments generation without replacing the current Pod.
	p := h.prepare("live-generation-change", "healthy")
	s, err := h.cluster.Connect(h.ctx, p.plan)
	if err != nil {
		t.Fatal(err)
	}
	dep := &appsv1.Deployment{}
	_ = admin.Get(h.ctx, client.ObjectKey{Namespace: "themis-test", Name: "latency-fixture"}, dep)
	h.guard(admin)
	dep.Spec.Paused = true
	if err = admin.Update(h.ctx, dep); err != nil {
		t.Fatal(err)
	}
	h.command("generation-drift-rejected-before-Apply", 5, "run", "--state", h.state, "-f", p.planFile, "--authorization", p.authFile, "--runs", p.root)
	status, err := s.Client.Control(h.ctx, p.auth, "status")
	s.Close()
	if err != nil || status.Applied || status.ApplyCount != 0 {
		t.Fatal("generation drift applied a fault", err)
	}
	h.save("generation-drift-zero-Apply", status)
	h.guard(admin)
	_ = admin.Get(h.ctx, client.ObjectKeyFromObject(dep), dep)
	dep.Spec.Paused = false
	if err = admin.Update(h.ctx, dep); err != nil {
		t.Fatal(err)
	}
	h.waitReady(admin, "", "")
	h.resetRequest(admin)
	// Actual Pod replacement, restricted to this UID-verified synthetic fixture.
	p = h.prepare("live-pod-replacement", "healthy")
	pod := &corev1.Pod{}
	if err = admin.Get(h.ctx, client.ObjectKey{Namespace: "themis-test", Name: p.plan.Target.Fixture.PodName}, pod); err != nil {
		t.Fatal(err)
	}
	h.guard(admin)
	uid := types.UID(p.plan.Target.Fixture.PodUID)
	if pod.UID != uid {
		t.Fatal("original fixture already replaced")
	}
	if err = admin.Delete(h.ctx, pod, client.Preconditions{UID: &uid}); err != nil {
		t.Fatal(err)
	}
	replacement := h.waitReady(admin, string(uid), "")
	h.exactForwardRole(admin, replacement)
	h.command("replaced-Pod-run-denied", 5, "run", "--state", h.state, "-f", p.planFile, "--authorization", p.authFile, "--runs", p.root)
	h.resetRequest(admin)
	current := h.prepare("replacement-zero-Apply", "healthy")
	s, err = h.cluster.Connect(h.ctx, current.plan)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Client.Control(h.ctx, p.auth, "apply")
	if !errors.Is(err, kubefault.ErrDenied) {
		t.Fatal("old grant applied to replacement fixture", err)
	}
	status, err = s.Client.Control(h.ctx, current.auth, "status")
	s.Close()
	if err != nil || status.Active || status.Applied || status.ApplyCount != 0 {
		t.Fatal("replacement target was faulted", err)
	}
	h.save("replacement-current-plan", current.plan)
	h.save("replacement-old-grant-denied-zero-Apply", status)
	// Restart the actual owned container, retaining the Pod UID.
	p = h.prepare("live-container-restart", "healthy")
	h.nodeGuard(admin)
	container := strings.TrimPrefix(p.plan.Target.ContainerID, "containerd://")
	if len(container) != 64 {
		t.Fatal("unexpected container runtime identity")
	}
	h.tool("owned-synthetic-container-restart", "docker", "exec", "themis-t21-control-plane", "crictl", "stop", container)
	restarted := h.waitReady(admin, "", p.plan.Target.ContainerID)
	if string(restarted.UID) != p.plan.Target.Fixture.PodUID {
		t.Fatal("container restart unexpectedly replaced Pod")
	}
	h.command("restarted-container-run-denied", 5, "run", "--state", h.state, "-f", p.planFile, "--authorization", p.authFile, "--runs", p.root)
	h.resetRequest(admin)
	current = h.prepare("restarted-boot-zero-Apply", "healthy")
	if current.plan.Target.Fixture.InstanceID == p.plan.Target.Fixture.InstanceID || current.plan.Target.Fixture.EvidenceKey == p.plan.Target.Fixture.EvidenceKey {
		t.Fatal("boot identity was reused")
	}
	s, err = h.cluster.Connect(h.ctx, current.plan)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Client.Control(h.ctx, p.auth, "apply")
	if !errors.Is(err, kubefault.ErrDenied) {
		t.Fatal("old grant accepted after container restart", err)
	}
	status, err = s.Client.Control(h.ctx, current.auth, "status")
	s.Close()
	if err != nil || status.Applied || status.Active {
		t.Fatal("restarted boot was faulted", err)
	}
	h.save("restarted-container-new-plan", current.plan)
	h.save("restarted-boot-old-grant-zero-Apply", status)
	// Full run proves the restored fixture is usable, rather than relying on Pod readiness.
	h.command("restored-fixture-actual-PASS", 0, "run", "--state", h.state, "-f", current.planFile, "--authorization", current.authFile, "--runs", current.root)
	h.copy("restored-fixture-events.jsonl", filepath.Join(current.runDir, "events.jsonl"))
	t.Log("REAL KIND generation drift, Pod replacement and container/boot restart rejected old plans/grants; replacement fixtures had zero Apply; restored app passed actual measured run")
}

func TestOwnedKindAPIUnavailableDuringCancellation(t *testing.T) {
	h := lifecycleHarness(t)
	admin := h.admin()
	p := h.prepare("api-unavailable-cleanup", "healthy")
	h.nodeGuard(admin)
	listing := h.tool("owned-apiserver-container", "docker", "exec", "themis-t21-control-plane", "crictl", "ps", "--name", "kube-apiserver", "-o", "json")
	var data struct {
		Containers []struct {
			ID     string            `json:"id"`
			Labels map[string]string `json:"labels"`
		} `json:"containers"`
	}
	if json.Unmarshal(listing, &data) != nil || len(data.Containers) != 1 || data.Containers[0].Labels["io.kubernetes.pod.namespace"] != "kube-system" {
		t.Fatal("exact owned API container unavailable")
	}
	id := data.Containers[0].ID
	runner := h.start(p)
	events := h.await(p, "APPLIED")
	h.save("api-failure-Apply-known", events[len(events)-1])
	h.nodeGuard(admin)
	h.tool("pause-only-owned-api-task", "docker", "exec", "themis-t21-control-plane", "ctr", "-n", "k8s.io", "tasks", "pause", id)
	resumed := false
	defer func() {
		if !resumed {
			h.tool("restore-owned-api-after-test-failure", "docker", "exec", "themis-t21-control-plane", "ctr", "-n", "k8s.io", "tasks", "resume", id)
		}
	}()
	h.command("cancel-with-api-unavailable", 7, "cancel", "--run-directory", p.runDir)
	h.tool("resume-only-owned-api-task", "docker", "exec", "themis-t21-control-plane", "ctr", "-n", "k8s.io", "tasks", "resume", id)
	resumed = true
	_, report := h.finish("runner-during-api-outage", runner)
	if report.Verdict == "PASS" {
		t.Fatal("API outage/cancellation produced PASS")
	}
	h.command("cleanup-after-api-restored", 0, "reconcile", "--run-directory", p.runDir)
	inspection, err := h.cluster.Inspect(h.ctx, p.runDir)
	if err != nil || inspection.Current.ResidualIntervention != "ABSENT" || inspection.Current.PriorCleanupReceipt == nil || !inspection.Current.PriorCleanupReceipt.RecoveryVerified {
		t.Fatal("cleanup/recovery after API restoration unproven", err)
	}
	h.save("api-restored-current-and-history", inspection)
	h.copy("api-outage-original-events.jsonl", filepath.Join(p.runDir, "events.jsonl"))
	t.Log("REAL KIND only owned API task paused; cancellation durably accepted with exit 7, fixture expiry independent; API restored and exact-target cleanup/recovery verified")
}
