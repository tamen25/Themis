package chaosmesh

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	api "github.com/tamen25/themis/api/kubernetes/v1alpha1"
	"github.com/tamen25/themis/internal/kube"
	"github.com/tamen25/themis/internal/result"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func fixture(t *testing.T) (*Cluster, Plan) {
	t.Helper()
	uids := []types.UID{"11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", "33333333-3333-3333-3333-333333333333", "44444444-4444-4444-4444-444444444444", "55555555-5555-5555-5555-555555555555", "66666666-6666-6666-6666-666666666666", "77777777-7777-7777-7777-777777777777"}
	cluster := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: uids[0]}}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: kube.Namespace, UID: uids[1]}}
	one, no, yes := int32(1), false, true
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "synthetic", Namespace: kube.Namespace, UID: uids[2], Generation: 1, Labels: map[string]string{api.Group + "/synthetic": "true"}}, Spec: appsv1.DeploymentSpec{Replicas: &one, Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{AutomountServiceAccountToken: &no, Containers: []corev1.Container{{Name: "echo", Image: "example.invalid/echo@sha256:" + strings.Repeat("a", 64)}}}}}, Status: appsv1.DeploymentStatus{ObservedGeneration: 1}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "synthetic-rs", Namespace: kube.Namespace, UID: uids[3], OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: dep.Name, UID: dep.UID, Controller: &yes}}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "synthetic-rs-pod", Namespace: kube.Namespace, UID: uids[4], Labels: map[string]string{"app": "themis-synthetic"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &yes}}}, Spec: *dep.Spec.Template.Spec.DeepCopy(), Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "echo", Ready: true, ContainerID: "containerd://" + strings.Repeat("b", 64), ImageID: "sha256:" + strings.Repeat("a", 64), State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
	run := kube.RunObject()
	run.SetName("external-latency-request")
	run.SetNamespace(kube.Namespace)
	run.SetUID(uids[5])
	run.SetGeneration(1)
	spec := api.RunSpec{SchemaVersion: "themis.kubernetes-run/v1alpha1", ExecutionProfile: kube.Profile, Contract: api.ContractSnapshot{SchemaVersion: "themis.kubernetes-contract/v1alpha1", Name: "external-candidate", Assertion: "DeploymentAvailable", MinReplicas: 1}, Target: api.TargetReference{APIVersion: "apps/v1", Kind: "Deployment", Namespace: kube.Namespace, Name: dep.Name, UID: dep.UID, Generation: 1}}
	run.Object["spec"], _ = runtime.DefaultUnstructuredConverter.ToUnstructured(&spec)
	policy, _ := kube.NewPolicy(kube.Namespace, cluster.UID, namespace.UID)
	compiled, code := policy.Compile(run.GetUID(), 1, spec, cluster, namespace, dep)
	if code != "" {
		t.Fatal(code)
	}
	preview := compiled.Snapshot()
	status := api.RunStatus{ObservedGeneration: 1, Phase: "PLANNED", Verdict: result.NotRun, PlanValid: true, PlanDigest: preview.Digest, Preview: &preview}
	run.Object["status"], _ = runtime.DefaultUnstructuredConverter.ToUnstructured(&status)
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, namespace, dep, rs, pod, run).Build()
	c := &Cluster{reader: reader, owner: Ownership{Version: OwnershipVersion, ClusterName: "themis-t24-0123456789ab", ClusterUID: string(uids[0]), NamespaceUID: string(uids[1]), DeploymentUID: string(uids[2]), Operator: Actor{PlannerActor, string(uids[6])}}}
	s, err := c.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p, err := Compile(s, strings.Repeat("c", 64), strings.Repeat("d", 64), time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return c, p
}

func TestPlanIsDeterministicAndCannotEnableProvider(t *testing.T) {
	_, p := fixture(t)
	copy, err := Compile(p.Document.Snapshot, p.Document.InvocationID, p.Document.ApproverPublicKey, p.Document.CreatedAt)
	if err != nil || !reflect.DeepEqual(copy, p) {
		t.Fatal("planning not deterministic", err)
	}
	data, _ := json.Marshal(p)
	if _, err = Decode(data); err != nil {
		t.Fatal(err)
	}
	s := p.Document.Snapshot
	s.Preview.Plan.Target.Images[0].Image = "changed"
	if copy.Validate() != nil {
		t.Fatal("compiled snapshot shares caller memory")
	}
	decision := Admit(copy, copy.Digest, copy.Document.CreatedAt)
	if decision.Admission != "DENIED" || decision.Verdict != result.NotRun || decision.MutationAttempted || len(decision.Reasons) < 6 {
		t.Fatal("provider safety gate opened", decision)
	}
}

func TestUpstreamLockMatchesCompiledPins(t *testing.T) {
	data, err := os.ReadFile("upstream.lock.json")
	if err != nil {
		t.Fatal(err)
	}
	var lock struct {
		Version      string   `json:"version"`
		Artifacts    Provider `json:"auditedArtifacts"`
		Enabled      bool     `json:"faultExecutionEnabled"`
		Installation string   `json:"installation"`
	}
	if json.Unmarshal(data, &lock) != nil || lock.Version != "themis.chaosmesh-upstream-lock/v1alpha1" || !reflect.DeepEqual(lock.Artifacts, PinnedProvider()) || lock.Enabled || lock.Installation != "CRD_SCHEMA_ONLY_NO_PROVIDER_WORKLOADS" {
		t.Fatal("installer research pins differ from policy")
	}
}

func TestClosedPlanAndProviderPinsRejectAlterations(t *testing.T) {
	_, original := fixture(t)
	data, _ := json.Marshal(original)
	for _, name := range []string{"provider", "API", "selector", "namespace", "kind", "delay", "duration", "device", "direction", "invocation", "approver", "window", "expiry", "enable", "UID"} {
		t.Run(name, func(t *testing.T) {
			var p Plan
			_ = json.Unmarshal(data, &p)
			d := &p.Document
			switch name {
			case "provider":
				d.Provider.Release = "latest"
			case "API":
				d.Resource.APIVersion = "chaos-mesh.org/v9"
			case "selector":
				d.Resource.Spec.Selector.Pods[kube.Namespace] = append(d.Resource.Spec.Selector.Pods[kube.Namespace], "unrelated")
			case "namespace":
				d.Resource.Metadata.Namespace = "default"
			case "kind":
				d.Resource.Kind = "PodChaos"
			case "delay":
				d.Resource.Spec.Delay.Latency = "10s"
			case "duration":
				d.Resource.Spec.Duration = "1h"
			case "device":
				d.Resource.Spec.Device = "lo"
			case "direction":
				d.Resource.Spec.Direction = "both"
			case "invocation":
				d.InvocationID = "short"
			case "approver":
				d.ApproverPublicKey = "unbound"
			case "window":
				d.StartBefore = d.StartBefore.Add(time.Second)
			case "expiry":
				d.HardStopBy = d.HardStopBy.Add(time.Second)
			case "enable":
				d.ExecutionAllowed = true
			case "UID":
				d.ResourceIdentity = "APPROVED"
			}
			// Rehash the entire malicious document: digest-only checking is not
			// the policy boundary.
			p.Digest = digest(PlanVersion, p.Document)
			if p.Validate() == nil {
				t.Fatal("altered closed candidate accepted", name)
			}
			decision := Admit(p, p.Digest, d.CreatedAt)
			if decision.Admission != "DENIED" || decision.MutationAttempted {
				t.Fatal("altered action executable")
			}
		})
	}
}

func TestFreshResolutionRejectsTargetAndRequestDrift(t *testing.T) {
	for _, name := range []string{"cluster", "namespace", "Pod UID", "container", "owner", "preview", "request"} {
		t.Run(name, func(t *testing.T) {
			c, p := fixture(t)
			ctx := context.Background()
			writer := c.reader.(client.Client)
			switch name {
			case "cluster":
				c.owner.ClusterUID = "99999999-9999-9999-9999-999999999999"
			case "namespace":
				c.owner.NamespaceUID = "99999999-9999-9999-9999-999999999999"
			case "Pod UID", "container", "owner":
				pod := &corev1.Pod{}
				_ = writer.Get(ctx, client.ObjectKey{Namespace: kube.Namespace, Name: p.Document.Snapshot.Target.PodName}, pod)
				if name == "Pod UID" {
					pod.UID = "99999999-9999-9999-9999-999999999999"
				} else if name == "container" {
					pod.Spec.Containers[0].Name = "other"
				} else {
					pod.OwnerReferences[0].UID = "99999999-9999-9999-9999-999999999999"
				}
				if err := writer.Update(ctx, pod); err != nil {
					t.Fatal(err)
				}
			case "preview", "request":
				u := kube.RunObject()
				_ = writer.Get(ctx, client.ObjectKey{Namespace: kube.Namespace, Name: "external-latency-request"}, u)
				if name == "preview" {
					u.Object["status"].(map[string]any)["preview"].(map[string]any)["digest"] = "forged"
				} else {
					u.Object["spec"].(map[string]any)["contract"].(map[string]any)["name"] = "changed"
				}
				if err := writer.Update(ctx, u); err != nil {
					t.Fatal(err)
				}
			}
			if c.Revalidate(ctx, p) == nil {
				t.Fatal("drift admitted", name)
			}
		})
	}
}

func TestOldGrantsUnknownFieldsAndProviderClaimsCannotAuthorize(t *testing.T) {
	_, p := fixture(t)
	data, _ := json.Marshal(p)
	for _, candidate := range [][]byte{[]byte(`{"version":"themis.kubernetes-authorization/v1alpha1","grant":{"planDigest":"old"}}`), append([]byte(`{"approved":true,`), data[1:]...), append([]byte(`{"digest":"duplicate",`), data[1:]...), []byte(strings.Replace(string(data), `"digest"`, `"Digest"`, 1)), []byte(strings.Replace(string(data), `"selector":{"pods"`, `"selector":{"labelSelectors":{"app":"unrelated"},"pods"`, 1)), []byte(strings.Repeat(" ", 1<<20+1))} {
		if _, err := Decode(candidate); err == nil {
			t.Fatal("unsupported grant or format accepted")
		}
	}
	for _, now := range []time.Time{p.Document.CreatedAt, p.Document.StartBefore, p.Document.CleanupBefore.Add(time.Hour)} {
		for i := 0; i < 2; i++ {
			d := Admit(p, p.Digest, now)
			if d.Admission != "DENIED" || d.Verdict != result.NotRun || d.MutationAttempted {
				t.Fatal("provider acknowledgement, repetition or expiry authorized fault")
			}
		}
	}
}

func FuzzExternalPlanCannotAuthorizeFault(f *testing.F) {
	f.Add([]byte(`{"plan":{"executionAllowed":true}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, _ := Decode(data)
		d := Admit(p, p.Digest, time.Now())
		if d.Admission != "DENIED" || d.MutationAttempted || d.Verdict == result.Pass {
			t.Fatal("external safety boundary opened")
		}
	})
}
