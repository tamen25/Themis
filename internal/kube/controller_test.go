package kube

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	api "github.com/tamen25/themis/api/kubernetes/v1alpha1"
	"github.com/tamen25/themis/internal/result"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func fixtures() (Policy, api.RunSpec, *corev1.Namespace, *corev1.Namespace, *appsv1.Deployment) {
	cluster := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "11111111-1111-1111-1111-111111111111"}}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: Namespace, UID: "22222222-2222-2222-2222-222222222222"}}
	ref := api.TargetReference{APIVersion: "apps/v1", Kind: "Deployment", Namespace: Namespace, Name: "synthetic", UID: "33333333-3333-3333-3333-333333333333", Generation: 1}
	spec := api.RunSpec{SchemaVersion: "themis.kubernetes-run/v1alpha1", ExecutionProfile: Profile, Contract: api.ContractSnapshot{SchemaVersion: "themis.kubernetes-contract/v1alpha1", Name: "readiness", Assertion: "DeploymentAvailable", MinReplicas: 1}, Target: ref}
	d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: Namespace, Name: ref.Name, UID: ref.UID, Generation: 1, Labels: map[string]string{api.Group + "/synthetic": "true"}}, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "example.invalid/synthetic@sha256:" + strings.Repeat("a", 64)}}}}}, Status: appsv1.DeploymentStatus{ObservedGeneration: 1}}
	p, _ := NewPolicy(Namespace, cluster.UID, namespace.UID)
	return p, spec, cluster, namespace, d
}

func TestPlanDeterminismAndIsolation(t *testing.T) {
	p, spec, cluster, ns, d := fixtures()
	uid := types.UID("44444444-4444-4444-4444-444444444444")
	a, code := p.Compile(uid, 1, spec, cluster, ns, d)
	if code != "" {
		t.Fatal(code)
	}
	b, _ := p.Compile(uid, 1, spec, cluster, ns, d.DeepCopy())
	if !reflect.DeepEqual(a.Snapshot(), b.Snapshot()) {
		t.Fatal("nondeterministic preview")
	}
	copy := a.Snapshot()
	copy.Plan.Target.Images[0].Image = "mutated"
	if a.Snapshot().Plan.Target.Images[0].Image == "mutated" || a.Snapshot().Plan.ExecutionAllowed {
		t.Fatal("mutable plan or execution authority")
	}
	spec.Contract.Name = "new-contract"
	c, _ := p.Compile(uid, 1, spec, cluster, ns, d)
	if c.Snapshot().Digest == a.Snapshot().Digest {
		t.Fatal("changed contract did not change digest")
	}
}

func TestSafetyDenials(t *testing.T) {
	for _, name := range []string{"namespace", "profile", "schema", "uid", "generation", "observed generation", "image tag", "privileged", "host networking", "namespace replacement", "cluster replacement"} {
		t.Run(name, func(t *testing.T) {
			p, s, cluster, ns, d := fixtures()
			switch name {
			case "namespace":
				s.Target.Namespace = "kube-system"
			case "profile":
				s.ExecutionProfile = "fault-injection"
			case "schema":
				s.Contract.SchemaVersion = "themis.contract/v1alpha2"
			case "uid":
				s.Target.UID = "55555555-5555-5555-5555-555555555555"
			case "generation":
				s.Target.Generation++
			case "observed generation":
				d.Status.ObservedGeneration = 0
			case "image tag":
				d.Spec.Template.Spec.Containers[0].Image = "app:latest"
			case "privileged":
				yes := true
				d.Spec.Template.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: &yes}
			case "host networking":
				d.Spec.Template.Spec.HostNetwork = true
			case "namespace replacement":
				ns.UID = "55555555-5555-5555-5555-555555555555"
			case "cluster replacement":
				cluster.UID = "55555555-5555-5555-5555-555555555555"
			}
			if _, code := p.Compile("44444444-4444-4444-4444-444444444444", 1, s, cluster, ns, d); code == "" {
				t.Fatal("unsafe input admitted")
			}
		})
	}
	if _, err := NewPolicy("default", "a", "b"); err == nil {
		t.Fatal("untrusted policy configuration")
	}
	_, spec, _, _, _ := fixtures()
	data, _ := json.Marshal(spec)
	data = append(data[:len(data)-1], []byte(`,"fault":{"type":"pod-kill"}}`)...)
	if _, err := DecodeSpec(data); err == nil {
		t.Fatal("unknown fault field accepted")
	}
}

func TestStrictSpecInput(t *testing.T) {
	_, spec, _, _, _ := fixtures()
	valid, _ := json.Marshal(spec)
	for _, suffix := range []string{`,"executionProfile":"kind-dry-run"}`, `,"ExecutionProfile":"kind-dry-run"}`, `,"fault":"unsupported"}`} {
		bad := append(append([]byte{}, valid[:len(valid)-1]...), []byte(suffix)...)
		if _, err := DecodeSpec(bad); err == nil {
			t.Fatal("duplicate, unknown or case-mismatched field accepted")
		}
	}
	if _, err := DecodeSpec(append(valid, []byte(` {}`)...)); err == nil {
		t.Fatal("trailing document accepted")
	}
	if _, err := DecodeSpec([]byte(strings.Repeat(" ", 8193))); err == nil {
		t.Fatal("oversized specification accepted")
	}
}

func testReconciler(t *testing.T) (*Reconciler, ctrl.Request) {
	t.Helper()
	p, spec, cluster, ns, d := fixtures()
	u := RunObject()
	u.SetName("preview")
	u.SetNamespace(Namespace)
	u.SetUID("44444444-4444-4444-4444-444444444444")
	u.SetGeneration(1)
	u.Object["spec"], _ = runtime.DefaultUnstructuredConverter.ToUnstructured(&spec)
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(u, cluster, ns, d).WithStatusSubresource(u).Build()
	return &Reconciler{Client: c, Reader: c, Policy: p}, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: Namespace, Name: u.GetName()}}
}

func reconcileStatus(t *testing.T, r *Reconciler, req ctrl.Request) api.RunStatus {
	t.Helper()
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	u := RunObject()
	if err := r.Client.Get(context.Background(), req.NamespacedName, u); err != nil {
		t.Fatal(err)
	}
	return ReadStatus(u)
}

func TestReconcileIdempotentRestartAndDeletion(t *testing.T) {
	r, req := testReconciler(t)
	first := reconcileStatus(t, r, req)
	if first.Phase != "PLANNED" || first.Verdict != result.NotRun || first.ExecutionAllowed || !first.PlanValid {
		t.Fatalf("invalid dry-run status: %+v", first)
	}
	u := RunObject()
	_ = r.Client.Get(context.Background(), req.NamespacedName, u)
	version := u.GetResourceVersion()
	restarted := &Reconciler{Client: r.Client, Reader: r.Reader, Policy: r.Policy}
	second := reconcileStatus(t, restarted, req)
	_ = r.Client.Get(context.Background(), req.NamespacedName, u)
	if !reflect.DeepEqual(first, second) || version != u.GetResourceVersion() {
		t.Fatal("unchanged restart caused an update loop")
	}
	if err := r.Client.Delete(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	d := &appsv1.Deployment{}
	if err := r.Client.Get(context.Background(), client.ObjectKey{Namespace: Namespace, Name: "synthetic"}, d); err != nil {
		t.Fatal("run deletion touched target")
	}
}

func TestUnknownEnvelopeDenied(t *testing.T) {
	r, req := testReconciler(t)
	u := RunObject()
	_ = r.Client.Get(context.Background(), req.NamespacedName, u)
	u.Object["fault"] = map[string]any{"type": "unsupported"}
	if err := r.Client.Update(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	s := reconcileStatus(t, r, req)
	if s.Phase != "DENIED" || s.Verdict != result.NotRun || s.Preview != nil || s.PlanValid {
		t.Fatal("unknown root field silently ignored")
	}
}

func TestPlanInvalidation(t *testing.T) {
	for _, mutation := range []string{"contract", "uid", "generation", "ownership", "template"} {
		t.Run(mutation, func(t *testing.T) {
			r, req := testReconciler(t)
			first := reconcileStatus(t, r, req)
			if mutation == "contract" {
				u := RunObject()
				_ = r.Client.Get(context.Background(), req.NamespacedName, u)
				_ = unstructured.SetNestedField(u.Object, "changed-contract", "spec", "contract", "name")
				u.SetGeneration(2)
				if err := r.Client.Update(context.Background(), u); err != nil {
					t.Fatal(err)
				}
			} else {
				d := &appsv1.Deployment{}
				_ = r.Client.Get(context.Background(), client.ObjectKey{Namespace: Namespace, Name: "synthetic"}, d)
				switch mutation {
				case "uid":
					d.UID = "55555555-5555-5555-5555-555555555555"
				case "generation":
					d.Generation++
				case "ownership":
					d.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: "changed", UID: "55555555-5555-5555-5555-555555555555"}}
				case "template":
					d.Spec.Template.Labels = map[string]string{"revision": "changed"}
				}
				if err := r.Client.Update(context.Background(), d); err != nil {
					t.Fatal(err)
				}
			}
			next := reconcileStatus(t, r, req)
			if next.Phase != "INVALIDATED" || next.PlanValid || next.ExecutionAllowed || next.PlanDigest != "" || next.Preview.Digest != first.Preview.Digest || next.Verdict != result.Inconclusive {
				t.Fatalf("stale plan remained valid: %+v", next)
			}
			if mutation != "contract" {
				_, _, _, _, original := fixtures()
				d := &appsv1.Deployment{}
				_ = r.Client.Get(context.Background(), client.ObjectKeyFromObject(original), d)
				d.UID, d.Generation, d.Spec, d.OwnerReferences = original.UID, original.Generation, original.Spec, original.OwnerReferences
				if err := r.Client.Update(context.Background(), d); err != nil {
					t.Fatal(err)
				}
				if restored := reconcileStatus(t, r, req); !restored.Invalidated || restored.PlanValid || restored.Phase != "INVALIDATED" {
					t.Fatal("reverting target drift revived the invalidated run")
				}
			}
		})
	}
}
