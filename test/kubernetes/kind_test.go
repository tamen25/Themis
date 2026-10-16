package kubernetes_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	api "github.com/tamen25/themis/api/kubernetes/v1alpha1"
	"github.com/tamen25/themis/internal/kube"
	"github.com/tamen25/themis/internal/result"
	appsv1 "k8s.io/api/apps/v1"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Explicit opt-in only. No ambient kubeconfig or current context is used.
// This test never changes the synthetic Deployment, deletes a pod, or creates
// a fault. Restart updates only the owned controller's rollout annotation.
func TestKindDryRun(t *testing.T) {
	path := os.Getenv("THEMIS_KIND_KUBECONFIG")
	if path == "" {
		t.Skip("NOT EXECUTED: set THEMIS_KIND_KUBECONFIG to the dedicated owned Kind config")
	}
	var owner struct {
		ClusterName, Context     string
		ClusterUID, NamespaceUID types.UID
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(path), "ownership.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &owner); err != nil || owner.ClusterName != "themis-t20" || owner.Context != "kind-themis-t20" || owner.ClusterUID == "" || owner.NamespaceUID == "" {
		t.Fatal("complete owned Kind identity required")
	}
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(&clientcmd.ClientConfigLoadingRules{ExplicitPath: path}, &clientcmd.ConfigOverrides{CurrentContext: owner.Context}).ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(config.Host, "https://127.0.0.1:") || config.ExecProvider != nil || config.AuthProvider != nil || config.TLSClientConfig.Insecure {
		t.Fatal("dedicated local Kind credentials required")
	}
	config.Timeout = 5 * time.Second
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	_ = authv1.AddToScheme(scheme)
	c, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	for name, uid := range map[string]types.UID{"kube-system": owner.ClusterUID, kube.Namespace: owner.NamespaceUID} {
		ns := &corev1.Namespace{}
		if err := c.Get(ctx, client.ObjectKey{Name: name}, ns); err != nil || ns.UID != uid {
			t.Fatal("owned Kind namespace identity mismatch")
		}
	}
	target := &appsv1.Deployment{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: kube.Namespace, Name: "synthetic"}, target); err != nil {
		t.Fatal(err)
	}
	originalTarget := target.DeepCopy()
	newRun := func(name string) *unstructured.Unstructured {
		u := kube.RunObject()
		u.SetGenerateName(name + "-")
		u.SetNamespace(kube.Namespace)
		spec := api.RunSpec{SchemaVersion: "themis.kubernetes-run/v1alpha1", ExecutionProfile: kube.Profile, Contract: api.ContractSnapshot{SchemaVersion: "themis.kubernetes-contract/v1alpha1", Name: "synthetic-readiness", Assertion: "DeploymentAvailable", MinReplicas: 1}, Target: api.TargetReference{APIVersion: "apps/v1", Kind: "Deployment", Namespace: kube.Namespace, Name: target.Name, UID: target.UID, Generation: target.Generation}}
		u.Object["spec"], _ = runtime.DefaultUnstructuredConverter.ToUnstructured(&spec)
		return u
	}
	waitStatus := func(u *unstructured.Unstructured, phase string) api.RunStatus {
		t.Helper()
		for start := time.Now(); time.Since(start) < 30*time.Second; {
			if err := c.Get(ctx, client.ObjectKeyFromObject(u), u); err != nil {
				t.Fatal(err)
			}
			s := kube.ReadStatus(u)
			if s.Phase == phase {
				return s
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(100 * time.Millisecond):
			}
		}
		t.Fatalf("did not reach %s: %+v", phase, kube.ReadStatus(u))
		return api.RunStatus{}
	}
	valid := newRun("valid")
	if err := c.Create(ctx, valid); err != nil {
		t.Fatal(err)
	}
	first := waitStatus(valid, "PLANNED")
	if first.Verdict != result.NotRun || first.ExecutionAllowed || !first.PlanValid || first.Preview == nil || first.Preview.Plan.Target.Reference.UID != target.UID {
		t.Fatalf("invalid dry-run result: %+v", first)
	}
	policy, _ := kube.NewPolicy(kube.Namespace, owner.ClusterUID, owner.NamespaceUID)
	cluster, namespace := &corev1.Namespace{}, &corev1.Namespace{}
	_ = c.Get(ctx, client.ObjectKey{Name: "kube-system"}, cluster)
	_ = c.Get(ctx, client.ObjectKey{Name: kube.Namespace}, namespace)
	raw, _ := json.Marshal(valid.Object["spec"])
	spec, _ := kube.DecodeSpec(raw)
	preview, code := policy.Compile(valid.GetUID(), valid.GetGeneration(), spec, cluster, namespace, target)
	if code != "" || preview.Snapshot().Digest != first.PlanDigest {
		t.Fatal("real target plan is not deterministic")
	}
	t.Logf("A: real API plan %s verdict=%s executionAllowed=false", first.PlanDigest, first.Verdict)

	missing := newRun("missing")
	_ = unstructured.SetNestedField(missing.Object, "absent", "spec", "target", "name")
	if err := c.Create(ctx, missing); err != nil {
		t.Fatal(err)
	}
	missingStatus := waitStatus(missing, "WAITING")
	if missingStatus.Reason != "TargetNotFound" || missingStatus.Verdict != result.Inconclusive {
		t.Fatal("missing target did not remain inconclusive")
	}
	t.Log("B: missing target explicit TargetNotFound / INCONCLUSIVE")
	for _, field := range []string{"uid", "generation"} {
		u := newRun("mismatch")
		var value any = "99999999-9999-9999-9999-999999999999"
		if field == "generation" {
			value = target.Generation + 1
		}
		_ = unstructured.SetNestedField(u.Object, value, "spec", "target", field)
		if err := c.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		s := waitStatus(u, "DENIED")
		if s.Reason != "TargetIdentityChanged" || s.ExecutionAllowed || s.PlanValid {
			t.Fatal("target mismatch admitted")
		}
	}
	t.Log("C: real API UID/generation mismatches denied; external replacement/rollout is covered by pure reconciliation tests without mutating this target")
	wrong := newRun("wrong-namespace")
	wrong.SetNamespace("default")
	if err := c.Create(ctx, wrong); !apierrors.IsForbidden(err) {
		t.Fatalf("namespace policy not enforced: %v", err)
	}
	t.Log("D: default namespace rejected by admission policy")
	for _, nested := range [][]string{{"spec", "fault"}, {"spec", "target", "selector"}, {"spec", "contract", "script"}} {
		u := newRun("unknown")
		_ = unstructured.SetNestedField(u.Object, "unsupported", nested...)
		if err := c.Create(ctx, u); !apierrors.IsInvalid(err) && !apierrors.IsBadRequest(err) {
			t.Fatalf("unknown field accepted or unexpected failure: %v", err)
		}
	}
	u := newRun("fault-profile")
	_ = unstructured.SetNestedField(u.Object, "fault-injection", "spec", "executionProfile")
	if err := c.Create(ctx, u); !apierrors.IsInvalid(err) {
		t.Fatalf("unsupported operation accepted: %v", err)
	}
	t.Log("E: unknown/nested execution fields and unsupported profile rejected by real CRD validation")
	rootUnknown := newRun("unknown-envelope")
	rootUnknown.Object["fault"] = map[string]any{"type": "unsupported"}
	if err := c.Create(ctx, rootUnknown); err != nil {
		t.Fatal(err)
	}
	if s := waitStatus(rootUnknown, "DENIED"); s.Preview != nil || s.PlanValid || s.Verdict != result.NotRun {
		t.Fatal("unknown root field was silently pruned/admitted")
	}
	t.Log("Unknown root input preserved and explicitly DENIED by controller admission")

	controller := &appsv1.Deployment{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: kube.Namespace, Name: "themis-controller"}, controller); err != nil {
		t.Fatal(err)
	}
	if controller.Spec.Template.Annotations == nil {
		controller.Spec.Template.Annotations = map[string]string{}
	}
	controller.Spec.Template.Annotations[api.Group+"/restart-at"] = time.Now().UTC().Format(time.RFC3339Nano)
	if err := c.Update(ctx, controller); err != nil {
		t.Fatal(err)
	}
	for start := time.Now(); ; {
		if err := c.Get(ctx, client.ObjectKeyFromObject(controller), controller); err != nil {
			t.Fatal(err)
		}
		if controller.Status.ObservedGeneration == controller.Generation && controller.Status.AvailableReplicas == 1 && controller.Status.UpdatedReplicas == 1 {
			break
		}
		if time.Since(start) > 60*time.Second {
			t.Fatal("owned controller restart did not become available")
		}
		time.Sleep(200 * time.Millisecond)
	}
	// Wait longer than a poll interval, then require no status update from restart.
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(6 * time.Second):
	}
	if after := waitStatus(valid, "PLANNED"); !reflect.DeepEqual(first, after) {
		t.Fatal("restart changed the deterministic preview/status")
	}
	t.Log("F: owned controller rollout restart preserved the full plan and condition timestamps")
	if len(valid.GetFinalizers()) != 0 {
		t.Fatal("dry-run resource has an unsafe finalizer")
	}
	if err := c.Delete(ctx, valid); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(valid), kube.RunObject()); !apierrors.IsNotFound(err) {
		t.Fatalf("run deletion did not complete: %v", err)
	}
	t.Log("G: VerificationRun deleted without finalizer or target cleanup mutation")
	changed := newRun("changed-contract")
	if err := c.Create(ctx, changed); err != nil {
		t.Fatal(err)
	}
	original := waitStatus(changed, "PLANNED")
	_ = unstructured.SetNestedField(changed.Object, "changed-contract", "spec", "contract", "name")
	if err := c.Update(ctx, changed); err != nil {
		t.Fatal(err)
	}
	invalidated := waitStatus(changed, "INVALIDATED")
	if invalidated.PlanValid || invalidated.PlanDigest != "" || invalidated.Preview.Digest != original.PlanDigest || invalidated.CandidateDigest == original.PlanDigest || invalidated.CandidateDigest == "" || invalidated.Verdict != result.Inconclusive {
		t.Fatal("contract mutation reused prior preview")
	}
	t.Logf("H: changed contract invalidated prior %s; candidate=%s", original.PlanDigest, invalidated.CandidateDigest)
	for _, forbidden := range []struct {
		field string
		value any
	}{{"verdict", "PASS"}, {"executionAllowed", true}} {
		attempt := changed.DeepCopy()
		_ = unstructured.SetNestedField(attempt.Object, forbidden.value, "status", forbidden.field)
		if err := c.Status().Update(ctx, attempt); !apierrors.IsInvalid(err) {
			t.Fatalf("status schema allowed %s: %v", forbidden.field, err)
		}
	}
	stale := changed.DeepCopy()
	_ = unstructured.SetNestedField(changed.Object, "second-contract-change", "spec", "contract", "name")
	if err := c.Update(ctx, changed); err != nil {
		t.Fatal(err)
	}
	if err := c.Status().Update(ctx, stale); !apierrors.IsConflict(err) {
		t.Fatalf("stale spec/status update did not conflict: %v", err)
	}
	t.Log("Real API rejected PASS/executionAllowed=true and stale resourceVersion status updates")

	for _, check := range []struct {
		group, resource, verb, namespace, name string
		allowed                                bool
	}{
		{"apps", "deployments", "get", kube.Namespace, "synthetic", true},
		{"apps", "deployments", "patch", kube.Namespace, "synthetic", false},
		{"", "pods", "delete", kube.Namespace, "synthetic", false},
		{"batch", "jobs", "create", kube.Namespace, "job", false},
		{"", "secrets", "list", kube.Namespace, "", false},
		{"", "namespaces", "get", "", "default", false},
		{"", "namespaces", "get", "", "kube-system", true},
		{api.Group, "verificationruns/status", "update", kube.Namespace, "run", true},
		{api.Group, "verificationruns", "update", kube.Namespace, "run", false},
		{api.Group, "verificationruns/status", "update", "default", "run", false},
	} {
		resource, subresource := check.resource, ""
		if parts := strings.SplitN(resource, "/", 2); len(parts) == 2 {
			resource, subresource = parts[0], parts[1]
		}
		review := &authv1.SubjectAccessReview{Spec: authv1.SubjectAccessReviewSpec{User: "system:serviceaccount:themis-test:themis-controller", Groups: []string{"system:serviceaccounts", "system:serviceaccounts:themis-test", "system:authenticated"}, ResourceAttributes: &authv1.ResourceAttributes{Group: check.group, Resource: resource, Subresource: subresource, Verb: check.verb, Namespace: check.namespace, Name: check.name}}}
		if err := c.Create(ctx, review); err != nil {
			t.Fatal(err)
		}
		if review.Status.Allowed != check.allowed {
			t.Fatalf("RBAC mismatch %s %s in %s", check.verb, check.resource, check.namespace)
		}
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(target), target); err != nil {
		t.Fatal(err)
	}
	if target.UID != originalTarget.UID || target.Generation != originalTarget.Generation || !reflect.DeepEqual(target.Spec, originalTarget.Spec) || !reflect.DeepEqual(target.Labels, originalTarget.Labels) || !reflect.DeepEqual(target.Annotations, originalTarget.Annotations) || !reflect.DeepEqual(target.OwnerReferences, originalTarget.OwnerReferences) {
		t.Fatal("dry-run workflow changed target workload")
	}
	t.Log("Least-privilege RBAC verified; target UID, generation, spec, ownership, labels and annotations unchanged")
	if directory := os.Getenv("THEMIS_KIND_EVIDENCE_DIR"); directory != "" {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
		for name, value := range map[string]any{"plan": first, "contract-change": invalidated, "missing": missingStatus} {
			data, _ := json.MarshalIndent(value, "", "  ")
			if err := os.WriteFile(filepath.Join(directory, name+".json"), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}
