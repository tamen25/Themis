package chaosmesh_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/chaosmesh"
	"github.com/tamen25/themis/internal/localstate"
	appsv1 "k8s.io/api/apps/v1"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestOwnedKindExternalPlanningHardGates(t *testing.T) {
	if os.Getenv("THEMIS_KIND_CHAOSMESH_PLANNING") != "1" {
		t.Skip("NOT EXECUTED: explicit fresh owned T2.4 planning environment required; no live fault tests enabled")
	}
	state, binary := os.Getenv("THEMIS_CHAOSMESH_STATE"), os.Getenv("THEMIS_CHAOSMESH_BINARY")
	if state == "" || binary == "" {
		t.Fatal("explicit private state and binary required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var owner chaosmesh.Ownership
	if localstate.Read(filepath.Join(state, "planning-owner.json"), &owner) != nil {
		t.Fatal("missing original owner")
	}
	var bootstrap struct {
		Version          string   `json:"version"`
		ClusterName      string   `json:"clusterName"`
		Context          string   `json:"context"`
		ClusterUID       string   `json:"clusterUID"`
		NamespaceUID     string   `json:"namespaceUID"`
		PreviousClusters []string `json:"previousClusters"`
	}
	if localstate.Read(filepath.Join(state, "bootstrap-owner.json"), &bootstrap) != nil || bootstrap.Version != "themis.chaosmesh-bootstrap/v1alpha1" || bootstrap.ClusterName != owner.ClusterName || bootstrap.Context != owner.Context || bootstrap.ClusterUID != owner.ClusterUID || bootstrap.NamespaceUID != owner.NamespaceUID {
		t.Fatal("trusted bootstrap identity required")
	}
	for _, name := range bootstrap.PreviousClusters {
		if name == owner.ClusterName {
			t.Fatal("existing cluster adopted")
		}
	}
	adminPath := filepath.Join(state, "admin-kubeconfig")
	if localstate.Check(adminPath) != nil {
		t.Fatal("private installer config required")
	}
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(&clientcmd.ClientConfigLoadingRules{ExplicitPath: adminPath}, &clientcmd.ConfigOverrides{CurrentContext: owner.Context}).ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	config.Timeout = 4 * time.Second
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = authzv1.AddToScheme(scheme)
	_ = apiextv1.AddToScheme(scheme)
	admin, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	guard := func() {
		t.Helper()
		for name, uid := range map[string]string{"kube-system": owner.ClusterUID, "themis-test": owner.NamespaceUID} {
			ns := &corev1.Namespace{}
			if admin.Get(ctx, client.ObjectKey{Name: name}, ns) != nil || string(ns.UID) != uid {
				t.Fatal("owned identity changed; no mutation permitted")
			}
		}
		dep := &appsv1.Deployment{}
		if admin.Get(ctx, client.ObjectKey{Namespace: "themis-test", Name: "synthetic"}, dep) != nil || string(dep.UID) != owner.DeploymentUID || dep.Labels["verification.themis.dev/synthetic"] != "true" {
			t.Fatal("owned workload differs")
		}
	}
	guard()
	// An unrelated synthetic control is installer-owned test setup, with a
	// disjoint selector. The planning actor cannot even Get its Deployment.
	targetDeployment := &appsv1.Deployment{}
	if err = admin.Get(ctx, client.ObjectKey{Namespace: "themis-test", Name: "synthetic"}, targetDeployment); err != nil {
		t.Fatal(err)
	}
	control := targetDeployment.DeepCopy()
	control.ObjectMeta = metav1.ObjectMeta{Name: "unrelated-control", Namespace: "themis-test", Labels: map[string]string{"verification.themis.dev/synthetic": "true"}}
	control.Spec.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{"app": "themis-unrelated-control"}}
	control.Spec.Template.Labels = map[string]string{"app": "themis-unrelated-control"}
	control.Status = appsv1.DeploymentStatus{}
	guard()
	if err = admin.Create(ctx, control); err != nil {
		t.Fatal("fresh unrelated synthetic control required", err)
	}
	var controlPod corev1.Pod
	controlReady := false
	for start := time.Now(); time.Since(start) < 45*time.Second; {
		pods := &corev1.PodList{}
		if admin.List(ctx, pods, client.InNamespace("themis-test"), client.MatchingLabels{"app": "themis-unrelated-control"}) == nil && len(pods.Items) == 1 && len(pods.Items[0].Status.ContainerStatuses) == 1 && pods.Items[0].Status.ContainerStatuses[0].Ready {
			controlPod = pods.Items[0]
			controlReady = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !controlReady {
		t.Fatal("unrelated control did not become ready")
	}
	if err = admin.Get(ctx, client.ObjectKey{Namespace: "themis-test", Name: control.Name}, control); err != nil {
		t.Fatal(err)
	}
	controlBefore := control.DeepCopy()
	evidence := os.Getenv("THEMIS_CHAOSMESH_EVIDENCE")
	if evidence != "" {
		if err = os.MkdirAll(evidence, 0700); err != nil {
			t.Fatal(err)
		}
	}
	save := func(name string, value any) {
		t.Helper()
		if evidence == "" {
			return
		}
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(evidence, name+".json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	commands := []any{}
	t.Cleanup(func() { save("commands", commands) })
	command := func(label string, want int, args ...string) []byte {
		t.Helper()
		var out, diagnostics bytes.Buffer
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Stdout = &out
		cmd.Stderr = &diagnostics
		start := time.Now()
		err := cmd.Run()
		code := 0
		if err != nil {
			code = -99
			if e, ok := err.(*exec.ExitError); ok {
				code = e.ExitCode()
			}
		}
		commands = append(commands, map[string]any{"label": label, "program": binary, "arguments": args, "exitCode": code, "elapsedMS": time.Since(start).Milliseconds(), "stdout": out.String(), "stderr": diagnostics.String()})
		if code != want {
			t.Fatalf("%s exit=%d want=%d %s", label, code, want, diagnostics.String())
		}
		return out.Bytes()
	}
	proposedKey := strings.Repeat("e", 64) // Public proposal only; no authority issued.
	data := command("real-readonly-plan", 0, "plan", "--state", state, "--approver-public-key", proposedKey)
	p, err := chaosmesh.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	save("resolved-plan", p)
	planPath := filepath.Join(state, "external-plan-"+p.Document.InvocationID+".json")
	if localstate.WriteNew(planPath, p) != nil {
		t.Fatal("private plan publication failed")
	}
	decision := command("matching-plan-still-denied", 5, "admit", "--state", state, "-f", planPath, "--expect-digest", p.Digest)
	if !bytes.Contains(decision, []byte(`"mutationAttempted": false`)) || !bytes.Contains(decision, []byte(`"verdict": "NOT_RUN"`)) {
		t.Fatal("unsafe admission output")
	}
	command("duplicate-admission-remains-denied", 5, "admit", "--state", state, "-f", planPath, "--expect-digest", p.Digest)
	command("altered-reviewed-digest-denied", 5, "admit", "-f", planPath, "--expect-digest", "sha256:"+strings.Repeat("0", 64))
	for _, change := range []string{"cluster", "namespace"} {
		dir, err := localstate.CreateDirectory(filepath.Join(state, "negative-"+change+"-"+localstate.RandomID()[:12]))
		if err != nil {
			t.Fatal(err)
		}
		copy := owner
		copy.Directory = dir
		if change == "cluster" {
			copy.ClusterUID = "99999999-9999-9999-9999-999999999999"
		} else {
			copy.NamespaceUID = "99999999-9999-9999-9999-999999999999"
		}
		if localstate.WriteNew(filepath.Join(dir, "planning-owner.json"), copy) != nil {
			t.Fatal("negative ownership setup")
		}
		bytes, err := os.ReadFile(filepath.Join(state, "planner-kubeconfig"))
		if err != nil {
			t.Fatal(err)
		}
		f, err := localstate.OpenNew(filepath.Join(dir, "planner-kubeconfig"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.Write(bytes)
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
		command("wrong-"+change+"-rejected", 5, "plan", "--state", dir, "--approver-public-key", proposedKey)
	}
	// Inspect the actual installed pinned upstream CRD. Schema-only compatibility
	// and dry-run acknowledgement never count as provider intervention evidence.
	crd := &apiextv1.CustomResourceDefinition{}
	if admin.Get(ctx, client.ObjectKey{Name: "networkchaos.chaos-mesh.org"}, crd) != nil {
		t.Fatal("pinned CRD absent")
	}
	if crd.Spec.Group != "chaos-mesh.org" || crd.Spec.Scope != apiextv1.NamespaceScoped || len(crd.Spec.Versions) != 1 || crd.Spec.Versions[0].Name != "v1alpha1" {
		t.Fatal("unexpected upstream CRD version")
	}
	save("actual-networkchaos-crd", crd)
	wire, _ := json.Marshal(p.Document.Resource)
	object := &unstructured.Unstructured{}
	if json.Unmarshal(wire, &object.Object) != nil {
		t.Fatal("candidate wire object")
	}
	dryRun := &client.CreateOptions{DryRun: []string{metav1.DryRunAll}, FieldValidation: metav1.FieldValidationStrict}
	guard()
	if err = admin.Create(ctx, object, dryRun); err != nil {
		t.Fatal("actual upstream schema rejected closed delay candidate", err)
	}
	save("server-dry-run-candidate", object)
	current := &unstructured.Unstructured{}
	current.SetGroupVersionKind(schema.GroupVersionKind{Group: "chaos-mesh.org", Version: "v1alpha1", Kind: "NetworkChaos"})
	if !apierrors.IsNotFound(admin.Get(ctx, client.ObjectKey{Namespace: "themis-test", Name: p.Document.Resource.Metadata.Name}, current)) {
		t.Fatal("dry-run persisted a fault resource")
	}
	bad := object.DeepCopy()
	bad.SetUID("")
	bad.SetResourceVersion("")
	_ = unstructured.SetNestedField(bad.Object, p.Document.Snapshot.Target.PodUID, "spec", "selector", "uid")
	guard()
	if err = admin.Create(ctx, bad, dryRun); err == nil {
		t.Fatal("strict upstream schema accepted an unsupported UID field; investigate before interpreting this test")
	}
	save("unsupported-approved-uid-field", map[string]any{"error": err.Error(), "dryRun": true})
	// Prove effective permissions. Only installer SubjectAccessReviews are created;
	// no denied fault POST is sent, even to a schema-only provider environment.
	rbac := []any{}
	for _, actor := range []string{"themis-chaosmesh-planner", "themis-controller"} {
		for _, operation := range []struct{ group, resource, subresource, verb string }{{"chaos-mesh.org", "networkchaos", "", "create"}, {"chaos-mesh.org", "networkchaos", "", "patch"}, {"chaos-mesh.org", "networkchaos", "", "delete"}, {"apps", "deployments", "", "patch"}, {"", "pods", "", "delete"}, {"", "pods", "exec", "create"}, {"", "pods", "portforward", "create"}, {"", "secrets", "", "get"}, {"batch", "jobs", "", "create"}, {"rbac.authorization.k8s.io", "roles", "", "update"}} {
			name := p.Document.Resource.Metadata.Name
			if operation.resource == "pods" {
				name = p.Document.Snapshot.Target.PodName
			} else if operation.resource == "deployments" {
				name = "synthetic"
			}
			review := &authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{User: "system:serviceaccount:themis-test:" + actor, Groups: []string{"system:serviceaccounts", "system:serviceaccounts:themis-test", "system:authenticated"}, ResourceAttributes: &authzv1.ResourceAttributes{Namespace: "themis-test", Name: name, Group: operation.group, Resource: operation.resource, Subresource: operation.subresource, Verb: operation.verb}}}
			guard()
			if err = admin.Create(ctx, review); err != nil || review.Status.Allowed {
				t.Fatal("runtime privileges widened", actor, operation, err)
			}
			rbac = append(rbac, review)
		}
	}
	save("actual-denied-rbac", rbac)
	// Installer-owned UID-precondition replacement tests fresh resolution. This is
	// test setup only; no Pod deletion primitive is available to either runtime.
	pod := &corev1.Pod{}
	if admin.Get(ctx, client.ObjectKey{Namespace: "themis-test", Name: p.Document.Snapshot.Target.PodName}, pod) != nil || string(pod.UID) != p.Document.Snapshot.Target.PodUID {
		t.Fatal("original target absent")
	}
	guard()
	uid := pod.UID
	if err = admin.Delete(ctx, pod, client.Preconditions{UID: &uid}); err != nil {
		t.Fatal(err)
	}
	var replacement *corev1.Pod
	for start := time.Now(); time.Since(start) < 60*time.Second; {
		pods := &corev1.PodList{}
		if admin.List(ctx, pods, client.InNamespace("themis-test"), client.MatchingLabels{"app": "themis-synthetic"}) == nil && len(pods.Items) == 1 {
			item := pods.Items[0]
			if item.UID != uid && len(item.Status.ContainerStatuses) == 1 && item.Status.ContainerStatuses[0].Ready {
				replacement = &item
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if replacement == nil {
		t.Fatal("owned replacement did not become ready")
	}
	cluster, err := chaosmesh.Open(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	if cluster.Revalidate(ctx, p) == nil {
		t.Fatal("replacement UID accepted")
	}
	save("replacement-identity", replacement)
	command("pod-replacement-revalidation-denied", 5, "admit", "--state", state, "-f", planPath, "--expect-digest", p.Digest)
	// Check that no provider workload or intervention resource exists anywhere.
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(schema.GroupVersionKind{Group: "chaos-mesh.org", Version: "v1alpha1", Kind: "NetworkChaosList"})
	if admin.List(ctx, list) != nil || len(list.Items) != 0 {
		t.Fatal("an external fault resource exists")
	}
	save("zero-networkchaos-resources", list)
	if err = admin.Get(ctx, client.ObjectKey{Namespace: "themis-test", Name: control.Name}, control); err != nil || control.UID != controlBefore.UID || control.Generation != controlBefore.Generation || !reflect.DeepEqual(control.Spec, controlBefore.Spec) || !reflect.DeepEqual(control.Labels, controlBefore.Labels) || !reflect.DeepEqual(control.Annotations, controlBefore.Annotations) {
		t.Fatal("unrelated synthetic Deployment changed", err)
	}
	currentControl := &corev1.Pod{}
	if err = admin.Get(ctx, client.ObjectKey{Namespace: "themis-test", Name: controlPod.Name}, currentControl); err != nil || currentControl.UID != controlPod.UID || len(currentControl.Status.ContainerStatuses) != 1 || !currentControl.Status.ContainerStatuses[0].Ready || currentControl.Status.ContainerStatuses[0].ContainerID != controlPod.Status.ContainerStatuses[0].ContainerID {
		t.Fatal("unrelated control replaced or restarted", err)
	}
	save("unrelated-control-unchanged", map[string]any{"deploymentBefore": controlBefore, "deploymentAfter": control, "podBefore": controlPod, "podAfter": currentControl})
	deployments := &appsv1.DeploymentList{}
	if admin.List(ctx, deployments) != nil {
		t.Fatal("cannot inspect provider absence")
	}
	for _, d := range deployments.Items {
		if strings.Contains(d.Name, "chaos-mesh") || strings.Contains(d.Name, "chaos-controller") {
			t.Fatal("provider controller unexpectedly installed")
		}
	}
	daemons := &appsv1.DaemonSetList{}
	if admin.List(ctx, daemons) != nil {
		t.Fatal("cannot inspect daemons")
	}
	for _, d := range daemons.Items {
		if strings.Contains(d.Name, "chaos") {
			t.Fatal("privileged provider daemon unexpectedly installed")
		}
	}
	before, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	var frozen chaosmesh.Plan
	if json.Unmarshal(before, &frozen) != nil || !reflect.DeepEqual(frozen, p) {
		t.Fatal("historical planning bytes altered")
	}
	t.Log("REAL KIND planning/CRD schema/server dry-run/RBAC/UID replacement negatives passed. ZERO real Chaos Mesh fault operations; A-D and active-fault crash/expiry demonstrations NOT EXECUTED because UID/deadline safety gates remain closed.")
}
