package livewitness

import (
	"context"
	"strings"
	"testing"

	api "github.com/tamen25/themis/api/kubernetes/v1alpha1"
	"github.com/tamen25/themis/internal/kube"
	"github.com/tamen25/themis/internal/kubefault"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// A client-simulated identity read, not a real Kubernetes experiment.
func targetFixture(t *testing.T) (*target, kubefault.Plan) {
	t.Helper()
	uid := func(n string) types.UID {
		return types.UID(strings.Repeat(n, 8) + "-" + strings.Repeat(n, 4) + "-" + strings.Repeat(n, 4) + "-" + strings.Repeat(n, 4) + "-" + strings.Repeat(n, 12))
	}
	cluster := &core.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: uid("1")}}
	ns := &core.Namespace{ObjectMeta: metav1.ObjectMeta{Name: kube.Namespace, UID: uid("2")}}
	one, no, yes := int32(1), false, true
	image := "example.invalid/fixture@sha256:" + strings.Repeat("a", 64)
	dep := &apps.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "latency-fixture", Namespace: kube.Namespace, UID: uid("3"), Generation: 1, Labels: map[string]string{api.Group + "/synthetic": "true"}}, Spec: apps.DeploymentSpec{Replicas: &one, Template: core.PodTemplateSpec{Spec: core.PodSpec{AutomountServiceAccountToken: &no, Containers: []core.Container{{Name: "fixture", Image: image}}}}}, Status: apps.DeploymentStatus{ObservedGeneration: 1}}
	rs := &apps.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "fixture-rs", Namespace: kube.Namespace, UID: uid("4"), OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: dep.Name, UID: dep.UID, Controller: &yes}}}}
	pod := &core.Pod{ObjectMeta: metav1.ObjectMeta{Name: "fixture-pod", Namespace: kube.Namespace, UID: uid("5"), OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &yes}}}, Spec: *dep.Spec.Template.Spec.DeepCopy(), Status: core.PodStatus{Phase: core.PodRunning, ContainerStatuses: []core.ContainerStatus{{Name: "fixture", Ready: true, ContainerID: "containerd://" + strings.Repeat("b", 64), ImageID: "sha256:" + strings.Repeat("a", 64), State: core.ContainerState{Running: &core.ContainerStateRunning{}}}}}}
	run := kube.RunObject()
	run.SetNamespace(kube.Namespace)
	run.SetName("latency-request")
	run.SetUID(uid("6"))
	run.SetGeneration(1)
	spec := api.RunSpec{SchemaVersion: "themis.kubernetes-run/v1alpha1", ExecutionProfile: kube.Profile, Contract: api.ContractSnapshot{SchemaVersion: "themis.kubernetes-contract/v1alpha1", Name: "readiness", Assertion: "DeploymentAvailable", MinReplicas: 1}, Target: api.TargetReference{APIVersion: "apps/v1", Kind: "Deployment", Namespace: kube.Namespace, Name: dep.Name, UID: dep.UID, Generation: 1}}
	run.Object["spec"], _ = runtime.DefaultUnstructuredConverter.ToUnstructured(&spec)
	policy, _ := kube.NewPolicy(kube.Namespace, cluster.UID, ns.UID)
	preview, code := policy.Compile(run.GetUID(), 1, spec, cluster, ns, dep)
	if code != "" {
		t.Fatal(code)
	}
	snapshot := preview.Snapshot()
	status := api.RunStatus{ObservedGeneration: 1, Phase: "PLANNED", Verdict: "NOT_RUN", PlanValid: true, PlanDigest: snapshot.Digest, Preview: &snapshot}
	run.Object["status"], _ = runtime.DefaultUnstructuredConverter.ToUnstructured(&status)
	scheme := runtime.NewScheme()
	_ = core.AddToScheme(scheme)
	_ = apps.AddToScheme(scheme)
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, ns, dep, rs, pod, run).Build()
	p := kubefault.Plan{Version: kubefault.PlanVersion, Policy: kubefault.PolicyVersion, RunName: run.GetName(), RunUID: string(run.GetUID()), RunGeneration: 1, PreviewDigest: snapshot.Digest, Operator: kubefault.Actor{Name: kubefault.OperatorName, UID: string(uid("7"))}, Target: kubefault.Target{Namespace: kube.Namespace, DeploymentName: dep.Name, DeploymentUID: string(dep.UID), DeploymentGeneration: 1, TemplateDigest: snapshot.Plan.Target.TemplateDigest, ReplicaSetName: rs.Name, ReplicaSetUID: string(rs.UID), PodSpecDigest: kubefault.Digest("themis.kubernetes-pod-spec/v1alpha1", pod.Spec), ContainerID: pod.Status.ContainerStatuses[0].ContainerID, Image: image, ImageID: pod.Status.ContainerStatuses[0].ImageID, Fixture: kubefault.Identity{Version: kubefault.Version, ClusterUID: string(cluster.UID), NamespaceUID: string(ns.UID), PodName: pod.Name, PodUID: string(pod.UID), InstanceID: strings.Repeat("c", 64), ProxyID: strings.Repeat("d", 64), EvidenceKey: strings.Repeat("e", 64)}}, Contract: kubefault.Contract{Version: "themis.kubernetes-experiment-contract/v1alpha1", Name: "synthetic-latency", Samples: 3, MinConfirmed: 3, MaxErrorFraction: "0"}, Fault: kubefault.Fault{Type: "http.response-latency", DelayMS: 200, DurationMS: 2500}, Scenario: "healthy"}
	target := &target{owner: Owner{ClusterUID: string(cluster.UID), NamespaceUID: string(ns.UID), DeploymentUID: string(dep.UID)}, reader: reader}
	if e := target.check(context.Background(), p); e != nil {
		t.Fatal("valid independently resolved target", e)
	}
	return target, p
}
func TestIndependentTargetReadsDenyDriftAndForgedPreviews(t *testing.T) {
	for _, name := range []string{"cluster", "namespace", "pod", "container", "deployment", "preview", "run", "unsupported-fault", "controller-forged-pass", "api-outage"} {
		t.Run(name, func(t *testing.T) {
			target, p := targetFixture(t)
			switch name {
			case "cluster":
				p.Target.Fixture.ClusterUID = "99999999-9999-9999-9999-999999999999"
			case "namespace":
				p.Target.Fixture.NamespaceUID = "99999999-9999-9999-9999-999999999999"
			case "pod":
				p.Target.Fixture.PodUID = "99999999-9999-9999-9999-999999999999"
			case "container":
				p.Target.ContainerID = "different"
			case "deployment":
				p.Target.DeploymentGeneration++
			case "preview":
				p.PreviewDigest = "sha256:" + strings.Repeat("f", 64)
			case "run":
				p.RunGeneration++
			case "unsupported-fault":
				p.Fault.Type = "pod.delete"
			case "controller-forged-pass":
				r := kube.RunObject()
				_ = target.reader.Get(t.Context(), client.ObjectKey{Namespace: kube.Namespace, Name: p.RunName}, r)
				r.Object["status"].(map[string]any)["verdict"] = "PASS"
				if e := target.reader.Update(t.Context(), r); e != nil {
					t.Fatal(e)
				}
			case "api-outage":
				target.reader = unavailableReader{target.reader}
			}
			if e := target.check(t.Context(), p); e == nil {
				t.Fatal("client-simulated unsafe identity accepted", name)
			}
		})
	}
}

type unavailableReader struct{ client.Client }

func (c unavailableReader) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return context.DeadlineExceeded
}
