package kubeexperiment

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	api "github.com/tamen25/themis/api/kubernetes/v1alpha1"
	"github.com/tamen25/themis/internal/kube"
	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/result"
	appsv1 "k8s.io/api/apps/v1"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type operatorClient struct {
	client.Client
	actor kubefault.Actor
}

func (c operatorClient) Create(ctx context.Context, obj client.Object, options ...client.CreateOption) error {
	if review, ok := obj.(*authv1.SelfSubjectReview); ok {
		review.Status.UserInfo = authv1.UserInfo{Username: c.actor.Name, UID: c.actor.UID}
		return nil
	}
	return c.Client.Create(ctx, obj, options...)
}

func clusterFixture(t *testing.T) (*Cluster, kubefault.Plan) {
	t.Helper()
	clusterUID, namespaceUID := "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	depUID, rsUID, podUID, runUID := "33333333-3333-3333-3333-333333333333", "44444444-4444-4444-4444-444444444444", "55555555-5555-5555-5555-555555555555", "66666666-6666-6666-6666-666666666666"
	actor := kubefault.Actor{Name: kubefault.OperatorName, UID: "77777777-7777-7777-7777-777777777777"}
	image := "example.invalid/fixture@sha256:" + strings.Repeat("a", 64)
	cluster := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID(clusterUID)}}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: kube.Namespace, UID: types.UID(namespaceUID)}}
	one, no, yes := int32(1), false, true
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "latency-fixture", Namespace: kube.Namespace, UID: types.UID(depUID), Generation: 1, Labels: map[string]string{api.Group + "/synthetic": "true"}}, Spec: appsv1.DeploymentSpec{Replicas: &one, Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{AutomountServiceAccountToken: &no, Containers: []corev1.Container{{Name: "fixture", Image: image}}}}}, Status: appsv1.DeploymentStatus{ObservedGeneration: 1}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "latency-fixture-rs", Namespace: kube.Namespace, UID: types.UID(rsUID), OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: dep.Name, UID: dep.UID, Controller: &yes}}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "latency-fixture-rs-pod", Namespace: kube.Namespace, UID: types.UID(podUID), Labels: map[string]string{"app": "themis-latency-fixture"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &yes}}}, Spec: *dep.Spec.Template.Spec.DeepCopy(), Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "fixture", Ready: true, ContainerID: "containerd://" + strings.Repeat("b", 64), ImageID: "sha256:" + strings.Repeat("a", 64), State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
	run := kube.RunObject()
	run.SetNamespace(kube.Namespace)
	run.SetName("latency-request")
	run.SetUID(types.UID(runUID))
	run.SetGeneration(1)
	spec := api.RunSpec{SchemaVersion: "themis.kubernetes-run/v1alpha1", ExecutionProfile: kube.Profile, Contract: api.ContractSnapshot{SchemaVersion: "themis.kubernetes-contract/v1alpha1", Name: "fixture-readiness", Assertion: "DeploymentAvailable", MinReplicas: 1}, Target: api.TargetReference{APIVersion: "apps/v1", Kind: "Deployment", Namespace: kube.Namespace, Name: dep.Name, UID: dep.UID, Generation: 1}}
	run.Object["spec"], _ = runtime.DefaultUnstructuredConverter.ToUnstructured(&spec)
	policy, _ := kube.NewPolicy(kube.Namespace, cluster.UID, namespace.UID)
	preview, code := policy.Compile(run.GetUID(), 1, spec, cluster, namespace, dep)
	if code != "" {
		t.Fatal(code)
	}
	snapshot := preview.Snapshot()
	status := api.RunStatus{ObservedGeneration: 1, Phase: "PLANNED", Verdict: result.NotRun, PlanValid: true, PlanDigest: snapshot.Digest, Preview: &snapshot}
	run.Object["status"], _ = runtime.DefaultUnstructuredConverter.ToUnstructured(&status)
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = authv1.AddToScheme(scheme)
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, namespace, dep, rs, pod, run).Build()
	c := &Cluster{Owner: Ownership{Version: "themis.kind-ownership/t2.1-v1", ClusterName: "themis-t21", Context: "kind-themis-t21", ClusterUID: clusterUID, NamespaceUID: namespaceUID, Operator: actor, DeploymentUID: depUID, FixtureImage: image, FixtureImageID: pod.Status.ContainerStatuses[0].ImageID}, Reader: operatorClient{base, actor}}
	p, err := c.resolve(context.Background(), run.GetName())
	if err != nil {
		t.Fatal(err)
	}
	p.Target.Fixture.InstanceID = strings.Repeat("c", 64)
	p.Target.Fixture.ProxyID = strings.Repeat("d", 64)
	p.Target.Fixture.EvidenceKey = strings.Repeat("e", 64)
	if p.Validate() != nil || c.Revalidate(context.Background(), p) != nil {
		t.Fatal("valid client fixture denied")
	}
	return c, p
}

func TestFreshIdentityAndAuthorizationDenials(t *testing.T) {
	for _, name := range []string{"cluster UID", "namespace UID", "Deployment UID", "Deployment generation", "Pod UID", "Pod replacement", "container restart", "workload ownership", "plan mutation", "unsupported fault", "duration", "actor", "unsupported PASS", "unknown envelope"} {
		t.Run(name, func(t *testing.T) {
			c, p := clusterFixture(t)
			ctx := context.Background()
			update := func(obj client.Object) {
				t.Helper()
				if err := c.Reader.Update(ctx, obj); err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "cluster UID":
				c.Owner.ClusterUID = "99999999-9999-9999-9999-999999999999"
			case "namespace UID":
				c.Owner.NamespaceUID = "99999999-9999-9999-9999-999999999999"
			case "Deployment UID":
				c.Owner.DeploymentUID = "99999999-9999-9999-9999-999999999999"
			case "Deployment generation":
				d := &appsv1.Deployment{}
				_ = c.Reader.Get(ctx, client.ObjectKey{Namespace: kube.Namespace, Name: "latency-fixture"}, d)
				d.Generation++
				update(d)
			case "Pod UID":
				p.Target.Fixture.PodUID = "99999999-9999-9999-9999-999999999999"
			case "Pod replacement":
				pod := &corev1.Pod{}
				_ = c.Reader.Get(ctx, client.ObjectKey{Namespace: kube.Namespace, Name: p.Target.Fixture.PodName}, pod)
				if err := c.Reader.Delete(ctx, pod); err != nil {
					t.Fatal(err)
				}
				pod.UID = "99999999-9999-9999-9999-999999999999"
				pod.ResourceVersion = ""
				if err := c.Reader.Create(ctx, pod); err != nil {
					t.Fatal(err)
				}
			case "container restart":
				p.Target.ContainerID = "containerd://" + strings.Repeat("f", 64)
			case "workload ownership":
				p.Target.ReplicaSetUID = "99999999-9999-9999-9999-999999999999"
			case "plan mutation":
				p.PreviewDigest = "sha256:" + strings.Repeat("f", 64)
			case "unsupported fault":
				p.Fault.Type = "pod.delete"
			case "duration":
				p.Fault.DurationMS = 60000
			case "actor":
				c.Owner.Operator.Name = "cluster-admin"
			case "unsupported PASS", "unknown envelope":
				u := kube.RunObject()
				_ = c.Reader.Get(ctx, client.ObjectKey{Namespace: kube.Namespace, Name: p.RunName}, u)
				if name == "unsupported PASS" {
					u.Object["status"].(map[string]any)["verdict"] = "PASS"
				} else {
					u.Object["fault"] = "unsupported"
				}
				update(u)
			}
			if err := c.Revalidate(ctx, p); err == nil {
				b, _ := json.Marshal(p)
				t.Fatalf("client-simulated %s admitted: %s", name, b)
			}
		})
	}
}
