package chaosmesh

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"time"

	"github.com/tamen25/themis/internal/kube"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
	appsv1 "k8s.io/api/apps/v1"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const PlannerActor = "system:serviceaccount:themis-test:themis-chaosmesh-planner"
const OwnershipVersion = "themis.chaosmesh-owned-kind/v1alpha1"

type Ownership struct {
	Version       string `json:"version"`
	Directory     string `json:"directory"`
	ClusterName   string `json:"clusterName"`
	Context       string `json:"context"`
	ClusterUID    string `json:"clusterUID"`
	NamespaceUID  string `json:"namespaceUID"`
	DeploymentUID string `json:"deploymentUID"`
	Operator      Actor  `json:"operator"`
}

// Cluster retains only Kubernetes reads. The one create during Open is an
// authenticated SelfSubjectReview, never a workload or provider operation.
type Cluster struct {
	reader client.Reader
	owner  Ownership
}

func Open(ctx context.Context, directory string) (*Cluster, error) {
	var owner Ownership
	if err := localstate.Read(filepath.Join(directory, "planning-owner.json"), &owner); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(directory)
	if err != nil || owner.Directory != abs || owner.Version != OwnershipVersion || !kindName.MatchString(owner.ClusterName) || owner.Context != "kind-"+owner.ClusterName || !uuid.MatchString(owner.ClusterUID) || !uuid.MatchString(owner.NamespaceUID) || !uuid.MatchString(owner.DeploymentUID) || owner.Operator.Name != PlannerActor || !uuid.MatchString(owner.Operator.UID) {
		return nil, ErrDenied
	}
	path := filepath.Join(directory, "planner-kubeconfig")
	if err = localstate.Check(path); err != nil {
		return nil, err
	}
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(&clientcmd.ClientConfigLoadingRules{ExplicitPath: path}, &clientcmd.ConfigOverrides{CurrentContext: owner.Context}).ClientConfig()
	if err != nil {
		return nil, ErrDenied
	}
	u, err := url.Parse(config.Host)
	if err != nil || u.Scheme != "https" || u.Hostname() != "127.0.0.1" || u.Port() == "" || config.Insecure || config.ExecProvider != nil || config.AuthProvider != nil || config.Impersonate.UserName != "" || config.Impersonate.UID != "" || len(config.Impersonate.Groups) != 0 || len(config.Impersonate.Extra) != 0 || config.Username != "" || config.Password != "" {
		return nil, ErrDenied
	}
	config.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	config.Timeout, config.QPS, config.Burst = 4*time.Second, 10, 20
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = authv1.AddToScheme(scheme)
	c, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		return nil, err
	}
	review := &authv1.SelfSubjectReview{}
	if err = c.Create(ctx, review); err != nil || review.Status.UserInfo.Username != owner.Operator.Name || review.Status.UserInfo.UID != owner.Operator.UID {
		return nil, ErrDenied
	}
	return &Cluster{c, owner}, nil
}

func (c *Cluster) Resolve(ctx context.Context) (Snapshot, error) {
	s := Snapshot{}
	o := c.owner
	policy, err := kube.NewPolicy(kube.Namespace, types.UID(o.ClusterUID), types.UID(o.NamespaceUID))
	if err != nil {
		return s, ErrDenied
	}
	cluster, namespace := &corev1.Namespace{}, &corev1.Namespace{}
	if c.reader.Get(ctx, client.ObjectKey{Name: "kube-system"}, cluster) != nil || c.reader.Get(ctx, client.ObjectKey{Name: kube.Namespace}, namespace) != nil || !policy.CheckEnvironment(cluster, namespace) {
		return s, ErrDenied
	}
	run := kube.RunObject()
	if c.reader.Get(ctx, client.ObjectKey{Namespace: kube.Namespace, Name: "external-latency-request"}, run) != nil || !run.GetDeletionTimestamp().IsZero() {
		return s, ErrDenied
	}
	for key := range run.Object {
		if key != "apiVersion" && key != "kind" && key != "metadata" && key != "spec" && key != "status" {
			return s, ErrDenied
		}
	}
	data, err := json.Marshal(run.Object["spec"])
	if err != nil {
		return s, ErrDenied
	}
	spec, err := kube.DecodeSpec(data)
	if err != nil || spec.Target.Name != "synthetic" || string(spec.Target.UID) != o.DeploymentUID {
		return s, ErrDenied
	}
	deployment := &appsv1.Deployment{}
	if c.reader.Get(ctx, client.ObjectKey{Namespace: kube.Namespace, Name: "synthetic"}, deployment) != nil || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 {
		return s, ErrDenied
	}
	compiled, code := policy.Compile(run.GetUID(), run.GetGeneration(), spec, cluster, namespace, deployment)
	status := kube.ReadStatus(run)
	preview := compiled.Snapshot()
	if code != "" || status.Preview == nil || !reflect.DeepEqual(*status.Preview, preview) || status.PlanDigest != preview.Digest || status.Invalidated || !status.PlanValid || status.ExecutionAllowed || status.Verdict != result.NotRun || status.Phase != "PLANNED" || status.ObservedGeneration != run.GetGeneration() {
		return s, ErrDenied
	}
	pods := &corev1.PodList{}
	if c.reader.List(ctx, pods, client.InNamespace(kube.Namespace), client.MatchingLabels{"app": "themis-synthetic"}) != nil || len(pods.Items) != 1 {
		return s, ErrDenied
	}
	pod := pods.Items[0]
	owner := metav1.GetControllerOf(&pod)
	if owner == nil || owner.Kind != "ReplicaSet" || owner.APIVersion != "apps/v1" || pod.Spec.HostNetwork || pod.Spec.HostPID || pod.Spec.HostIPC || len(pod.Spec.Volumes) != 0 || !pod.DeletionTimestamp.IsZero() || pod.Status.Phase != corev1.PodRunning || len(pod.Spec.Containers) != 1 || len(pod.Spec.InitContainers) != 0 || len(pod.Spec.EphemeralContainers) != 0 || len(pod.Status.ContainerStatuses) != 1 || pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		return s, ErrDenied
	}
	rs := &appsv1.ReplicaSet{}
	if c.reader.Get(ctx, client.ObjectKey{Namespace: kube.Namespace, Name: owner.Name}, rs) != nil {
		return s, ErrDenied
	}
	parent := metav1.GetControllerOf(rs)
	container := pod.Status.ContainerStatuses[0]
	if rs.UID != owner.UID || !rs.DeletionTimestamp.IsZero() || parent == nil || parent.APIVersion != "apps/v1" || parent.Kind != "Deployment" || parent.Name != deployment.Name || parent.UID != deployment.UID || !container.Ready || container.State.Running == nil || len(deployment.Spec.Template.Spec.Containers) != 1 || pod.Spec.Containers[0].Name != "echo" || container.Name != "echo" || pod.Spec.Containers[0].Image != deployment.Spec.Template.Spec.Containers[0].Image {
		return s, ErrDenied
	}
	s = Snapshot{o.ClusterName, o.ClusterUID, o.NamespaceUID, o.Operator, run.GetName(), spec, preview, Target{rs.Name, string(rs.UID), pod.Name, string(pod.UID), digest("themis.chaosmesh-pod-spec/v1alpha1", pod.Spec), container.Name, container.ContainerID, pod.Spec.Containers[0].Image, container.ImageID}}
	return s, nil
}

func (c *Cluster) Revalidate(ctx context.Context, p Plan) error {
	if p.Validate() != nil {
		return ErrDenied
	}
	live, err := c.Resolve(ctx)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(live, p.Document.Snapshot) {
		return ErrDenied
	}
	return nil
}
