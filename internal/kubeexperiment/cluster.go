// Package kubeexperiment runs only the preinstalled owned-Kind fixture. The
// T2.0 controller and local experiment implementation remain independent.
package kubeexperiment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/tamen25/themis/internal/kube"
	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
	appsv1 "k8s.io/api/apps/v1"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Ownership struct {
	Version        string          `json:"version"`
	ClusterName    string          `json:"clusterName"`
	Context        string          `json:"context"`
	ClusterUID     string          `json:"clusterUID"`
	NamespaceUID   string          `json:"namespaceUID"`
	Operator       kubefault.Actor `json:"operator"`
	ApproverKey    string          `json:"approverKey"`
	DeploymentUID  string          `json:"deploymentUID"`
	FixtureImage   string          `json:"fixtureImage"`
	FixtureImageID string          `json:"fixtureImageID"`
}

type Cluster struct {
	Owner          Ownership
	StateDirectory string
	Reader         client.Client
	config         *rest.Config
	// Tests may replace only transport creation; admission still uses Reader.
	forwardPod func(context.Context, string) (*Session, error)
}

func Open(ctx context.Context, stateDirectory string) (*Cluster, error) {
	return openCluster(ctx, stateDirectory, true)
}

func openCluster(ctx context.Context, stateDirectory string, check bool) (*Cluster, error) {
	var owner Ownership
	if err := localstate.Read(filepath.Join(stateDirectory, "execution-owner.json"), &owner); err != nil {
		return nil, err
	}
	if owner.Version != "themis.kind-ownership/t2.1-v1" || owner.ClusterName != "themis-t21" || owner.Context != "kind-themis-t21" || owner.Operator.Name != kubefault.OperatorName || owner.ClusterUID == "" || owner.NamespaceUID == "" || owner.DeploymentUID == "" || owner.FixtureImageID == "" {
		return nil, kubefault.ErrDenied
	}
	path := filepath.Join(stateDirectory, "operator-kubeconfig")
	if err := localstate.Check(path); err != nil {
		return nil, err
	}
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(&clientcmd.ClientConfigLoadingRules{ExplicitPath: path}, &clientcmd.ConfigOverrides{CurrentContext: owner.Context}).ClientConfig()
	if err != nil {
		return nil, errors.New("explicit owned Kind operator credentials unavailable")
	}
	u, err := url.Parse(config.Host)
	if err != nil || u.Scheme != "https" || u.Hostname() != "127.0.0.1" || u.Port() == "" || config.TLSClientConfig.Insecure || config.ExecProvider != nil || config.AuthProvider != nil || config.Impersonate.UserName != "" || config.Impersonate.UID != "" || len(config.Impersonate.Groups) != 0 || len(config.Impersonate.Extra) != 0 || config.Username != "" || config.Password != "" {
		return nil, kubefault.ErrDenied
	}
	config.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	config.Timeout, config.QPS, config.Burst = 5*time.Second, 10, 20
	scheme := runtime.NewScheme()
	if err = corev1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err = appsv1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err = authv1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	c, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		return nil, err
	}
	cluster := &Cluster{Owner: owner, StateDirectory: stateDirectory, Reader: c, config: config}
	if check {
		if err = cluster.CheckEnvironment(ctx); err != nil {
			return nil, err
		}
	}
	return cluster, nil
}

func (c *Cluster) CheckEnvironment(ctx context.Context) error {
	policy, err := kube.NewPolicy(kube.Namespace, types.UID(c.Owner.ClusterUID), types.UID(c.Owner.NamespaceUID))
	if err != nil {
		return kubefault.ErrDenied
	}
	cluster, namespace := &corev1.Namespace{}, &corev1.Namespace{}
	if err = c.Reader.Get(ctx, client.ObjectKey{Name: "kube-system"}, cluster); err != nil {
		return errors.New("pinned cluster identity unavailable")
	}
	if err = c.Reader.Get(ctx, client.ObjectKey{Name: kube.Namespace}, namespace); err != nil {
		return errors.New("pinned namespace identity unavailable")
	}
	if !policy.CheckEnvironment(cluster, namespace) {
		return kubefault.ErrDenied
	}
	review := &authv1.SelfSubjectReview{}
	if err = c.Reader.Create(ctx, review); err != nil {
		return errors.New("authenticated operator context unavailable")
	}
	if review.Status.UserInfo.Username != c.Owner.Operator.Name || review.Status.UserInfo.UID != c.Owner.Operator.UID {
		return kubefault.ErrDenied
	}
	return nil
}

func (c *Cluster) resolve(ctx context.Context, runName string) (kubefault.Plan, error) {
	if err := c.CheckEnvironment(ctx); err != nil {
		return kubefault.Plan{}, err
	}
	run := kube.RunObject()
	if err := c.Reader.Get(ctx, client.ObjectKey{Namespace: kube.Namespace, Name: runName}, run); err != nil {
		return kubefault.Plan{}, errors.New("requested VerificationRun unavailable")
	}
	if !run.GetDeletionTimestamp().IsZero() {
		return kubefault.Plan{}, kubefault.ErrDenied
	}
	for key := range run.Object {
		if key != "apiVersion" && key != "kind" && key != "metadata" && key != "spec" && key != "status" {
			return kubefault.Plan{}, kubefault.ErrDenied
		}
	}
	specBytes, err := json.Marshal(run.Object["spec"])
	if err != nil {
		return kubefault.Plan{}, err
	}
	spec, err := kube.DecodeSpec(specBytes)
	if err != nil || spec.Target.Name != "latency-fixture" || string(spec.Target.UID) != c.Owner.DeploymentUID {
		return kubefault.Plan{}, kubefault.ErrDenied
	}
	deployment := &appsv1.Deployment{}
	if err = c.Reader.Get(ctx, client.ObjectKey{Namespace: kube.Namespace, Name: spec.Target.Name}, deployment); err != nil {
		return kubefault.Plan{}, errors.New("owned fixture workload unavailable")
	}
	cluster, namespace := &corev1.Namespace{}, &corev1.Namespace{}
	if err = c.Reader.Get(ctx, client.ObjectKey{Name: "kube-system"}, cluster); err != nil {
		return kubefault.Plan{}, err
	}
	if err = c.Reader.Get(ctx, client.ObjectKey{Name: kube.Namespace}, namespace); err != nil {
		return kubefault.Plan{}, err
	}
	policy, err := kube.NewPolicy(kube.Namespace, types.UID(c.Owner.ClusterUID), types.UID(c.Owner.NamespaceUID))
	if err != nil {
		return kubefault.Plan{}, err
	}
	preview, code := policy.Compile(run.GetUID(), run.GetGeneration(), spec, cluster, namespace, deployment)
	status := kube.ReadStatus(run)
	snapshot := preview.Snapshot()
	if code != "" || status.Invalidated || status.Phase != "PLANNED" || status.Verdict != result.NotRun || !status.PlanValid || status.PlanDigest != snapshot.Digest || status.Preview == nil || !reflect.DeepEqual(*status.Preview, snapshot) || status.ExecutionAllowed || status.ObservedGeneration != run.GetGeneration() || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 {
		return kubefault.Plan{}, kubefault.ErrDenied
	}
	pods := &corev1.PodList{}
	if err = c.Reader.List(ctx, pods, client.InNamespace(kube.Namespace), client.MatchingLabels{"app": "themis-latency-fixture"}); err != nil {
		return kubefault.Plan{}, errors.New("owned fixture pod unavailable")
	}
	if len(pods.Items) != 1 {
		return kubefault.Plan{}, kubefault.ErrDenied
	}
	pod := &pods.Items[0]
	owner := metav1.GetControllerOf(pod)
	if owner == nil || owner.Kind != "ReplicaSet" || owner.APIVersion != "apps/v1" || !pod.DeletionTimestamp.IsZero() || pod.Status.Phase != corev1.PodRunning || len(pod.Spec.Containers) != 1 || len(pod.Spec.InitContainers) != 0 || len(pod.Spec.EphemeralContainers) != 0 || len(pod.Status.ContainerStatuses) != 1 || pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		return kubefault.Plan{}, kubefault.ErrDenied
	}
	rs := &appsv1.ReplicaSet{}
	if err = c.Reader.Get(ctx, client.ObjectKey{Namespace: kube.Namespace, Name: owner.Name}, rs); err != nil {
		return kubefault.Plan{}, errors.New("fixture ownership chain unavailable")
	}
	parent := metav1.GetControllerOf(rs)
	container := pod.Status.ContainerStatuses[0]
	if rs.UID != owner.UID || parent == nil || parent.UID != deployment.UID || parent.Name != deployment.Name || parent.Kind != "Deployment" || !rs.DeletionTimestamp.IsZero() || !container.Ready || container.State.Running == nil || container.ContainerID == "" || pod.Spec.Containers[0].Image != c.Owner.FixtureImage || deployment.Spec.Template.Spec.Containers[0].Image != c.Owner.FixtureImage {
		return kubefault.Plan{}, kubefault.ErrDenied
	}
	// Containerd may report a platform manifest while the immutable image reference
	// names its OCI index. Trusted setup pins both instead of conflating the hashes.
	if container.ImageID != c.Owner.FixtureImageID {
		return kubefault.Plan{}, kubefault.ErrDenied
	}
	target := kubefault.Target{Namespace: kube.Namespace, DeploymentName: deployment.Name, DeploymentUID: string(deployment.UID), DeploymentGeneration: deployment.Generation, TemplateDigest: preview.Snapshot().Plan.Target.TemplateDigest, ReplicaSetName: rs.Name, ReplicaSetUID: string(rs.UID), PodSpecDigest: kubefault.Digest("themis.kubernetes-pod-spec/v1alpha1", pod.Spec), ContainerID: container.ContainerID, Image: pod.Spec.Containers[0].Image, ImageID: container.ImageID, Fixture: kubefault.Identity{Version: kubefault.Version, ClusterUID: c.Owner.ClusterUID, NamespaceUID: c.Owner.NamespaceUID, PodName: pod.Name, PodUID: string(pod.UID)}}
	return kubefault.Plan{Version: kubefault.PlanVersion, Policy: kubefault.PolicyVersion, RunName: runName, RunUID: string(run.GetUID()), RunGeneration: run.GetGeneration(), PreviewDigest: preview.Snapshot().Digest, Operator: c.Owner.Operator, Target: target, Contract: kubefault.Contract{Version: "themis.kubernetes-experiment-contract/v1alpha1", Name: "synthetic-latency", Samples: 3, MinConfirmed: 3, MaxErrorFraction: "0"}, Fault: kubefault.Fault{Type: "http.response-latency", DelayMS: 200, DurationMS: 2500}, Scenario: "healthy"}, nil
}

type Session struct {
	Client *kubefault.Client
	stop   chan struct{}
	once   sync.Once
}

func (s *Session) Close() { s.once.Do(func() { close(s.stop); s.Client.Close() }) }

func (c *Cluster) forward(ctx context.Context, podName string) (*Session, error) {
	if c.forwardPod != nil {
		return c.forwardPod(ctx, podName)
	}
	transport, upgrader, err := spdy.RoundTripperFor(c.config)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(c.config.Host)
	if err != nil {
		return nil, err
	}
	u.Path = "/api/v1/namespaces/" + kube.Namespace + "/pods/" + podName + "/portforward"
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport, Timeout: 5 * time.Second}, http.MethodPost, u)
	stop, ready := make(chan struct{}), make(chan struct{})
	pf, err := portforward.NewOnAddresses(dialer, []string{"127.0.0.1"}, []string{"0:8080"}, stop, ready, io.Discard, io.Discard)
	if err != nil {
		return nil, err
	}
	failed := make(chan error, 1)
	go func() { failed <- pf.ForwardPorts() }()
	select {
	case <-ctx.Done():
		close(stop)
		return nil, ctx.Err()
	case <-ready:
	case <-failed:
		close(stop)
		return nil, errors.New("exact Pod port-forward unavailable")
	case <-time.After(6 * time.Second):
		close(stop)
		return nil, errors.New("exact Pod port-forward timed out")
	}
	ports, err := pf.GetPorts()
	if err != nil || len(ports) != 1 {
		close(stop)
		return nil, errors.New("invalid exact Pod port-forward")
	}
	fixture, err := kubefault.NewClient(fmt.Sprintf("http://127.0.0.1:%d", ports[0].Local))
	if err != nil {
		close(stop)
		return nil, err
	}
	s := &Session{Client: fixture, stop: stop}
	go func() {
		select {
		case <-ctx.Done():
			s.Close()
		case <-stop:
		}
	}()
	return s, nil
}

func (c *Cluster) Plan(ctx context.Context, runName, scenario string) (kubefault.Plan, error) {
	p, err := c.resolve(ctx, runName)
	if err != nil {
		return p, err
	}
	s, err := c.forward(ctx, p.Target.Fixture.PodName)
	if err != nil {
		return p, err
	}
	defer s.Close()
	id, err := s.Client.Resolve(ctx, nil)
	if err != nil {
		return p, err
	}
	if id.PodUID != p.Target.Fixture.PodUID || id.PodName != p.Target.Fixture.PodName || id.ClusterUID != c.Owner.ClusterUID || id.NamespaceUID != c.Owner.NamespaceUID {
		return p, kubefault.ErrDenied
	}
	p.Target.Fixture = id
	p.Scenario = scenario
	if err = p.Validate(); err != nil {
		return p, err
	}
	if err = c.Revalidate(ctx, p); err != nil {
		return p, err
	}
	return p, nil
}

func (c *Cluster) Revalidate(ctx context.Context, p kubefault.Plan) error {
	if p.Validate() != nil {
		return kubefault.ErrDenied
	}
	live, err := c.resolve(ctx, p.RunName)
	if err != nil {
		return err
	}
	if live.Target.Fixture.PodUID != p.Target.Fixture.PodUID || live.Target.Fixture.PodName != p.Target.Fixture.PodName || live.Target.Fixture.ClusterUID != p.Target.Fixture.ClusterUID || live.Target.Fixture.NamespaceUID != p.Target.Fixture.NamespaceUID {
		return kubefault.ErrDenied
	}
	live.Target.Fixture = p.Target.Fixture
	live.Scenario = p.Scenario
	live.Fault = p.Fault
	live.Contract = p.Contract
	if !reflect.DeepEqual(live, p) {
		return kubefault.ErrDenied
	}
	return nil
}

func (c *Cluster) Connect(ctx context.Context, p kubefault.Plan) (*Session, error) {
	if err := c.Revalidate(ctx, p); err != nil {
		return nil, err
	}
	s, err := c.forward(ctx, p.Target.Fixture.PodName)
	if err != nil {
		return nil, err
	}
	if _, err = s.Client.Resolve(ctx, &p.Target.Fixture); err != nil {
		s.Close()
		return nil, err
	}
	if err = c.Revalidate(ctx, p); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}
