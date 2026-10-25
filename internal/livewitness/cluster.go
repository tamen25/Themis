package livewitness

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
	"regexp"
	"sync"
	"time"

	"github.com/tamen25/themis/internal/kube"
	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/localstate"
	apps "k8s.io/api/apps/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const WitnessActor = "system:serviceaccount:themis-test:themis-witness"

type Owner struct {
	Version       string          `json:"version"`
	ClusterName   string          `json:"clusterName"`
	Context       string          `json:"context"`
	ClusterUID    string          `json:"clusterUID"`
	NamespaceUID  string          `json:"namespaceUID"`
	Actor         kubefault.Actor `json:"actor"`
	DeploymentUID string          `json:"deploymentUID"`
}
type target struct {
	owner  Owner
	reader client.Client
	config *rest.Config
}

func openTarget(ctx context.Context, state string, p kubefault.Plan) (*target, error) {
	var owner Owner
	if localstate.Read(filepath.Join(state, "witness-owner.json"), &owner) != nil || owner.Version != "themis.kind-witness-owner/v1alpha1" || !regexp.MustCompile(`^themis-t41-[a-f0-9]{12}$`).MatchString(owner.ClusterName) || owner.Context != "kind-"+owner.ClusterName || owner.Actor.Name != WitnessActor || owner.Actor.UID == "" || owner.ClusterUID != p.Target.Fixture.ClusterUID || owner.NamespaceUID != p.Target.Fixture.NamespaceUID || owner.DeploymentUID != p.Target.DeploymentUID {
		return nil, errors.New("owned witness identity denied")
	}
	path := filepath.Join(state, "witness-kubeconfig")
	if localstate.Check(path) != nil {
		return nil, errors.New("protected witness credentials required")
	}
	cfg, e := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(&clientcmd.ClientConfigLoadingRules{ExplicitPath: path}, &clientcmd.ConfigOverrides{CurrentContext: owner.Context}).ClientConfig()
	if e != nil {
		return nil, errors.New("explicit witness kubeconfig unavailable")
	}
	endpoint, e := url.Parse(cfg.Host)
	if e != nil || endpoint.Scheme != "https" || endpoint.Hostname() != "127.0.0.1" || endpoint.Port() == "" || endpoint.User != nil || endpoint.Path != "" || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || cfg.TLSClientConfig.Insecure || cfg.ExecProvider != nil || cfg.AuthProvider != nil || cfg.Username != "" || cfg.Password != "" || cfg.Impersonate.UserName != "" || cfg.Impersonate.UID != "" || len(cfg.Impersonate.Groups) > 0 || len(cfg.Impersonate.Extra) > 0 {
		return nil, errors.New("external or executable witness credentials denied")
	}
	cfg.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	cfg.Timeout = time.Second
	cfg.QPS = 20
	cfg.Burst = 30
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{apps.AddToScheme, core.AddToScheme, auth.AddToScheme} {
		if e = add(scheme); e != nil {
			return nil, e
		}
	}
	reader, e := client.New(cfg, client.Options{Scheme: scheme})
	if e != nil {
		return nil, e
	}
	t := &target{owner, reader, cfg}
	review := &auth.SelfSubjectReview{}
	if e = reader.Create(ctx, review); e != nil || review.Status.UserInfo.Username != owner.Actor.Name || review.Status.UserInfo.UID != owner.Actor.UID {
		return nil, errors.New("witness Kubernetes principal mismatch")
	}
	return t, t.check(ctx, p)
}

// check independently recompiles the preview and exact Pod owner chain. It has
// no broad selectors and issues only the named reads permitted to the witness.
func (t *target) check(ctx context.Context, p kubefault.Plan) error {
	if p.Validate() != nil || p.Target.Fixture.ClusterUID != t.owner.ClusterUID || p.Target.Fixture.NamespaceUID != t.owner.NamespaceUID || p.Target.DeploymentUID != t.owner.DeploymentUID {
		return errors.New("invalid immutable observation plan")
	}
	cluster, namespace := &core.Namespace{}, &core.Namespace{}
	if t.reader.Get(ctx, client.ObjectKey{Name: "kube-system"}, cluster) != nil || t.reader.Get(ctx, client.ObjectKey{Name: kube.Namespace}, namespace) != nil {
		return errors.New("witness cluster identity unavailable")
	}
	policy, e := kube.NewPolicy(kube.Namespace, types.UID(t.owner.ClusterUID), types.UID(t.owner.NamespaceUID))
	if e != nil || !policy.CheckEnvironment(cluster, namespace) {
		return errors.New("witness cluster identity changed")
	}
	deployment, pod, rs := &apps.Deployment{}, &core.Pod{}, &apps.ReplicaSet{}
	run := kube.RunObject()
	for _, item := range []struct {
		object client.Object
		name   string
	}{{deployment, p.Target.DeploymentName}, {pod, p.Target.Fixture.PodName}, {rs, p.Target.ReplicaSetName}, {run, p.RunName}} {
		if t.reader.Get(ctx, client.ObjectKey{Namespace: kube.Namespace, Name: item.name}, item.object) != nil {
			return errors.New("witness pinned target unavailable")
		}
	}
	raw, e := json.Marshal(run.Object["spec"])
	if e != nil {
		return e
	}
	spec, e := kube.DecodeSpec(raw)
	if e != nil {
		return e
	}
	preview, code := policy.Compile(run.GetUID(), run.GetGeneration(), spec, cluster, namespace, deployment)
	status := kube.ReadStatus(run)
	parent := metav1.GetControllerOf(pod)
	grandparent := metav1.GetControllerOf(rs)
	if code != "" || p.PreviewDigest != preview.Snapshot().Digest || status.Invalidated || status.Phase != "PLANNED" || status.Verdict != "NOT_RUN" || !status.PlanValid || status.ExecutionAllowed || status.ObservedGeneration != run.GetGeneration() || status.PlanDigest != p.PreviewDigest || status.Preview == nil || !reflect.DeepEqual(*status.Preview, preview.Snapshot()) || string(run.GetUID()) != p.RunUID || run.GetGeneration() != p.RunGeneration || !run.GetDeletionTimestamp().IsZero() || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 || string(deployment.UID) != p.Target.DeploymentUID || deployment.Generation != p.Target.DeploymentGeneration || !deployment.DeletionTimestamp.IsZero() || string(pod.UID) != p.Target.Fixture.PodUID || !pod.DeletionTimestamp.IsZero() || pod.Status.Phase != core.PodRunning || len(pod.Spec.Containers) != 1 || len(pod.Spec.InitContainers) != 0 || len(pod.Spec.EphemeralContainers) != 0 || pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken || len(pod.Status.ContainerStatuses) != 1 || parent == nil || parent.Kind != "ReplicaSet" || parent.APIVersion != "apps/v1" || parent.Name != rs.Name || string(parent.UID) != p.Target.ReplicaSetUID || parent.UID != rs.UID || !rs.DeletionTimestamp.IsZero() || grandparent == nil || grandparent.Kind != "Deployment" || grandparent.APIVersion != "apps/v1" || grandparent.Name != deployment.Name || grandparent.UID != deployment.UID || kubefault.Digest("themis.kubernetes-pod-spec/v1alpha1", pod.Spec) != p.Target.PodSpecDigest {
		return errors.New("witness target, plan or ownership drift")
	}
	c := pod.Status.ContainerStatuses[0]
	if !c.Ready || c.State.Running == nil || c.ContainerID != p.Target.ContainerID || c.ImageID != p.Target.ImageID || pod.Spec.Containers[0].Image != p.Target.Image {
		return errors.New("witness container identity drift")
	}
	return nil
}

type connection struct {
	client *kubefault.Client
	stop   chan struct{}
	once   sync.Once
}

func (c *connection) Close() { c.once.Do(func() { close(c.stop); c.client.Close() }) }
func (t *target) connect(ctx context.Context, p kubefault.Plan) (*connection, error) {
	transport, upgrader, e := spdy.RoundTripperFor(t.config)
	if e != nil {
		return nil, e
	}
	endpoint, e := url.Parse(t.config.Host)
	if e != nil {
		return nil, e
	}
	endpoint.Path = "/api/v1/namespaces/" + kube.Namespace + "/pods/" + p.Target.Fixture.PodName + "/portforward"
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport, Timeout: time.Second}, http.MethodPost, endpoint)
	stop, ready := make(chan struct{}), make(chan struct{})
	pf, e := portforward.NewOnAddresses(dialer, []string{"127.0.0.1"}, []string{"0:8080"}, stop, ready, io.Discard, io.Discard)
	if e != nil {
		return nil, e
	}
	failed := make(chan error, 1)
	go func() { failed <- pf.ForwardPorts() }()
	select {
	case <-ctx.Done():
		close(stop)
		return nil, ctx.Err()
	case <-failed:
		close(stop)
		return nil, errors.New("witness exact-Pod forwarding unavailable")
	case <-ready:
	case <-time.After(3 * time.Second):
		close(stop)
		return nil, errors.New("witness forward deadline")
	}
	ports, e := pf.GetPorts()
	if e != nil || len(ports) != 1 {
		close(stop)
		return nil, errors.New("witness port binding invalid")
	}
	data, e := kubefault.NewClient(fmt.Sprintf("http://127.0.0.1:%d", ports[0].Local))
	if e != nil {
		close(stop)
		return nil, e
	}
	c := &connection{client: data, stop: stop}
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
		case <-stop:
		}
	}()
	if _, e = data.Resolve(ctx, &p.Target.Fixture); e != nil {
		c.Close()
		return nil, errors.New("witness fixture boot identity denied")
	}
	return c, nil
}
