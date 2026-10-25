// Package dependencyexperiment is the concrete owned-Kind native HTTP adapter.
package dependencyexperiment

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	wire "github.com/tamen25/themis/internal/dependencyhttp"
	"github.com/tamen25/themis/internal/localstate"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

type Owner struct {
	Version      string            `json:"version"`
	ClusterName  string            `json:"clusterName"`
	Namespace    string            `json:"namespace"`
	ClusterUID   string            `json:"clusterUID"`
	NamespaceUID string            `json:"namespaceUID"`
	Role         string            `json:"role"`
	Actor        string            `json:"actor"`
	ActorUID     string            `json:"actorUID"`
	Runner       string            `json:"runner"`
	RunnerUID    string            `json:"runnerUID"`
	InstallerKey string            `json:"installerKey"`
	ApproverKey  string            `json:"approverKey"`
	Image        string            `json:"image"`
	Pods         map[string]string `json:"pods"`
	Endpoints    map[string]string `json:"endpoints"`
}
type Cluster struct {
	Owner  Owner
	API    kubernetes.Interface
	config *rest.Config
}

func Open(ctx context.Context, state, role string) (*Cluster, error) {
	var o Owner
	if localstate.Read(filepath.Join(state, "owner.json"), &o) != nil || o.Version != "themis.native-http-owner/v1alpha1" || o.Role != role || !regexp.MustCompile(`^themis-t42-[a-f0-9]{12}$`).MatchString(o.ClusterName) || o.Namespace != "themis-dep-"+o.ClusterName[len("themis-t42-"):] {
		return nil, wire.ErrDenied
	}
	path := filepath.Join(state, "kubeconfig")
	if localstate.Check(path) != nil {
		return nil, wire.ErrDenied
	}
	cfg, e := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(&clientcmd.ClientConfigLoadingRules{ExplicitPath: path}, &clientcmd.ConfigOverrides{CurrentContext: "kind-" + o.ClusterName}).ClientConfig()
	if e != nil {
		return nil, errors.New("explicit owned kubeconfig required")
	}
	u, e := url.Parse(cfg.Host)
	if e != nil || u.Scheme != "https" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || cfg.Insecure || cfg.ExecProvider != nil || cfg.AuthProvider != nil || cfg.Username != "" || cfg.Password != "" || cfg.Impersonate.UserName != "" || cfg.Impersonate.UID != "" || len(cfg.Impersonate.Groups) > 0 || len(cfg.Impersonate.Extra) > 0 {
		return nil, wire.ErrDenied
	}
	cfg.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	cfg.Timeout = time.Second
	cfg.QPS = 30
	cfg.Burst = 40
	api, e := kubernetes.NewForConfig(cfg)
	if e != nil {
		return nil, e
	}
	c := &Cluster{o, api, cfg}
	if e = c.Environment(ctx); e != nil {
		return nil, e
	}
	if role != "installer" {
		if o.Actor != "system:serviceaccount:"+o.Namespace+":native-"+role {
			return nil, wire.ErrDenied
		}
		review, e := api.AuthenticationV1().SelfSubjectReviews().Create(ctx, &auth.SelfSubjectReview{}, metav1.CreateOptions{})
		if e != nil || review.Status.UserInfo.Username != o.Actor || review.Status.UserInfo.UID != o.ActorUID {
			return nil, wire.ErrDenied
		}
	}
	return c, nil
}
func (c *Cluster) Environment(ctx context.Context) error {
	cluster, e := c.API.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if e != nil || string(cluster.UID) != c.Owner.ClusterUID {
		return wire.ErrDenied
	}
	ns, e := c.API.CoreV1().Namespaces().Get(ctx, c.Owner.Namespace, metav1.GetOptions{})
	if e != nil || string(ns.UID) != c.Owner.NamespaceUID || ns.DeletionTimestamp != nil || ns.Labels["themis.dev/native-dependency"] != "owned-synthetic" {
		return wire.ErrDenied
	}
	return nil
}

type Connection struct {
	Base   string
	Client *http.Client
	stop   chan struct{}
	once   sync.Once
}

// Data connections are pinned installer-owned loopback NodePort mappings. Once
// checked, they remain usable while the owned API is paused. The final actuator
// checks the approved boot key and Pod identity; a Service replacement gets no grant.
func (c *Cluster) Data(role string) (*Connection, error) {
	endpoint := c.Owner.Endpoints[role]
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, wire.ErrDenied
	}
	return &Connection{Base: endpoint, Client: wire.HTTPClient(), stop: make(chan struct{})}, nil
}

func (c *Connection) Close() { c.once.Do(func() { close(c.stop); c.Client.CloseIdleConnections() }) }
func (c *Cluster) Forward(ctx context.Context, pod string) (*Connection, error) {
	transport, upgrader, e := spdy.RoundTripperFor(c.config)
	if e != nil {
		return nil, e
	}
	endpoint, e := url.Parse(c.config.Host)
	if e != nil {
		return nil, e
	}
	endpoint.Path = "/api/v1/namespaces/" + c.Owner.Namespace + "/pods/" + pod + "/portforward"
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport, Timeout: time.Second}, "POST", endpoint)
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
		return nil, errors.New("exact Pod forwarding unavailable")
	case <-time.After(2 * time.Second):
		close(stop)
		return nil, errors.New("forward deadline")
	case <-ready:
	}
	ports, e := pf.GetPorts()
	if e != nil || len(ports) != 1 {
		close(stop)
		return nil, wire.ErrDenied
	}
	conn := &Connection{Base: fmt.Sprintf("http://127.0.0.1:%d", ports[0].Local), Client: wire.HTTPClient(), stop: stop}
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-stop:
		}
	}()
	return conn, nil
}
func (c *Cluster) resolve(ctx context.Context, role, podName string) (wire.Workload, string, error) {
	var w wire.Workload
	d, e := c.API.AppsV1().Deployments(c.Owner.Namespace).Get(ctx, "native-"+role, metav1.GetOptions{})
	if e != nil {
		return w, "", wire.ErrDenied
	}
	p, e := c.API.CoreV1().Pods(c.Owner.Namespace).Get(ctx, podName, metav1.GetOptions{})
	if e != nil {
		return w, "", wire.ErrDenied
	}
	parent := metav1.GetControllerOf(p)
	if parent == nil || parent.Kind != "ReplicaSet" || parent.APIVersion != "apps/v1" {
		return w, "", wire.ErrDenied
	}
	rs, e := c.API.AppsV1().ReplicaSets(c.Owner.Namespace).Get(ctx, parent.Name, metav1.GetOptions{})
	if e != nil {
		return w, "", wire.ErrDenied
	}
	grand := metav1.GetControllerOf(rs)
	if grand == nil || grand.Kind != "Deployment" || grand.UID != d.UID || parent.UID != rs.UID || d.DeletionTimestamp != nil || rs.DeletionTimestamp != nil || p.DeletionTimestamp != nil || d.Spec.Replicas == nil || *d.Spec.Replicas != 1 || p.Status.Phase != core.PodRunning || len(p.Spec.Containers) != 1 || len(p.Status.ContainerStatuses) != 1 || len(p.Spec.InitContainers) > 0 || len(p.Spec.EphemeralContainers) > 0 || p.Spec.HostNetwork || p.Spec.HostPID || p.Spec.HostIPC || p.Spec.AutomountServiceAccountToken == nil || *p.Spec.AutomountServiceAccountToken {
		return w, "", wire.ErrDenied
	}
	container := p.Spec.Containers[0]
	status := p.Status.ContainerStatuses[0]
	sc := container.SecurityContext
	if !status.Ready || status.State.Running == nil || container.Image != c.Owner.Image || sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation || sc.Privileged != nil && *sc.Privileged || sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
		return w, "", wire.ErrDenied
	}
	for _, v := range p.Spec.Volumes {
		if v.HostPath != nil {
			return w, "", wire.ErrDenied
		}
	}
	conn, e := c.Forward(ctx, podName)
	if e != nil {
		return w, "", e
	}
	defer conn.Close()
	nonce := wire.ID()
	r, e := wire.Fetch(ctx, conn.Client, conn.Base+"/identity?nonce="+nonce)
	if e != nil || !r.Identity.Valid(role) || !r.Verified(r.Identity, nonce, "identity") || r.Code != 200 || r.Identity.ClusterUID != c.Owner.ClusterUID || r.Identity.NamespaceUID != c.Owner.NamespaceUID || r.Identity.PodUID != string(p.UID) {
		return w, "", wire.ErrDenied
	}
	w = wire.Workload{Name: d.Name, DeploymentUID: string(d.UID), Generation: d.Generation, ReplicaSet: rs.Name, ReplicaSetUID: string(rs.UID), Pod: p.Name, ContainerID: status.ContainerID, Image: container.Image, ImageID: status.ImageID, SpecDigest: wire.Hash(p.Spec), Process: r.Identity}
	if !w.Valid(role) || !wire.PrivateIP(p.Status.PodIP) {
		return w, "", wire.ErrDenied
	}
	return w, p.Status.PodIP, nil
}
func (c *Cluster) Resolve(ctx context.Context) (wire.Target, error) {
	var t wire.Target
	t.Namespace = c.Owner.Namespace
	if e := c.Environment(ctx); e != nil {
		return t, e
	}
	var e error
	t.Application, t.ApplicationIP, e = c.resolve(ctx, "application", c.Owner.Pods["application"])
	if e != nil {
		return t, e
	}
	t.Proxy, _, e = c.resolve(ctx, "proxy", c.Owner.Pods["proxy"])
	if e != nil {
		return t, e
	}
	t.Dependency, t.DependencyIP, e = c.resolve(ctx, "dependency", c.Owner.Pods["dependency"])
	return t, e
}
func (c *Cluster) Check(ctx context.Context, t wire.Target) error {
	if !t.Valid() || t.Namespace != c.Owner.Namespace {
		return wire.ErrDenied
	}
	if e := c.Environment(ctx); e != nil {
		return e
	}
	for _, item := range []struct {
		role string
		w    wire.Workload
		ip   string
	}{{"application", t.Application, t.ApplicationIP}, {"proxy", t.Proxy, ""}, {"dependency", t.Dependency, t.DependencyIP}} {
		actual, ip, e := c.resolve(ctx, item.role, item.w.Pod)
		if e != nil || wire.Hash(actual) != wire.Hash(item.w) || (item.ip != "" && item.ip != ip) {
			return wire.ErrDenied
		}
	}
	return nil
}
