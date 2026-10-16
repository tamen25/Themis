// themis-controller is the experimental Kubernetes dry-run control plane.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/tamen25/themis/internal/kube"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metrics "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func main() {
	if err := run(os.Args[1:]); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("themis-controller", flag.ContinueOnError)
	namespace := flags.String("namespace", "", "required dedicated themis-test namespace")
	clusterUID := flags.String("cluster-uid", "", "trusted kube-system UID from owned Kind setup")
	namespaceUID := flags.String("namespace-uid", "", "trusted themis-test UID from owned Kind setup")
	kubeconfig := flags.String("kubeconfig", "", "explicit dedicated Kind config; empty uses in-cluster identity")
	contextName := flags.String("context", "", "must be kind-themis-t20 when using a file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	policy, err := kube.NewPolicy(*namespace, types.UID(*clusterUID), types.UID(*namespaceUID))
	if err != nil {
		return err
	}
	var config *rest.Config
	if *kubeconfig == "" {
		if *contextName != "" {
			return errors.New("context is only valid with an explicit kubeconfig")
		}
		config, err = rest.InClusterConfig()
	} else {
		if *contextName != "kind-themis-t20" {
			return errors.New("explicit owned kind-themis-t20 context required")
		}
		loading := &clientcmd.ClientConfigLoadingRules{ExplicitPath: *kubeconfig}
		config, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loading, &clientcmd.ConfigOverrides{CurrentContext: *contextName}).ClientConfig()
		if err == nil {
			u, parseErr := url.Parse(config.Host)
			if parseErr != nil || u.Scheme != "https" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" && u.Hostname() != "localhost") {
				return errors.New("out-of-cluster mode requires the explicit local Kind API endpoint")
			}
		}
	}
	if err != nil {
		return errors.New("Kubernetes credentials unavailable; no ambient context is selected")
	}
	if config.ExecProvider != nil || config.AuthProvider != nil || config.TLSClientConfig.Insecure || config.Impersonate.UserName != "" || config.Impersonate.UID != "" || len(config.Impersonate.Groups) != 0 || len(config.Impersonate.Extra) != 0 {
		return errors.New("exec/auth plugins, impersonation and insecure TLS are unsupported")
	}
	config.Timeout, config.QPS, config.Burst = 5*time.Second, 10, 20
	config.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return err
	}
	if err := appsv1.AddToScheme(scheme); err != nil {
		return err
	}
	reader, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	startup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cluster, ns := &corev1.Namespace{}, &corev1.Namespace{}
	if err := reader.Get(startup, client.ObjectKey{Name: "kube-system"}, cluster); err != nil {
		return errors.New("cannot verify pinned cluster identity")
	}
	if err := reader.Get(startup, client.ObjectKey{Name: kube.Namespace}, ns); err != nil {
		return errors.New("cannot verify pinned namespace identity")
	}
	if !policy.CheckEnvironment(cluster, ns) {
		return errors.New("cluster or namespace UID differs from trusted pins; controller not started")
	}
	ctrl.SetLogger(zap.New())
	manager, err := ctrl.NewManager(config, ctrl.Options{Scheme: scheme, Cache: cache.Options{DefaultNamespaces: map[string]cache.Config{kube.Namespace: {}}, ReaderFailOnMissingInformer: true}, LeaderElection: false, Metrics: metrics.Options{BindAddress: "0"}, HealthProbeBindAddress: ":8081"})
	if err != nil {
		return err
	}
	r := &kube.Reconciler{Client: manager.GetClient(), Reader: manager.GetAPIReader(), Policy: policy}
	if err := ctrl.NewControllerManagedBy(manager).For(kube.RunObject()).Complete(r); err != nil {
		return err
	}
	if err := manager.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return err
	}
	if err := manager.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return err
	}
	return manager.Start(ctrl.SetupSignalHandler())
}
