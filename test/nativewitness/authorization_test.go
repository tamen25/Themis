package nativewitness_test

import (
	"path/filepath"
	"testing"

	adapter "github.com/tamen25/themis/internal/dependencyexperiment"
	"github.com/tamen25/themis/internal/localstate"
)

func TestOwnedKindEffectiveNativeWitnessAuthorization(t *testing.T) {
	h := newHarness(t)
	var owner adapter.Owner
	if localstate.Read(filepath.Join(h.state, "witness", "owner.json"), &owner) != nil {
		t.Fatal("protected witness principal missing")
	}
	query := func(label string, want int, args ...string) {
		t.Helper()
		prefix := []string{"--kubeconfig", filepath.Join(h.state, "witness", "kubeconfig"), "--context", "kind-" + owner.ClusterName, "auth", "can-i"}
		h.external(label, "kubectl", want, append(prefix, args...)...)
	}
	for _, target := range []string{"namespace/kube-system", "namespace/" + owner.Namespace} {
		query("named-namespace-identity", 0, "get", target)
	}
	for _, role := range []string{"application", "proxy", "dependency"} {
		query("named-deployment", 0, "get", "deployments.apps/native-"+role, "-n", owner.Namespace)
		query("named-pod", 0, "get", "pods/"+owner.Pods[role], "-n", owner.Namespace)
		query("named-forward", 0, "create", "pods/"+owner.Pods[role], "--subresource=portforward", "-n", owner.Namespace)
	}
	for _, bad := range []struct {
		label string
		args  []string
	}{{"secrets", []string{"get", "secrets"}}, {"broad-list", []string{"list", "pods"}}, {"broad-watch", []string{"watch", "pods"}}, {"unrelated-pod", []string{"get", "pods/unrelated"}}, {"delete-pod", []string{"delete", "pods/" + owner.Pods["proxy"]}}, {"patch-workload", []string{"patch", "deployments.apps/native-proxy"}}, {"create-job", []string{"create", "jobs.batch"}}, {"create-pod", []string{"create", "pods"}}, {"exec", []string{"create", "pods/" + owner.Pods["proxy"], "--subresource=exec"}}, {"rbac-read", []string{"get", "roles.rbac.authorization.k8s.io"}}} {
		query(bad.label, 1, append(bad.args, "-n", owner.Namespace)...)
	}
	query("other-namespace", 1, "get", "namespace/default")
	t.Log("REAL API dedicated native-witness principal: 11 named reads/forwards allowed, 11 broad-read/mutation/exec/Secret/other-namespace operations denied")
}
