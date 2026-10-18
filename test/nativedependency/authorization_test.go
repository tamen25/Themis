package nativedependency_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	adapter "github.com/tamen25/themis/internal/dependencyexperiment"
	"github.com/tamen25/themis/internal/localstate"
)

func TestOwnedKindEffectiveRuntimeAuthorization(t *testing.T) {
	h := newHarness(t)
	for _, role := range []string{"runner", "observer"} {
		var owner adapter.Owner
		if localstate.Read(filepath.Join(h.state, role, "owner.json"), &owner) != nil {
			t.Fatal("protected actor identity missing")
		}
		query := func(label string, want int, arguments ...string) {
			t.Helper()
			args := append([]string{"--kubeconfig", filepath.Join(h.state, role, "kubeconfig"), "--context", "kind-" + owner.ClusterName, "auth", "can-i"}, arguments...)
			start := time.Now()
			cmd := exec.Command("rtk", append([]string{"proxy", "kubectl"}, args...)...)
			cmd.Env = append(os.Environ(), "DEBUG=")
			var out, errOut bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &errOut
			e := cmd.Run()
			code := 0
			if e != nil {
				code = cmd.ProcessState.ExitCode()
			}
			h.records = append(h.records, commandRecord{"kubectl", role + "-" + label, args, code, out.String(), errOut.String(), time.Since(start).Milliseconds()})
			h.save("commands.json", h.records)
			if code != want {
				t.Fatalf("%s %s authorization exit %d, wanted %d", role, label, code, want)
			}
		}
		for _, resource := range []string{"namespace/kube-system", "namespace/" + owner.Namespace} {
			query("named-identity-read", 0, "get", resource)
		}
		for _, target := range []string{"application", "proxy", "dependency"} {
			query("named-deployment", 0, "get", "deployments.apps/native-"+target, "-n", owner.Namespace)
			query("named-pod", 0, "get", "pods/"+owner.Pods[target], "-n", owner.Namespace)
			query("named-forward", 0, "create", "pods/"+owner.Pods[target], "--subresource=portforward", "-n", owner.Namespace)
		}
		for _, negative := range []struct {
			label string
			args  []string
		}{{"secret", []string{"get", "secrets"}}, {"list", []string{"list", "pods"}}, {"watch", []string{"watch", "pods"}}, {"unrelated-pod", []string{"get", "pods/unrelated"}}, {"delete", []string{"delete", "pods/" + owner.Pods["proxy"]}}, {"patch", []string{"patch", "deployments.apps/native-proxy"}}, {"job", []string{"create", "jobs.batch"}}, {"pod", []string{"create", "pods"}}, {"exec", []string{"create", "pods/" + owner.Pods["proxy"], "--subresource=exec"}}, {"role", []string{"get", "roles.rbac.authorization.k8s.io"}}} {
			query(negative.label, 1, append(negative.args, "-n", owner.Namespace)...)
		}
		query("other-namespace", 1, "get", "namespace/default")
	}
	t.Log("REAL API effective authorization for both roles: named reads/forward allowed; workload mutation, broad reads, exec, Secrets and other namespace denied")
}
