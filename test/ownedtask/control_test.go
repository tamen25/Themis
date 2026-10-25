package ownedtask

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tamen25/themis/internal/localstate"
)

func fixture(t *testing.T) (*Controller, *string, *bool) {
	t.Helper()
	t.Setenv("DOCKER_CONTEXT", "")
	t.Setenv("DOCKER_HOST", "tcp://ambient.example:2375")
	endpoint := "unix:///var/run/docker.sock"
	if runtime.GOOS == "windows" {
		endpoint = "npipe:////./pipe/dockerDesktopLinuxEngine"
	}
	o := Owner{endpoint, "original-engine-identity", strings.Repeat("a", 64), "themis-t42-0123456789ab", "kind-themis-t42-0123456789ab", "original-cluster-uid", "original-namespace-uid"}
	failure := ""
	mutated := false
	c := &Controller{Owner: o}
	c.Run = func(ctx context.Context, args, env []string) ([]byte, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded Docker operation")
		}
		if args[0] != "--host" || args[1] != endpoint {
			t.Fatal("original explicit host lost", args)
		}
		for _, v := range env {
			if strings.HasPrefix(strings.ToUpper(v), "DOCKER_") {
				t.Fatal("Docker ambient precedence leaked")
			}
		}
		if failure == "lost-connection" {
			return nil, errors.New("connection lost")
		}
		a := args[2:]
		var value any
		switch {
		case a[0] == "info":
			engine := o.EngineID
			if failure == "wrong-engine" {
				engine = "different-engine"
			}
			value = map[string]any{"ID": engine, "OSType": "linux"}
		case a[0] == "inspect":
			node := o.NodeID
			cluster := o.ClusterName
			if failure == "replaced-node" {
				node = strings.Repeat("c", 64)
			}
			if failure == "unrelated-cluster" {
				cluster = "unrelated"
			}
			value = []any{map[string]any{"Id": node, "Name": "/" + o.ClusterName + "-control-plane", "Config": map[string]any{"Labels": map[string]string{"io.x-k8s.kind.cluster": cluster, "io.x-k8s.kind.role": "control-plane"}}}}
		case a[5] == "containers":
			uid := "pod-uid"
			if failure == "changed-task-pod" {
				uid = "replacement-pod"
			}
			value = map[string]any{"ID": strings.Repeat("b", 64), "Labels": map[string]string{"io.kubernetes.pod.uid": uid}}
		case a[5] == "tasks" && a[6] == "list":
			pid := 123
			if failure == "changed-task" {
				pid = 456
			}
			return []byte(fmt.Sprintf("TASK PID STATUS\n%s %d RUNNING\n", strings.Repeat("b", 64), pid)), nil
		default:
			if failure == "restore-failure" {
				return nil, errors.New("resume failed")
			}
			if a[1] != o.NodeID || a[5] != "tasks" || (a[6] != "pause" && a[6] != "resume" && a[6] != "kill") || a[len(a)-1] != strings.Repeat("b", 64) {
				t.Fatal("mutation exceeded exact original task", a)
			}
			mutated = true
			return nil, nil
		}
		return json.Marshal(value)
	}
	return c, &failure, &mutated
}

func TestOriginalEngineNodeAndTaskOnly(t *testing.T) {
	for _, action := range []string{"pause", "resume", "kill"} {
		t.Run(action, func(t *testing.T) {
			c, _, mutated := fixture(t)
			id := strings.Repeat("b", 64)
			if err := c.Bind(id, "pod-uid"); err != nil {
				t.Fatal(err)
			}
			if err := c.Action(action, id); err != nil || !*mutated {
				t.Fatal(err)
			}
		})
	}
}

func TestChangedOrUnavailableOriginalIdentityDeniesMutation(t *testing.T) {
	for _, mode := range []string{"wrong-engine", "wrong-context", "missing-endpoint", "remote-endpoint", "replaced-node", "changed-task", "changed-task-pod", "unrelated-cluster", "context-precedence", "lost-connection"} {
		t.Run(mode, func(t *testing.T) {
			c, failure, mutated := fixture(t)
			id := strings.Repeat("b", 64)
			if err := c.Bind(id, "pod-uid"); err != nil {
				t.Fatal(err)
			}
			*failure = mode
			switch mode {
			case "wrong-context":
				c.Owner.Context = "kind-unrelated"
			case "missing-endpoint":
				c.Owner.Endpoint = ""
			case "remote-endpoint":
				c.Owner.Endpoint = "tcp://127.0.0.1:2375"
			case "context-precedence":
				t.Setenv("DOCKER_CONTEXT", "unrelated")
			}
			if c.Action("pause", id) == nil || *mutated {
				t.Fatal("unsafe original identity accepted")
			}
		})
	}
}

func TestRestoreFailureIsNotReportedAsSuccess(t *testing.T) {
	c, failure, mutated := fixture(t)
	id := strings.Repeat("b", 64)
	if err := c.Bind(id, "pod-uid"); err != nil {
		t.Fatal(err)
	}
	if err := c.Action("pause", id); err != nil || !*mutated {
		t.Fatal(err)
	}
	*failure = "restore-failure"
	*mutated = false
	if c.Action("resume", id) == nil || *mutated {
		t.Fatal("restore failure hidden")
	}
}

func TestUnboundTaskOrOtherOperationDenied(t *testing.T) {
	c, _, mutated := fixture(t)
	if c.Action("resume", strings.Repeat("b", 64)) == nil || c.Action("delete", strings.Repeat("b", 64)) == nil || *mutated {
		t.Fatal("unbound task or operation accepted")
	}
}

func TestPrivateOriginalInstallerRecordRequired(t *testing.T) {
	for _, mode := range []string{"original", "wrong-cluster", "wrong-uid", "missing-endpoint", "wrong-context"} {
		t.Run(mode, func(t *testing.T) {
			c, _, _ := fixture(t)
			o := c.Owner
			dir, err := localstate.CreateDirectory(filepath.Join(t.TempDir(), "owner"))
			if err != nil {
				t.Fatal(err)
			}
			fields := map[string]string{"version": "themis.native-http-bootstrap/v1alpha1", "endpoint": o.Endpoint, "engineID": o.EngineID, "nodeID": o.NodeID, "context": o.Context, "clusterName": o.ClusterName, "clusterUID": o.ClusterUID, "namespaceUID": o.NamespaceUID}
			switch mode {
			case "wrong-cluster":
				fields["clusterName"] = "themis-t42-aaaaaaaaaaaa"
			case "wrong-uid":
				fields["clusterUID"] = "replacement-cluster"
			case "missing-endpoint":
				delete(fields, "endpoint")
			case "wrong-context":
				fields["context"] = "kind-unrelated"
			}
			if err := localstate.WriteNew(filepath.Join(dir, "bootstrap.json"), fields); err != nil {
				t.Fatal(err)
			}
			got, err := Read(dir, o.ClusterName, o.ClusterUID, o.NamespaceUID)
			if mode == "original" {
				if err != nil || got != o {
					t.Fatal(got, err)
				}
			} else if err == nil {
				t.Fatal("changed ownership accepted")
			}
		})
	}
}
