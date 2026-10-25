// Package ownedtask limits integration-only containerd task controls to the
// original installer-owned local engine, Kind node and exact container identity.
package ownedtask

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/postgres"
)

var hexID = regexp.MustCompile(`^[a-f0-9]{64}$`)
var clusterName = regexp.MustCompile(`^themis-t42-[a-f0-9]{12}$`)
var staticHash = regexp.MustCompile(`^[a-f0-9]{32}$`)

// RuntimeUID retains the distinction between an API mirror Pod's UID and the
// static Pod UID used by CRI. Only the two original local control-plane Pods may
// use the kubelet's immutable mirror/config hash binding.
func RuntimeUID(cluster, namespace, name, node, apiUID string, annotations map[string]string) (string, error) {
	if !clusterName.MatchString(cluster) || node != cluster+"-control-plane" || apiUID == "" {
		return "", errors.New("original API Pod identity required")
	}
	if namespace == "themis-dep-"+strings.TrimPrefix(cluster, "themis-t42-") {
		if annotations["kubernetes.io/config.mirror"] != "" {
			return "", errors.New("workload cannot inherit static Pod identity")
		}
		return apiUID, nil
	}
	if namespace != "kube-system" || (name != "kube-apiserver-"+node && name != "kube-controller-manager-"+node) {
		return "", errors.New("unrelated static Pod denied")
	}
	hash := annotations["kubernetes.io/config.mirror"]
	if annotations["kubernetes.io/config.source"] != "file" || !staticHash.MatchString(hash) || annotations["kubernetes.io/config.hash"] != hash {
		return "", errors.New("original static Pod hash required")
	}
	return hash, nil
}

type Owner struct {
	Endpoint, EngineID, NodeID, ClusterName, Context, ClusterUID, NamespaceUID string
}

// Read checks the private bootstrap rather than deriving authority from Docker
// context selection. Existing installations without these pins must be recreated.
func Read(state, cluster, clusterUID, namespaceUID string) (Owner, error) {
	var fields map[string]json.RawMessage
	if err := localstate.Read(filepath.Join(state, "bootstrap.json"), &fields); err != nil {
		return Owner{}, err
	}
	var version string
	if json.Unmarshal(fields["version"], &version) != nil || version != "themis.native-http-bootstrap/v1alpha1" {
		return Owner{}, errors.New("original installer bootstrap version required")
	}
	var o Owner
	for key, dest := range map[string]*string{"endpoint": &o.Endpoint, "engineID": &o.EngineID, "nodeID": &o.NodeID, "clusterName": &o.ClusterName, "context": &o.Context, "clusterUID": &o.ClusterUID, "namespaceUID": &o.NamespaceUID} {
		if json.Unmarshal(fields[key], dest) != nil {
			return Owner{}, errors.New("complete original Docker ownership required")
		}
	}
	if o.ClusterName != cluster || o.ClusterUID != clusterUID || o.NamespaceUID != namespaceUID {
		return Owner{}, errors.New("original Kubernetes ownership changed")
	}
	return o, o.validate()
}

func (o Owner) validate() error {
	// Use the existing local-engine endpoint policy; no second socket allowlist.
	if err := postgres.ValidateEndpoint(o.Endpoint); err != nil {
		return err
	}
	if !clusterName.MatchString(o.ClusterName) || o.Context != "kind-"+o.ClusterName || !hexID.MatchString(o.NodeID) || len(o.EngineID) < 16 || o.ClusterUID == "" || o.NamespaceUID == "" {
		return errors.New("complete original local engine/node ownership required")
	}
	return nil
}

// Run receives a bounded explicit-host command and a Docker-environment-free
// environment. Tests can substitute a fixed responder to exercise denials.
type Run func(context.Context, []string, []string) ([]byte, error)

type Controller struct {
	Owner    Owner
	Run      Run
	Receipts []Receipt
	pins     map[string]identity
}
type Receipt struct {
	Arguments      []string
	Exit           int
	Stdout, Stderr string
	ElapsedNS      int64
}
type identity struct {
	PodUID string
	PID    int
}

func (c *Controller) command(args ...string) ([]byte, error) {
	if err := c.Owner.validate(); err != nil {
		return nil, err
	}
	if os.Getenv("DOCKER_CONTEXT") != "" {
		return nil, errors.New("ambient Docker context must be empty")
	}
	env := []string{}
	for _, e := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(e), "DOCKER_") {
			env = append(env, e)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	argv := append([]string{"--host", c.Owner.Endpoint}, args...)
	if c.Run != nil {
		return c.Run(ctx, argv, env)
	}
	cmd := exec.CommandContext(ctx, "docker", argv...)
	cmd.Env, cmd.WaitDelay = env, 2*time.Second
	var output, diagnostic boundedOutput
	cmd.Stdout, cmd.Stderr = &output, &diagnostic
	start := time.Now()
	err := cmd.Run()
	code := 0
	if err != nil {
		code = -1
		if cmd.ProcessState != nil {
			code = cmd.ProcessState.ExitCode()
		}
	}
	c.Receipts = append(c.Receipts, Receipt{argv, code, string(output.data), string(diagnostic.data), time.Since(start).Nanoseconds()})
	return output.data, err
}

type boundedOutput struct{ data []byte }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(b.data)+len(p) > 1<<20 {
		return 0, errors.New("Docker diagnostic limit exceeded")
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func (c *Controller) check(id, podUID string) (identity, error) {
	if !hexID.MatchString(id) || podUID == "" {
		return identity{}, errors.New("exact original task and Pod UID required")
	}
	b, err := c.command("info", "--format", "{{json .}}")
	var engine struct{ ID, OSType string }
	if err != nil || json.Unmarshal(b, &engine) != nil || engine.ID != c.Owner.EngineID || engine.OSType != "linux" {
		return identity{}, errors.New("original Linux Docker engine unavailable")
	}
	b, err = c.command("inspect", "--type", "container", c.Owner.NodeID)
	var nodes []struct {
		ID, Name string
		Config   struct{ Labels map[string]string }
	}
	if err != nil || json.Unmarshal(b, &nodes) != nil || len(nodes) != 1 {
		return identity{}, errors.New("original owned node unavailable")
	}
	n := nodes[0]
	if n.ID != c.Owner.NodeID || n.Name != "/"+c.Owner.ClusterName+"-control-plane" || n.Config.Labels["io.x-k8s.kind.cluster"] != c.Owner.ClusterName || n.Config.Labels["io.x-k8s.kind.role"] != "control-plane" {
		return identity{}, errors.New("original owned node changed")
	}
	b, err = c.command("exec", c.Owner.NodeID, "ctr", "-n", "k8s.io", "containers", "info", id)
	var container struct {
		ID     string
		Labels map[string]string
	}
	if err != nil || json.Unmarshal(b, &container) != nil || container.ID != id || container.Labels["io.kubernetes.pod.uid"] != podUID {
		return identity{}, errors.New("original task Pod identity changed")
	}
	b, err = c.command("exec", c.Owner.NodeID, "ctr", "-n", "k8s.io", "tasks", "list")
	if err != nil {
		return identity{}, errors.New("original task unavailable")
	}
	pid := 0
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == id {
			if fields[2] != "RUNNING" && fields[2] != "PAUSED" {
				return identity{}, errors.New("original task is not live")
			}
			if pid != 0 {
				return identity{}, errors.New("ambiguous original task")
			}
			pid, err = strconv.Atoi(fields[1])
			if err != nil || pid <= 0 {
				return identity{}, errors.New("original task PID unavailable")
			}
		}
	}
	if pid == 0 {
		return identity{}, errors.New("original task unavailable")
	}
	return identity{podUID, pid}, nil
}

func (c *Controller) Bind(id, podUID string) error {
	if _, exists := c.pins[id]; exists {
		return errors.New("task already bound")
	}
	p, err := c.check(id, podUID)
	if err != nil {
		return err
	}
	if c.pins == nil {
		c.pins = map[string]identity{}
	}
	c.pins[id] = p
	return nil
}

func (c *Controller) Action(action, id string) error {
	if action != "pause" && action != "resume" && action != "kill" {
		return errors.New("fixed original task operation required")
	}
	p, ok := c.pins[id]
	if !ok {
		return errors.New("task has no original binding")
	}
	current, err := c.check(id, p.PodUID)
	if err != nil {
		return err
	}
	if current != p {
		return errors.New("original task changed")
	}
	args := []string{"exec", c.Owner.NodeID, "ctr", "-n", "k8s.io", "tasks", action}
	if action == "kill" {
		args = append(args, "--signal", "SIGKILL")
	}
	_, err = c.command(append(args, id)...)
	return err
}
