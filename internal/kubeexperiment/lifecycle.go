package kubeexperiment

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/localstate"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const InventoryVersion = "themis.kubernetes-execution-inventory/v1alpha2"
const ActionVersion = "themis.kubernetes-experiment-action/v1alpha1"

var errCancelled = errors.New("durable cancellation accepted")
var ErrReceiptPublication = errors.New("cleanup receipt publication failed")

type Action struct {
	Version          string    `json:"version"`
	ID               string    `json:"id"`
	Kind             string    `json:"kind"`
	PlanDigest       string    `json:"planDigest"`
	InvocationID     string    `json:"invocationID"`
	RequestedAt      time.Time `json:"requestedAt"`
	AlreadyFinalized bool      `json:"alreadyFinalized"`
}

func loadInventory(dir string) (inventory, error) {
	var inv inventory
	if err := localstate.Read(filepath.Join(dir, "inventory.json"), &inv); err != nil {
		return inv, err
	}
	if (inv.Version != InventoryVersion && inv.Version != "themis.kubernetes-execution-inventory/v1alpha1") || inv.Plan.Validate() != nil || !reflect.DeepEqual(inv.Plan, inv.Authorization.Grant.Plan) || inv.Authorization.Grant.PlanDigest != inv.Plan.Digest() || inv.Authorization.CheckKeys() != nil {
		return inv, kubefault.ErrDenied
	}
	if inv.Version == InventoryVersion && (!filepath.IsAbs(inv.StateDirectory) || filepath.Base(filepath.Clean(dir)) != "run-"+inv.Authorization.Grant.InvocationID) {
		return inv, kubefault.ErrDenied
	}
	return inv, nil
}

// OpenRun loads protected configuration without requiring the API to be up.
// Each subsequent control connection authenticates the exact environment again.
func OpenRun(ctx context.Context, dir, state string) (*Cluster, error) {
	inv, err := loadInventory(dir)
	if err != nil {
		return nil, err
	}
	if inv.StateDirectory != "" {
		if state != "" {
			absolute, err := filepath.Abs(state)
			if err != nil || absolute != inv.StateDirectory {
				return nil, kubefault.ErrDenied
			}
		}
		state = inv.StateDirectory
	}
	if state == "" {
		state = ".themis/kind-t21"
	}
	c, err := openCluster(ctx, state, false)
	if err != nil {
		return nil, err
	}
	if err = c.validateInventory(inv); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Cluster) validateInventory(inv inventory) error {
	g := inv.Authorization.Grant
	// Verify the original signature at issuance, without treating expired cleanup
	// authority as fresh. The fixture enforces today's expiry on every command.
	if g.Plan.Target.Fixture.ClusterUID != c.Owner.ClusterUID || g.Plan.Target.Fixture.NamespaceUID != c.Owner.NamespaceUID || g.Plan.Target.DeploymentUID != c.Owner.DeploymentUID || !kubefault.VerifyGrant(g, c.Owner.ApproverKey, inv.Plan.Target.Fixture, c.Owner.Operator, g.IssuedAt, false) {
		return kubefault.ErrDenied
	}
	return nil
}

func lifecycleLock(ctx context.Context, dir string) (*localstate.Lock, error) {
	l, err := localstate.OpenLock(filepath.Join(dir, "lifecycle.lock"), true)
	if err != nil {
		return nil, err
	}
	if err = l.Acquire(ctx); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

func stopRequested(dir string, inv inventory) (*Action, error) {
	var a Action
	err := localstate.Read(filepath.Join(dir, "stop-request.json"), &a)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if a.Version != ActionVersion || a.Kind != "cancel" || a.AlreadyFinalized || a.PlanDigest != inv.Plan.Digest() || a.InvocationID != inv.Authorization.Grant.InvocationID || !validID(a.ID) || a.RequestedAt.IsZero() {
		return nil, kubefault.ErrDenied
	}
	return &a, nil
}

func acceptedStop(dir string, inv inventory) error {
	a, err := stopRequested(dir, inv)
	if err != nil {
		return err
	}
	if a != nil {
		return errCancelled
	}
	return nil
}

// Cleanup targets the original identity, even if a run or Deployment generation
// changed. It never resolves a new target or relaxes Pod/container/boot checks.
func (c *Cluster) checkOriginal(ctx context.Context, p kubefault.Plan) error {
	if p.Validate() != nil || p.Operator != c.Owner.Operator || p.Target.DeploymentUID != c.Owner.DeploymentUID {
		return kubefault.ErrDenied
	}
	if err := c.CheckEnvironment(ctx); err != nil {
		return err
	}
	pod, rs, dep := &corev1.Pod{}, &appsv1.ReplicaSet{}, &appsv1.Deployment{}
	for _, read := range []struct {
		name   string
		object client.Object
	}{{p.Target.Fixture.PodName, pod}, {p.Target.ReplicaSetName, rs}, {p.Target.DeploymentName, dep}} {
		if err := c.Reader.Get(ctx, client.ObjectKey{Namespace: p.Target.Namespace, Name: read.name}, read.object); err != nil {
			return err
		}
	}
	owner, parent := metav1.GetControllerOf(pod), metav1.GetControllerOf(rs)
	if string(pod.UID) != p.Target.Fixture.PodUID || !pod.DeletionTimestamp.IsZero() || string(rs.UID) != p.Target.ReplicaSetUID || string(dep.UID) != p.Target.DeploymentUID || owner == nil || string(owner.UID) != p.Target.ReplicaSetUID || owner.Name != rs.Name || owner.Kind != "ReplicaSet" || parent == nil || parent.UID != dep.UID || parent.Name != dep.Name || parent.Kind != "Deployment" || kubefault.Digest("themis.kubernetes-pod-spec/v1alpha1", pod.Spec) != p.Target.PodSpecDigest || len(pod.Status.ContainerStatuses) != 1 || pod.Status.ContainerStatuses[0].ContainerID != p.Target.ContainerID || pod.Status.ContainerStatuses[0].ImageID != p.Target.ImageID {
		return kubefault.ErrDenied
	}
	return nil
}

func (c *Cluster) connectOriginal(ctx context.Context, p kubefault.Plan) (*Session, error) {
	if err := c.checkOriginal(ctx, p); err != nil {
		return nil, err
	}
	s, err := c.forward(ctx, p.Target.Fixture.PodName)
	if err != nil {
		return nil, err
	}
	if _, err = s.Client.Resolve(ctx, &p.Target.Fixture); err == nil {
		err = c.checkOriginal(ctx, p)
	}
	if err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}
