package experiment

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tamen25/themis/internal/fixture"
	"github.com/tamen25/themis/internal/localpolicy"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/plan"
)

const ActionVersion = "themis.experiment-action/v1alpha1"

type ActionKind string

const (
	CancelAction  ActionKind = "cancel"
	CleanupAction ActionKind = "cleanup"
	RunnerCleanup ActionKind = "runner"
)

type ActionIntent struct {
	Version          string              `json:"version"`
	ID               string              `json:"id"`
	Kind             ActionKind          `json:"kind"`
	RunID            string              `json:"runID"`
	PlanDigest       string              `json:"planDigest"`
	Handle           fixture.FaultHandle `json:"handle"`
	Actor            localstate.Actor    `json:"actor"`
	RequestedAt      time.Time           `json:"requestedAt"`
	AlreadyFinalized bool                `json:"alreadyFinalized"`
}

func loadInventory(directory string) (Inventory, plan.ExperimentPlan, error) {
	var inventory Inventory
	if err := localstate.Read(filepath.Join(directory, "resources.json"), &inventory); err != nil {
		return inventory, plan.ExperimentPlan{}, fmt.Errorf("protected resource inventory unavailable: %w", err)
	}
	if inventory.Version != Version && inventory.Version != LegacyVersion {
		return inventory, plan.ExperimentPlan{}, errors.New("unsupported resource inventory version")
	}
	p, err := validateManifest(inventory.Manifest, inventory.Manifest.Handle.RunID)
	if err != nil {
		return inventory, p, err
	}
	actor, err := localstate.CurrentActor()
	if err != nil {
		return inventory, p, err
	}
	id := p.Snapshot().Target
	if id.OwnerUID != actor.UID || id.Host != actor.Host {
		return inventory, p, errors.New("resource inventory is owned by another OS user/host")
	}
	if !filepath.IsAbs(inventory.FixtureDirectory) {
		return inventory, p, errors.New("inventory fixture directory must be absolute")
	}
	return inventory, p, nil
}

func validAction(a ActionIntent, inventory Inventory, p plan.ExperimentPlan) bool {
	return a.Version == ActionVersion && plan.ValidInstanceID(a.ID) && (a.Kind == CancelAction || a.Kind == CleanupAction || a.Kind == RunnerCleanup) && a.RunID == inventory.Manifest.Handle.RunID && a.PlanDigest == p.Digest() && a.Handle == inventory.Manifest.Handle && a.Actor.UID == p.Snapshot().Target.OwnerUID && a.Actor.Host == p.Snapshot().Target.Host && !a.RequestedAt.IsZero()
}

func stopRequested(directory string, inventory Inventory, p plan.ExperimentPlan) (bool, error) {
	var action ActionIntent
	err := localstate.Read(filepath.Join(directory, "stop-request.json"), &action)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !validAction(action, inventory, p) || action.AlreadyFinalized || action.Kind == RunnerCleanup {
		return false, errors.New("invalid durable stop request")
	}
	return true, nil
}

func lifecycleLock(ctx context.Context, directory string) (*localstate.Lock, error) {
	lock, err := localstate.OpenLock(filepath.Join(directory, "lifecycle.lock"), true)
	if err != nil {
		return nil, err
	}
	if err := lock.Acquire(ctx); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return lock, nil
}

func Reconcile(directory string) (CleanupResult, error) {
	return ReconcileContext(context.Background(), directory)
}
func ReconcileContext(ctx context.Context, directory string) (CleanupResult, error) {
	return reconcile(ctx, directory, CleanupAction, localstate.WriteNew)
}
func Cancel(ctx context.Context, directory string) (CleanupResult, error) {
	return reconcile(ctx, directory, CancelAction, localstate.WriteNew)
}

// Intent/finalization share a short OS lock; the fixture's permanent quiescence
// fence linearizes concurrent Apply/remove/stop. No process PID is acted upon.
func reconcile(ctx context.Context, directory string, kind ActionKind, writeRecord func(string, any) error) (CleanupResult, error) {
	ctx, cancel := context.WithTimeout(ctx, localpolicy.CleanupLimit)
	defer cancel()
	inventory, p, err := loadInventory(directory)
	if err != nil {
		return CleanupResult{}, err
	}
	actor, err := localstate.CurrentActor()
	if err != nil {
		return CleanupResult{}, err
	}
	lock, err := lifecycleLock(ctx, directory)
	if err != nil {
		return CleanupResult{}, fmt.Errorf("lifecycle coordination unavailable; independent expiry remains active: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = lock.Close()
		}
	}()
	inspection := inspectJournalFile(filepath.Join(directory, "events.jsonl"))
	finalized := inspection.Integrity == JournalComplete && inspection.LastState == Finalized && inspection.scan.Manifest.Handle == inventory.Manifest.Handle && inspection.scan.Plan.Digest() == p.Digest()
	action := ActionIntent{Version: ActionVersion, ID: localstate.RandomID(), Kind: kind, RunID: inventory.Manifest.Handle.RunID, PlanDigest: p.Digest(), Handle: inventory.Manifest.Handle, Actor: actor, RequestedAt: time.Now().UTC(), AlreadyFinalized: finalized}
	if err := writeRecord(filepath.Join(directory, "action-"+action.ID+".json"), action); err != nil {
		return CleanupResult{}, fmt.Errorf("cannot persist %s intent; no control action attempted: %w", kind, err)
	}
	if !finalized {
		requested, err := stopRequested(directory, inventory, p)
		if err != nil {
			return CleanupResult{}, err
		}
		if !requested {
			if err := writeRecord(filepath.Join(directory, "stop-request.json"), action); err != nil {
				return CleanupResult{}, fmt.Errorf("cannot persist stop request; no control action attempted: %w", err)
			}
		}
	}
	if err := lock.Close(); err != nil {
		return CleanupResult{}, err
	}
	closed = true
	var client *fixture.Client
	c, openErr := fixture.Open(inventory.FixtureDirectory)
	if openErr == nil {
		if c.Identity != p.Snapshot().Target {
			c.Close()
			return CleanupResult{}, errors.New("cleanup inventory fixture identity mismatch")
		}
		client = c
		defer c.Close()
	}
	r := cleanupResources(ctx, p.Snapshot().Target, client, inventory.Manifest.Handle, string(kind))
	r.ActionID = action.ID
	r.Kind = kind
	r.PlanDigest = p.Digest()
	r.FixtureID = p.Snapshot().Target.InstanceID
	r.FaultID = inventory.Manifest.Handle.FaultID
	return persistCleanup(directory, r, writeRecord)
}

func persistCleanup(directory string, r CleanupResult, writeRecord func(string, any) error) (CleanupResult, error) {
	if r.ActionID == "" {
		r.ActionID = localstate.RandomID()
	}
	if r.Completed {
		r.Disposition = Cleaned
	} else {
		r.Disposition = Pending
	}
	if err := writeRecord(filepath.Join(directory, "cleanup-"+r.ActionID+".json"), r); err != nil {
		r.ReceiptPersisted = boolean(false)
		r.Disposition = Pending
		r.Failure = &Failure{Operation: OpReceipt, Code: "CLEANUP_RECEIPT_WRITE_FAILED", Reason: "cleanup observations could not be durably recorded; retry reconciliation"}
		return r, fmt.Errorf("cleanup receipt persistence failed: %w", err)
	}
	r.ReceiptPersisted = boolean(true)
	return r, nil
}
