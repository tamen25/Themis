package kubeexperiment

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/localstate"
)

func (c *Cluster) Cancel(ctx context.Context, dir string) (CleanupReceipt, error) {
	return c.action(ctx, dir, "cancel", writePrivate)
}

func (c *Cluster) Reconcile(ctx context.Context, dir string) (CleanupReceipt, error) {
	return c.action(ctx, dir, "reconcile", writePrivate)
}

func (c *Cluster) action(ctx context.Context, dir, kind string, write func(string, any) error) (CleanupReceipt, error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	inv, err := loadInventory(dir)
	if err != nil {
		return CleanupReceipt{}, err
	}
	if err = c.validateInventory(inv); err != nil {
		return CleanupReceipt{}, err
	}
	// Legacy runners did not participate in this protocol. Their completed/dead
	// executions can be cleaned, but concurrent cancellation is refused honestly.
	if inv.Version != InventoryVersion || kind == "reconcile" {
		live, err := localstate.OpenLock(filepath.Join(dir, "runner.lock"), false)
		if err != nil {
			return CleanupReceipt{}, err
		}
		defer live.Close()
		held, err := live.Try()
		if err != nil || !held {
			return CleanupReceipt{}, errors.New("runner is active; use cancel for a T2.2 execution")
		}
	}
	gate, err := lifecycleLock(ctx, dir)
	if err != nil {
		return CleanupReceipt{}, err
	}
	closed := false
	defer func() {
		if !closed {
			_ = gate.Close()
		}
	}()
	finalized := false
	if events, readErr := ReadJournal(filepath.Join(dir, "events.jsonl")); readErr == nil {
		first, last := events[0], events[len(events)-1]
		finalized = first.Plan.Digest() == inv.Plan.Digest() && first.Authorization.InvocationID == inv.Authorization.Grant.InvocationID && last.Type == "FINAL"
	}
	a := Action{Version: ActionVersion, ID: kubefault.RandomID(), Kind: kind, PlanDigest: inv.Plan.Digest(), InvocationID: inv.Authorization.Grant.InvocationID, RequestedAt: time.Now().UTC(), AlreadyFinalized: finalized}
	if err = write(filepath.Join(dir, "action-"+a.ID+".json"), a); err != nil {
		return CleanupReceipt{}, err
	}
	if kind == "cancel" && !finalized {
		stop, err := stopRequested(dir, inv)
		if err != nil {
			return CleanupReceipt{}, err
		}
		if stop == nil {
			if err = write(filepath.Join(dir, "stop-request.json"), a); err != nil {
				return CleanupReceipt{}, err
			}
		}
	}
	if err = gate.Close(); err != nil {
		return CleanupReceipt{}, err
	}
	closed = true
	r := c.cleanupOriginal(ctx, inv, a)
	// Observed inactivity and durable publication are separate facts. Publication
	// failure never returns operational success, even with a signed inactive reply.
	persisted := true
	r.ReceiptPersisted = &persisted
	if err = write(filepath.Join(dir, "cleanup-"+a.ID+".json"), r); err != nil {
		persisted = false
		r.OperationalState, r.Failure = "CLEANUP_PENDING", "CleanupReceiptPublicationFailed"
		return r, ErrReceiptPublication
	}
	return r, nil
}

func (c *Cluster) cleanupOriginal(ctx context.Context, inv inventory, a Action) CleanupReceipt {
	r := CleanupReceipt{Version: "themis.kubernetes-cleanup-receipt/v1alpha2", PlanDigest: a.PlanDigest, InvocationID: a.InvocationID, At: time.Now().UTC(), CurrentState: "UNKNOWN", OperationalState: "CLEANUP_PENDING", HistoricalVerdictUnchanged: true, Action: &a}
	s, connectErr := c.connectOriginal(ctx, inv.Plan)
	if connectErr != nil {
		r.CurrentState, r.Failure = "TARGET_UNAVAILABLE_OR_REPLACED", "OriginalTargetUnavailable"
	} else {
		defer s.Close()
		status, removeErr := s.Client.Control(ctx, inv.Authorization, "remove")
		if removeErr == nil && !status.Active && status.InvocationID == a.InvocationID && c.checkOriginal(ctx, inv.Plan) == nil {
			r.Status, r.CurrentState, r.OperationalState = &status, "INACTIVE", "CLEANUP_COMPLETE"
			r.FixtureApplyFenceConfirmed = true
			epoch := time.Now()
			for i := 0; i < inv.Plan.Contract.Samples; i++ {
				r.Recovery = append(r.Recovery, observe(ctx, s.Client, epoch, "recovery", i))
			}
			complete, good, _ := complete(inv.Plan, a.InvocationID, "recovery", r.Recovery)
			r.RecoveryVerified = complete && good
		} else {
			r.Failure = "CleanupNotConfirmed"
		}
	}
	return r
}
