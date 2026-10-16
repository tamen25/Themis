package kubeexperiment

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

type inventory struct {
	Version        string                  `json:"version"`
	Plan           kubefault.Plan          `json:"plan"`
	Authorization  kubefault.Authorization `json:"authorization"`
	StateDirectory string                  `json:"stateDirectory,omitempty"`
}

func (c *Cluster) Approve(ctx context.Context, p kubefault.Plan, digest string) (kubefault.Authorization, error) {
	if err := c.Revalidate(ctx, p); err != nil {
		return kubefault.Authorization{}, err
	}
	s, err := c.Connect(ctx, p)
	if err != nil {
		return kubefault.Authorization{}, err
	}
	defer s.Close()
	var signing struct {
		Key string `json:"privateKey"`
	}
	if err = localstate.Read(filepath.Join(c.StateDirectory, "approver-key.json"), &signing); err != nil {
		return kubefault.Authorization{}, err
	}
	key, err := hex.DecodeString(signing.Key)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return kubefault.Authorization{}, kubefault.ErrDenied
	}
	if hex.EncodeToString(ed25519.PrivateKey(key).Public().(ed25519.PublicKey)) != c.Owner.ApproverKey {
		return kubefault.Authorization{}, kubefault.ErrDenied
	}
	return kubefault.Approve(p, digest, key, time.Now())
}

func observe(ctx context.Context, c *kubefault.Client, epoch time.Time, phase string, index int) Observation {
	o := Observation{Phase: phase, Index: index, RequestID: kubefault.RandomID(), Probes: make([]Probe, 3)}
	var group sync.WaitGroup
	for i, kind := range []string{"direct", "proxy", "application"} {
		group.Go(func() {
			p := Probe{Kind: kind, StartedNS: int64(time.Since(epoch))}
			body, code, err := c.Data(ctx, kind, o.RequestID)
			if err == nil {
				p.HTTPCode = code
				p.Response = &body
			}
			p.CompletedNS = int64(time.Since(epoch))
			o.Probes[i] = p
		})
	}
	group.Wait()
	return o
}

func collect(ctx context.Context, c *kubefault.Client, j *journal, p kubefault.Plan, phase string) error {
	typeName := map[string]string{"baseline": "BASELINE", "intervention": "INTERVENTION", "recovery": "RECOVERY"}[phase]
	if err := j.append(Event{Type: typeName}); err != nil {
		return err
	}
	slot := 100 * time.Millisecond
	if phase == "intervention" {
		slot = time.Duration(p.Fault.DelayMS+100) * time.Millisecond
	}
	start := time.Now()
	for i := 0; i < p.Contract.Samples; i++ {
		if j.stop != nil {
			if err := j.stop(); err != nil {
				return err
			}
		}
		timer := time.NewTimer(time.Until(start.Add(time.Duration(i) * slot)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		if time.Since(start.Add(time.Duration(i)*slot)) > slot {
			return errors.New("planned observation slot missed")
		}
		o := observe(ctx, c, j.epoch, phase, i)
		if err := j.append(Event{Type: "OBSERVATION", Observation: &o}); err != nil {
			return err
		}
		if j.stop != nil {
			if err := j.stop(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Cluster) Execute(ctx context.Context, p kubefault.Plan, a kubefault.Authorization, runsDirectory string) (Report, string, error) {
	return c.executeWithStorage(ctx, p, a, runsDirectory, func(path string) (journalFile, error) { return localstate.OpenNew(path) })
}

func (c *Cluster) executeWithStorage(ctx context.Context, p kubefault.Plan, a kubefault.Authorization, runsDirectory string, openJournal func(string) (journalFile, error)) (Report, string, error) {
	if p.Validate() != nil || a.CheckKeys() != nil || !reflect.DeepEqual(p, a.Grant.Plan) || a.Grant.PlanDigest != p.Digest() || !kubefault.VerifyGrant(a.Grant, c.Owner.ApproverKey, p.Target.Fixture, c.Owner.Operator, time.Now(), true) {
		return Report{}, "", kubefault.ErrDenied
	}
	s, err := c.Connect(ctx, p)
	if err != nil {
		return Report{}, "", err
	}
	defer s.Close()
	dir, err := localstate.CreateDirectory(filepath.Join(runsDirectory, "run-"+a.Grant.InvocationID))
	if err != nil {
		return Report{}, "", err
	}
	lock, err := localstate.OpenLock(filepath.Join(dir, "runner.lock"), true)
	if err != nil {
		return Report{}, dir, err
	}
	defer lock.Close()
	if err = lock.Acquire(ctx); err != nil {
		return Report{}, dir, err
	}
	state, err := filepath.Abs(c.StateDirectory)
	if err != nil {
		return Report{}, dir, err
	}
	inv := inventory{Version: InventoryVersion, Plan: p, Authorization: a, StateDirectory: state}
	if err = writePrivate(filepath.Join(dir, "inventory.json"), inv); err != nil {
		return Report{}, dir, err
	}
	file, err := openJournal(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		return Report{}, dir, err
	}
	defer file.Close()
	j := &journal{file: file, epoch: time.Now(), version: LifecycleJournalVersion, stop: func() error { return acceptedStop(dir, inv) }}
	summary := publicAuthorization(a.Grant)
	if err = j.append(Event{Type: "START", Plan: &p, Authorization: &summary}); err != nil {
		return Report{}, dir, err
	}
	// This process holds liveness only. No local actor/lock grants a cluster action.
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	operationErr := collect(ctx, s.Client, j, p, "baseline")
	if operationErr == nil {
		base := []Observation{}
		for _, e := range j.events {
			if e.Observation != nil {
				base = append(base, *e.Observation)
			}
		}
		complete, healthy, _ := complete(p, a.Grant.InvocationID, "baseline", base)
		if !complete || !healthy {
			operationErr = errors.New("baseline measurements did not meet safety prerequisites")
		}
	}
	if operationErr == nil {
		operationErr = c.apply(ctx, dir, inv, s, j)
	}
	if operationErr == nil {
		operationErr = c.Revalidate(ctx, p)
	}
	if operationErr == nil {
		operationErr = collect(ctx, s.Client, j, p, "intervention")
	}
	// Cleanup has its own context. Watchdog expiry does not depend on any I/O here.
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Second)
	status, cleanupErr := s.Client.Control(cleanupCtx, a, "remove")
	if cleanupErr != nil {
		// Parent cancellation may have closed the original forwarding stream.
		// Reconnect only to the inventoried Pod/boot under the cleanup context.
		if cleanupSession, connectErr := c.connectOriginal(cleanupCtx, p); connectErr == nil {
			status, cleanupErr = cleanupSession.Client.Control(cleanupCtx, a, "remove")
			cleanupSession.Close()
		}
	}
	if cleanupErr == nil && status.Active {
		cleanupErr = errors.New("fault still active after Remove")
	}
	if cleanupErr == nil {
		cleanupErr = c.checkOriginal(cleanupCtx, p)
	}
	cleanupCancel()
	if cleanupErr == nil {
		cleanupErr = j.append(Event{Type: "REMOVED", Status: &status})
	}
	if cleanupErr == nil && operationErr == nil {
		operationErr = collect(ctx, s.Client, j, p, "recovery")
	}
	// This short lock orders durable cancellation acceptance against finalization.
	// A filesystem stall can delay acceptance, but cannot extend fixture expiry.
	finalCtx, finalCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer finalCancel()
	gate, gateErr := lifecycleLock(finalCtx, dir)
	if gateErr != nil {
		return assess(j.events, true), dir, gateErr
	}
	defer gate.Close()
	stopErr := acceptedStop(dir, inv)
	if stopErr != nil {
		operationErr = stopErr
	}
	execution := result.Succeeded
	if operationErr != nil {
		execution = result.Error
		_ = j.append(Event{Type: "ABORT", Reason: "ExecutionInterrupted"})
	}
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(operationErr, errCancelled) {
		execution = result.Cancelled
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		execution = result.TimedOut
	}
	if errors.Is(operationErr, errCancelled) {
		action, _ := stopRequested(dir, inv)
		if action != nil {
			_ = j.append(Event{Type: "CANCEL_ACCEPTED", ActionID: action.ID})
		}
	}
	if cleanupErr != nil {
		execution = result.CleanupPending
	}
	terminalErr := j.append(Event{Type: "FINAL", Execution: string(execution)})
	report := assess(j.events, true)
	if terminalErr != nil || j.poisoned || stopErr != nil && !errors.Is(stopErr, errCancelled) {
		report.Execution = result.CleanupPending
		report.Cleanup = "PENDING"
		if report.Verdict == result.Pass {
			report.Verdict = result.Inconclusive
		}
		report.Unknowns = append(report.Unknowns, "journal or lifecycle persistence failed; historical record is incomplete")
	}
	if err = writePrivate(filepath.Join(dir, "report.json"), report); err != nil {
		report.Execution, report.Cleanup = result.CleanupPending, "PENDING"
		if report.Verdict == result.Pass {
			report.Verdict = result.Inconclusive
		}
		return report, dir, err
	}
	if terminalErr != nil {
		return report, dir, terminalErr
	}
	return report, dir, nil
}

func (c *Cluster) apply(ctx context.Context, dir string, inv inventory, s *Session, j *journal) error {
	gate, err := lifecycleLock(ctx, dir)
	if err != nil {
		return err
	}
	defer gate.Close()
	if err = acceptedStop(dir, inv); err != nil {
		return err
	}
	p, a := inv.Plan, inv.Authorization
	operationErr := j.append(Event{Type: "INTENT"})
	if operationErr == nil {
		// Fresh API and exact boot-key checks occur after durable intent and directly
		// before Apply. No journal append or retry occurs between these and Apply.
		operationErr = c.Revalidate(ctx, p)
		if operationErr == nil {
			_, operationErr = s.Client.Resolve(ctx, &p.Target.Fixture)
		}
		if operationErr != nil {
			notAttempted := false
			_ = j.append(Event{Type: "ABORT", Attempted: &notAttempted, Reason: "TargetRevalidationDenied"})
		}
	}
	if operationErr == nil {
		var status kubefault.Status
		status, operationErr = s.Client.Control(ctx, a, "apply")
		if operationErr == nil {
			operationErr = j.append(Event{Type: "APPLIED", Status: &status})
		} else {
			var attempted *bool
			var denied *kubefault.Denial
			if errors.As(operationErr, &denied) {
				v := false
				attempted = &v
			}
			_ = j.append(Event{Type: "ABORT", Attempted: attempted, Reason: "ApplyAcknowledgementUnavailable"})
		}
	}
	return operationErr
}

type CleanupReceipt struct {
	Version                    string            `json:"version"`
	PlanDigest                 string            `json:"planDigest"`
	InvocationID               string            `json:"invocationID"`
	At                         time.Time         `json:"at"`
	CurrentState               string            `json:"currentState"`
	Status                     *kubefault.Status `json:"status,omitempty"`
	Recovery                   []Observation     `json:"recovery"`
	RecoveryVerified           bool              `json:"recoveryVerified"`
	HistoricalVerdictUnchanged bool              `json:"historicalVerdictUnchanged"`
	Action                     *Action           `json:"action,omitempty"`
	OperationalState           string            `json:"operationalState,omitempty"`
	ReceiptPersisted           *bool             `json:"receiptPersisted,omitempty"`
	Failure                    string            `json:"failure,omitempty"`
	FixtureApplyFenceConfirmed bool              `json:"fixtureApplyFenceConfirmed,omitempty"`
}
