package kubeexperiment

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"path/filepath"
	"sync"
	"time"

	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

type inventory struct {
	Version       string                  `json:"version"`
	Plan          kubefault.Plan          `json:"plan"`
	Authorization kubefault.Authorization `json:"authorization"`
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
	}
	return nil
}

func (c *Cluster) Execute(ctx context.Context, p kubefault.Plan, a kubefault.Authorization, runsDirectory string) (Report, string, error) {
	return c.executeWithStorage(ctx, p, a, runsDirectory, func(path string) (journalFile, error) { return localstate.OpenNew(path) })
}

func (c *Cluster) executeWithStorage(ctx context.Context, p kubefault.Plan, a kubefault.Authorization, runsDirectory string, openJournal func(string) (journalFile, error)) (Report, string, error) {
	if p.Validate() != nil || a.CheckKeys() != nil || a.Grant.PlanDigest != p.Digest() || !kubefault.VerifyGrant(a.Grant, c.Owner.ApproverKey, p.Target.Fixture, c.Owner.Operator, time.Now(), true) {
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
	if err = writePrivate(filepath.Join(dir, "inventory.json"), inventory{"themis.kubernetes-execution-inventory/v1alpha1", p, a}); err != nil {
		return Report{}, dir, err
	}
	file, err := openJournal(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		return Report{}, dir, err
	}
	defer file.Close()
	j := &journal{file: file, epoch: time.Now()}
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
		operationErr = j.append(Event{Type: "INTENT"})
	}
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
	if operationErr == nil {
		operationErr = c.Revalidate(ctx, p)
	}
	if operationErr == nil {
		operationErr = collect(ctx, s.Client, j, p, "intervention")
	}
	// Cleanup has its own context. Watchdog expiry does not depend on any I/O here.
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Second)
	status, cleanupErr := s.Client.Control(cleanupCtx, a, "remove")
	if cleanupErr == nil && status.Active {
		cleanupErr = errors.New("fault still active after Remove")
	}
	if cleanupErr == nil {
		cleanupErr = c.Revalidate(cleanupCtx, p)
	}
	cleanupCancel()
	if cleanupErr == nil {
		cleanupErr = j.append(Event{Type: "REMOVED", Status: &status})
	}
	if cleanupErr == nil && operationErr == nil {
		operationErr = collect(ctx, s.Client, j, p, "recovery")
	}
	execution := result.Succeeded
	if operationErr != nil {
		execution = result.Error
		_ = j.append(Event{Type: "ABORT", Reason: "ExecutionInterrupted"})
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		execution = result.Cancelled
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		execution = result.TimedOut
	}
	if cleanupErr != nil {
		execution = result.CleanupPending
	}
	terminalErr := j.append(Event{Type: "FINAL", Execution: string(execution)})
	report := assess(j.events, true)
	if terminalErr != nil || j.poisoned {
		report.Execution = result.CleanupPending
		report.Cleanup = "PENDING"
		if report.Verdict == result.Pass {
			report.Verdict = result.Inconclusive
		}
		report.Unknowns = append(report.Unknowns, "journal persistence failed; historical record is incomplete")
	}
	if err = writePrivate(filepath.Join(dir, "report.json"), report); err != nil {
		return report, dir, err
	}
	if terminalErr != nil {
		return report, dir, terminalErr
	}
	return report, dir, nil
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
}

func (c *Cluster) Reconcile(ctx context.Context, runDirectory string) (CleanupReceipt, error) {
	var inv inventory
	if err := localstate.Read(filepath.Join(runDirectory, "inventory.json"), &inv); err != nil {
		return CleanupReceipt{}, err
	}
	if inv.Version != "themis.kubernetes-execution-inventory/v1alpha1" || inv.Plan.Validate() != nil || inv.Authorization.Grant.PlanDigest != inv.Plan.Digest() {
		return CleanupReceipt{}, kubefault.ErrDenied
	}
	lock, err := localstate.OpenLock(filepath.Join(runDirectory, "runner.lock"), false)
	if err != nil {
		return CleanupReceipt{}, err
	}
	defer lock.Close()
	held, err := lock.Try()
	if err != nil || !held {
		return CleanupReceipt{}, errors.New("runner is active; cleanup is not accepted")
	}
	r := CleanupReceipt{Version: "themis.kubernetes-cleanup-receipt/v1alpha1", PlanDigest: inv.Plan.Digest(), InvocationID: inv.Authorization.Grant.InvocationID, At: time.Now().UTC(), CurrentState: "UNKNOWN", HistoricalVerdictUnchanged: true}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	s, connectErr := c.Connect(ctx, inv.Plan)
	if connectErr == nil {
		defer s.Close()
		status, removeErr := s.Client.Control(ctx, inv.Authorization, "remove")
		if removeErr == nil && !status.Active {
			r.Status = &status
			r.CurrentState = "INACTIVE"
			epoch := time.Now()
			for i := 0; i < inv.Plan.Contract.Samples; i++ {
				r.Recovery = append(r.Recovery, observe(ctx, s.Client, epoch, "recovery", i))
			}
			complete, good, _ := complete(inv.Plan, inv.Authorization.Grant.InvocationID, "recovery", r.Recovery)
			r.RecoveryVerified = complete && good
		} else {
			r.CurrentState = "CLEANUP_PENDING"
		}
	} else {
		r.CurrentState = "TARGET_UNAVAILABLE_OR_REPLACED"
	}
	// A corrupt journal never removes cleanup authority from the separate protected
	// inventory. Receipt publication never repairs or rewrites that history.
	if err = writePrivate(filepath.Join(runDirectory, "cleanup-"+kubefault.RandomID()+".json"), r); err != nil {
		return r, err
	}
	return r, nil
}
