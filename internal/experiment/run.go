package experiment

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/tamen25/themis/internal/fixture"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/plan"
	"github.com/tamen25/themis/internal/result"
	"github.com/tamen25/themis/internal/safety"
)

func wait(ctx context.Context, until time.Time) error {
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func collect(ctx context.Context, c *fixture.Client, j *journal, p plan.ExperimentPlan, state State) error {
	if err := j.append(Event{State: state}); err != nil {
		return err
	}
	phase, duration, count := phaseConfig(p, state)
	phaseStart := j.epoch.Add(time.Duration(j.events[len(j.events)-1].AtNS))
	phaseEnd := phaseStart.Add(duration)
	phaseCtx, cancel := context.WithDeadline(ctx, phaseEnd)
	defer cancel()
	slot := duration / time.Duration(count)
	for i := range count {
		if err := wait(ctx, phaseStart.Add(time.Duration(i)*slot)); err != nil {
			return err
		}
		if j.checkStop != nil {
			if err := j.checkStop(); err != nil {
				return err
			}
		}
		if !time.Now().Before(phaseStart.Add(time.Duration(i+1) * slot)) {
			continue
		}
		o := observe(phaseCtx, c, j.epoch, phase, i)
		if err := j.append(Event{State: state, Observation: &o}); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	if err := wait(ctx, phaseEnd); err != nil {
		return err
	}
	if j.checkStop != nil {
		return j.checkStop()
	}
	return nil
}

// Only actual filesystem boundaries are injectable. There is no configurable
// fault provider, scheduler framework or production test hook.
type runStorage interface {
	OpenJournal(string) (journalFile, error)
	WriteRecord(string, any) error
}
type diskStorage struct{}

func (diskStorage) OpenJournal(path string) (journalFile, error) { return localstate.OpenNew(path) }
func (diskStorage) WriteRecord(path string, value any) error     { return localstate.WriteNew(path, value) }

type operationError struct {
	code, reason string
	cause        error
}

func (e *operationError) Error() string              { return e.reason }
func (e *operationError) Unwrap() error              { return e.cause }
func problem(code, reason string, cause error) error { return &operationError{code, reason, cause} }

func Execute(ctx context.Context, p plan.ExperimentPlan, a safety.Authorization, fixtureDirectory, runsDirectory string) (Report, string, error) {
	return execute(ctx, p, a, fixtureDirectory, runsDirectory, diskStorage{})
}

func execute(ctx context.Context, p plan.ExperimentPlan, a safety.Authorization, fixtureDirectory, runsDirectory string, storage runStorage) (Report, string, error) {
	return executeUsing(ctx, p, a, fixtureDirectory, runsDirectory, storage, fixture.Open)
}

func executeUsing(ctx context.Context, p plan.ExperimentPlan, a safety.Authorization, fixtureDirectory, runsDirectory string, storage runStorage, openFixture func(string) (*fixture.Client, error)) (Report, string, error) {
	c, err := openFixture(fixtureDirectory)
	if err != nil {
		return Report{}, "", err
	}
	defer c.Close()
	id, err := c.Resolve(ctx)
	if err != nil {
		return Report{}, "", err
	}
	if id != p.Snapshot().Target {
		return Report{}, "", fmt.Errorf("%w: resolved fixture differs from approved target", safety.ErrDenied)
	}
	actor, err := localstate.CurrentActor()
	if err != nil {
		return Report{}, "", err
	}
	if err := safety.CheckAuthorization(a, p, actor, time.Now()); err != nil {
		return Report{}, "", err
	}
	runID := localstate.RandomID()
	if runsDirectory == "" {
		runsDirectory = filepath.Join(".themis", "experiments")
	}
	dir, err := localstate.CreateDirectory(filepath.Join(runsDirectory, "run-"+runID))
	if err != nil {
		return Report{}, "", err
	}
	runner, err := localstate.OpenLock(filepath.Join(dir, "runner.lock"), true)
	if err != nil {
		return Report{}, dir, err
	}
	defer runner.Close()
	if err := runner.Acquire(ctx); err != nil {
		return Report{}, dir, err
	}
	coordination, err := lifecycleLock(ctx, dir)
	if err != nil {
		return Report{}, dir, err
	}
	if err := coordination.Close(); err != nil {
		return Report{}, dir, err
	}
	handle, err := c.Claim(ctx, a, runID)
	if err != nil {
		return Report{}, dir, err
	}
	cleanupTimeout, _ := time.ParseDuration(p.Snapshot().Contract.Spec.Cleanup.Timeout)
	cleanupNeeded := true
	defer func() {
		if cleanupNeeded {
			cleanup(c, handle, cleanupTimeout)
		}
	}()
	publicAuthorization := a
	publicAuthorization.Seal = ""
	manifest := Manifest{Plan: p.JSON(), Authorization: publicAuthorization, Handle: handle, StartedAt: time.Now().UTC()}
	absoluteFixture, err := filepath.Abs(fixtureDirectory)
	if err != nil {
		return Report{}, dir, err
	}
	inventory := Inventory{Version, absoluteFixture, manifest}
	if err := storage.WriteRecord(filepath.Join(dir, "resources.json"), inventory); err != nil {
		return Report{}, dir, err
	}
	f, err := storage.OpenJournal(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		return Report{}, dir, err
	}
	defer f.Close()
	j := &journal{file: f, runID: runID, epoch: time.Now()}
	if err := j.append(Event{State: Authorized, Manifest: &manifest}); err != nil {
		return Report{}, dir, err
	}
	if err := localstate.SyncDirectory(dir); err != nil {
		return Report{}, dir, err
	}
	budget, _ := time.ParseDuration(p.Snapshot().Contract.Spec.Execution.MaxDuration)
	runCtx, cancel := context.WithDeadline(ctx, manifest.StartedAt.Add(budget))
	defer cancel()
	j.checkStop = func() error {
		if err := runCtx.Err(); err != nil {
			return err
		}
		requested, err := stopRequested(dir, inventory, p)
		if err != nil {
			return problem("STOP_REQUEST_UNREADABLE", "protected stop request is unreadable; intervention is not continued", err)
		}
		if requested {
			return problem("EXTERNAL_STOP_REQUESTED", "another CLI requested cancellation or cleanup", context.Canceled)
		}
		return nil
	}
	op := OpBaseline
	attempted := boolean(false)
	workErr := func() error {
		if err := collect(runCtx, c, j, p, Baseline); err != nil {
			return err
		}
		if err := j.append(Event{State: BaselineCompleted}); err != nil {
			return err
		}
		if !evaluate(p, manifest, j.events).BaselineSatisfied {
			return problem("BASELINE_REJECTED", "baseline prerequisites failed; fault application was not attempted", nil)
		}
		op = OpRevalidate
		if err := j.append(Event{State: Revalidating}); err != nil {
			return err
		}
		if err := func() error {
			lock, err := lifecycleLock(runCtx, dir)
			if err != nil {
				return err
			}
			defer lock.Close()
			if err := j.checkStop(); err != nil {
				return err
			}
			currentActor, err := localstate.CurrentActor()
			if err != nil {
				return err
			}
			if err := safety.CheckAuthorization(a, p, currentActor, time.Now()); err != nil {
				return problem("AUTHORIZATION_REVALIDATION_FAILED", "authorization expired or no longer matches before intent", err)
			}
			if err := c.ValidateClaim(runCtx, handle); err != nil {
				return problem("TARGET_REVALIDATION_FAILED", "target identity or trusted claim revalidation failed before intent", err)
			}
			if err := j.checkStop(); err != nil {
				return err
			}
			op = OpIntent
			if err := j.append(Event{State: Intent}); err != nil {
				return err
			}
			// No additional resolution or storage operation intervenes here.
			op = OpApply
			attempted = nil
			receipt, err := c.ApplyPrepared(runCtx, handle)
			if err != nil {
				if fixture.ApplicationNotAttempted(err) {
					attempted = boolean(false)
				}
				return problem("APPLICATION_UNACKNOWLEDGED", "fault application was denied or its acknowledgment was not verified", err)
			}
			if receipt.Handle != handle {
				return problem("APPLICATION_IDENTITY_MISMATCH", "application receipt does not match the approved resource", nil)
			}
			attempted = boolean(true)
			op = OpAcknowledge
			return j.append(Event{State: Applied, Receipt: &receipt})
		}(); err != nil {
			return err
		}
		op = OpIntervention
		if err := collect(runCtx, c, j, p, Intervention); err != nil {
			return err
		}
		preview := append(append([]Event{}, j.events...), Event{State: Unverified, AtNS: int64(time.Since(j.epoch))})
		confirmation := Unverified
		if evaluate(p, manifest, preview).InterventionConfirmed {
			confirmation = Confirmed
		}
		if err := j.append(Event{State: confirmation}); err != nil {
			return err
		}
		op = OpRemove
		if err := j.append(Event{State: Removal}); err != nil {
			return err
		}
		removal := RemovalUnknown
		if err := c.Remove(runCtx, handle); err == nil {
			if state, err := c.Status(runCtx); err == nil && state.ActiveFault == nil {
				removal = Removed
			}
		}
		if err := j.append(Event{State: removal}); err != nil {
			return err
		}
		op = OpRecovery
		if err := collect(runCtx, c, j, p, Recovery); err != nil {
			return err
		}
		preview = append(append([]Event{}, j.events...), Event{State: RecoveryUnknown, AtNS: int64(time.Since(j.epoch))})
		recovery := RecoveryUnknown
		if evaluate(p, manifest, preview).RecoveryObserved {
			recovery = Recovered
		}
		return j.append(Event{State: recovery})
	}()
	status := result.Succeeded
	var failure *Failure
	var durabilityError error
	noteFailure := func(failure *Failure) {
		if failure == nil {
			return
		}
		note := FailureRecord{Version: "themis.operation-failure/v1alpha1", RunID: runID, PlanDigest: p.Digest(), FixtureID: id.InstanceID, LastSequence: len(j.events), LastState: j.state, At: time.Now().UTC(), Failure: *failure}
		if err := storage.WriteRecord(filepath.Join(dir, "failure-"+localstate.RandomID()+".json"), note); err != nil {
			durabilityError = errors.Join(durabilityError, fmt.Errorf("failure diagnostic could not be persisted: %w", err))
		}
	}
	if workErr != nil {
		status = result.Error
		if errors.Is(workErr, context.Canceled) {
			status = result.Cancelled
		} else if errors.Is(workErr, context.DeadlineExceeded) {
			status = result.TimedOut
		}
		failure = &Failure{Operation: op, Code: "EXPERIMENT_OPERATION_FAILED", Reason: "experiment operation failed; recorded intent and measurements must be inspected", FaultAttempted: attempted}
		var known *operationError
		if errors.As(workErr, &known) {
			failure.Code = known.code
			failure.Reason = known.reason
		} else if status == result.Cancelled {
			failure.Code = "CANCELLED"
			failure.Reason = "execution was cancelled"
		} else if status == result.TimedOut {
			failure.Code = "EXPERIMENT_DEADLINE"
			failure.Reason = "experiment deadline elapsed"
		}
		if j.failed {
			failure.Code = "JOURNAL_WRITE_FAILED"
			failure.Reason = "journal append or sync failed; no further journal writes are trusted"
			durabilityError = errors.Join(durabilityError, workErr)
		}
		noteFailure(failure)
		if !j.failed {
			if err := j.append(Event{State: Aborted, Status: status, Failure: failure}); err != nil {
				durabilityError = errors.Join(durabilityError, err)
			}
		}
	}
	if !j.failed {
		if err := j.append(Event{State: Cleaning}); err != nil {
			durabilityError = errors.Join(durabilityError, err)
		}
	}
	cleanupAction := ActionIntent{Version: ActionVersion, ID: localstate.RandomID(), Kind: RunnerCleanup, RunID: runID, PlanDigest: p.Digest(), Handle: handle, Actor: actor, RequestedAt: time.Now().UTC()}
	if err := storage.WriteRecord(filepath.Join(dir, "action-"+cleanupAction.ID+".json"), cleanupAction); err != nil {
		durabilityError = errors.Join(durabilityError, fmt.Errorf("cleanup intent write failed; safe owned cleanup still attempted: %w", err))
	}
	clean := cleanup(c, handle, cleanupTimeout)
	cleanupNeeded = false
	clean.ActionID = cleanupAction.ID
	clean.Kind = RunnerCleanup
	clean.PlanDigest = p.Digest()
	clean.FixtureID = id.InstanceID
	clean.FaultID = handle.FaultID
	clean, receiptErr := persistCleanup(dir, clean, storage.WriteRecord)
	if receiptErr != nil {
		status = result.CleanupPending
		failure = &Failure{Operation: OpReceipt, Code: "CLEANUP_RECEIPT_WRITE_FAILED", Reason: "resource observations could not be durably recorded; reconciliation is required", FaultAttempted: attempted}
		noteFailure(failure)
		durabilityError = errors.Join(durabilityError, receiptErr)
	}
	cleanupState := Cleaned
	if !clean.Completed || receiptErr != nil {
		cleanupState = Pending
		status = result.CleanupPending
	}
	if !j.failed {
		event := Event{State: cleanupState, Residuals: clean.Residuals}
		if receiptErr != nil {
			event.Failure = failure
		}
		if err := j.append(event); err != nil {
			durabilityError = errors.Join(durabilityError, err)
		}
	}
	finalCtx, finalCancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer finalCancel()
	lock, lockErr := lifecycleLock(finalCtx, dir)
	if lockErr == nil {
		defer lock.Close()
		requested, err := stopRequested(dir, inventory, p)
		if err != nil {
			durabilityError = errors.Join(durabilityError, err)
		} else if requested && status == result.Succeeded {
			status = result.Cancelled
			failure = &Failure{Operation: OpFinalize, Code: "EXTERNAL_STOP_REQUESTED", Reason: "stop request was accepted before finalization", FaultAttempted: attempted}
			noteFailure(failure)
		}
	} else {
		durabilityError = errors.Join(durabilityError, lockErr)
	}
	if durabilityError != nil && status == result.Succeeded {
		status = result.Error
	}
	if durabilityError != nil && failure == nil {
		failure = &Failure{Operation: OpFinalize, Code: "DURABILITY_FAILED", Reason: "one or more execution records could not be durably persisted", FaultAttempted: attempted}
		noteFailure(failure)
	}
	if !j.failed {
		if err := j.append(Event{State: Finalized, Status: status, Failure: failure}); err != nil {
			durabilityError = errors.Join(durabilityError, err)
		}
	}
	if err := f.Close(); err != nil {
		durabilityError = errors.Join(durabilityError, err)
	}
	var r Report
	if !j.failed {
		r, err = ReplayFile(filepath.Join(dir, "events.jsonl"))
		if err != nil {
			durabilityError = errors.Join(durabilityError, err)
		}
	}
	if j.failed || r.RunID == "" {
		virtual := append(append([]Event{}, j.events...), Event{State: Finalized, Status: status, Failure: failure, AtNS: int64(time.Since(j.epoch))})
		r = evaluate(p, manifest, virtual)
		r.Execution.Status = status
		r.FaultAttempted = attempted
		r.CleanupCompleted = clean.Completed && receiptErr == nil
		r.Verdict = nonPassing(r.Verdict)
		r.Unknowns = append(r.Unknowns, "journal persistence failed; this local diagnostic is not a complete execution journal")
	}
	if durabilityError != nil {
		r.Verdict = nonPassing(r.Verdict)
		if r.Execution.Status == result.Succeeded {
			r.Execution.Status = result.Error
		}
		if r.Failure == nil {
			r.Failure = &Failure{Operation: OpFinalize, Code: "DURABILITY_FAILED", Reason: "one or more execution records could not be durably persisted", FaultAttempted: attempted}
		}
		r.Execution.Error = &result.ExecutionError{Code: r.Failure.Code, Message: r.Failure.Reason}
	}
	r.Provenance = classifyProvenance(r, manifest, LocallyCollected)
	if err := storage.WriteRecord(filepath.Join(dir, "report.json"), r); err != nil {
		durabilityError = errors.Join(durabilityError, fmt.Errorf("report could not be persisted: %w", err))
		r.Verdict = nonPassing(r.Verdict)
		if r.Execution.Status != result.CleanupPending {
			r.Execution.Status = result.Error
		}
		r.Execution.Error = &result.ExecutionError{Code: "REPORT_WRITE_FAILED", Message: "verification report could not be durably persisted"}
	}
	return r, dir, durabilityError
}

func nonPassing(v result.Verdict) result.Verdict {
	if v == result.Fail {
		return v
	}
	return result.Inconclusive
}
