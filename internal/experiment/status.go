package experiment

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tamen25/themis/internal/fixture"
	"github.com/tamen25/themis/internal/localpolicy"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/plan"
	"github.com/tamen25/themis/internal/result"
)

const StatusVersion = "themis.experiment-status/v1alpha1"

type ApplicationState string

const (
	NotAttempted          ApplicationState = "NOT_ATTEMPTED"
	Acknowledged          ApplicationState = "ACKNOWLEDGED"
	Ambiguous             ApplicationState = "AMBIGUOUS"
	ApplicationUnverified ApplicationState = "UNVERIFIED"
)

type HistoricalStatus struct {
	Source            string            `json:"source"`
	OriginalReport    *Report           `json:"originalReport,omitempty"`
	OriginalVerdict   *result.Verdict   `json:"originalMeasuredVerdict,omitempty"`
	OriginalExecution *result.Execution `json:"originalExecution,omitempty"`
	LastCleanup       State             `json:"lastJournalCleanup,omitempty"`
	Provenance        *Provenance       `json:"provenance,omitempty"`
}
type LiveStatus struct {
	CheckedAt            time.Time               `json:"checkedAt"`
	Runner               string                  `json:"runner"`
	Fixture              string                  `json:"fixture"`
	Fault                string                  `json:"fault"`
	ExpectedFaultExpiry  *time.Time              `json:"expectedFaultExpiry,omitempty"`
	FaultExpirySource    string                  `json:"faultExpirySource"`
	FaultDeadlineExpired *bool                   `json:"faultDeadlineExpired,omitempty"`
	LeaseExpiresAt       *time.Time              `json:"leaseExpiresAt,omitempty"`
	FixtureExpiresAt     *time.Time              `json:"fixtureExpiresAt,omitempty"`
	Residuals            []fixture.ListenerState `json:"residuals"`
	Claim                *fixture.ClaimStatus    `json:"claim,omitempty"`
}
type StatusReport struct {
	Version                 string                 `json:"version"`
	RunID                   string                 `json:"runID,omitempty"`
	ContractName            string                 `json:"contractName,omitempty"`
	PlanDigest              string                 `json:"planDigest,omitempty"`
	Target                  *plan.FixtureIdentity  `json:"target,omitempty"`
	InventoryUsable         bool                   `json:"inventoryUsable"`
	InventoryError          string                 `json:"inventoryError,omitempty"`
	Journal                 JournalInspection      `json:"journal"`
	History                 HistoricalStatus       `json:"history"`
	Live                    LiveStatus             `json:"live"`
	ExecutionDisposition    result.ExecutionStatus `json:"executionDisposition"`
	Application             ApplicationState       `json:"faultApplication"`
	ApplicationSource       string                 `json:"faultApplicationSource"`
	StopRequested           bool                   `json:"stopRequested"`
	LastCleanup             *CleanupResult         `json:"lastRecordedCleanup,omitempty"`
	LastFailure             *FailureRecord         `json:"lastRecordedFailure,omitempty"`
	ReconciliationNecessary bool                   `json:"reconciliationNecessary"`
	OperatorActions         []string               `json:"operatorActions"`
	Limitations             []string               `json:"limitations"`
}

func applicationState(attempted *bool) ApplicationState {
	if attempted == nil {
		return Ambiguous
	}
	if *attempted {
		return Acknowledged
	}
	return NotAttempted
}

func probeRunner(directory string) string {
	lock, err := localstate.OpenLock(filepath.Join(directory, "runner.lock"), false)
	if err != nil {
		return "UNKNOWN"
	}
	defer lock.Close()
	acquired, err := lock.Try()
	if err != nil {
		return "UNKNOWN"
	}
	if acquired {
		return "NOT_RUNNING"
	}
	return "RUNNING"
}

// A bounded directory scan cannot silently drop malformed action receipts.
func records(directory, prefix string) ([]string, error) {
	f, err := os.Open(directory)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	names, err := f.Readdirnames(1025)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(names) > 1024 {
		return nil, errors.New("run directory exceeds 1024 entries")
	}
	var paths []string
	for _, name := range names {
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".json") {
			paths = append(paths, filepath.Join(directory, name))
		}
	}
	return paths, nil
}

func lastReceipt(directory string, inventory Inventory, p plan.ExperimentPlan) (*CleanupResult, error) {
	paths, err := records(directory, "cleanup-")
	if err != nil {
		return nil, err
	}
	var latest *CleanupResult
	for _, path := range paths {
		var r CleanupResult
		if err := localstate.Read(path, &r); err != nil {
			return latest, errors.New("cleanup receipt is unreadable or corrupt")
		}
		if r.RunID != inventory.Manifest.Handle.RunID || r.CheckedAt.IsZero() {
			return latest, errors.New("cleanup receipt identity/time mismatch")
		}
		if r.Version == Version {
			if !plan.ValidInstanceID(r.ActionID) || r.PlanDigest != p.Digest() || r.FixtureID != p.Snapshot().Target.InstanceID || r.FaultID != inventory.Manifest.Handle.FaultID || (r.Kind != CancelAction && r.Kind != CleanupAction && r.Kind != RunnerCleanup) || r.RecoveryVerified || (r.Disposition != Cleaned && r.Disposition != Pending) || r.Completed != residualsClosed(r.Residuals) {
				return latest, errors.New("cleanup receipt scope/disposition mismatch")
			}
		} else if r.Version != LegacyVersion || inventory.Version != LegacyVersion {
			return latest, errors.New("unsupported cleanup receipt")
		}
		id := p.Snapshot().Target
		for i, endpoint := range []string{id.ServiceURL, id.ProxyURL, id.ControlURL} {
			if i >= len(r.Residuals) || r.Residuals[i].Endpoint != endpoint {
				return latest, errors.New("cleanup residual target mismatch")
			}
		}
		r.ReceiptPersisted = boolean(true)
		if latest == nil || r.CheckedAt.After(latest.CheckedAt) {
			copy := r
			latest = &copy
		}
	}
	return latest, nil
}

func lastFailure(directory string, inventory Inventory, p plan.ExperimentPlan) (*FailureRecord, error) {
	paths, err := records(directory, "failure-")
	if err != nil {
		return nil, err
	}
	var latest *FailureRecord
	for _, path := range paths {
		var note FailureRecord
		if err := localstate.Read(path, &note); err != nil {
			return latest, err
		}
		if note.Version != "themis.operation-failure/v1alpha1" || note.RunID != inventory.Manifest.Handle.RunID || note.PlanDigest != p.Digest() || note.FixtureID != p.Snapshot().Target.InstanceID || !validOperation(note.Failure.Operation) || note.Failure.Code == "" || note.At.IsZero() {
			return latest, errors.New("invalid failure diagnostic")
		}
		if latest == nil || note.At.After(latest.At) {
			copy := note
			latest = &copy
		}
	}
	return latest, nil
}

func savedHistory(directory string, inspection JournalInspection, inventory Inventory, p plan.ExperimentPlan) HistoricalStatus {
	h := HistoricalStatus{Source: "NONE"}
	for _, e := range inspection.scan.Events {
		if e.State == Cleaned || e.State == Pending {
			h.LastCleanup = e.State
		}
	}
	var saved Report
	err := localstate.Read(filepath.Join(directory, "report.json"), &saved)
	if err == nil && validateReportFormat(saved) == nil && saved.RunID == inventory.Manifest.Handle.RunID && saved.PlanDigest == p.Digest() && saved.FixtureID == p.Snapshot().Target.InstanceID {
		h.OriginalReport = &saved
		h.OriginalVerdict = &saved.Verdict
		h.OriginalExecution = &saved.Execution
		h.Source = "UNVERIFIED_SAVED_REPORT"
		if inspection.report != nil {
			a, b := saved, *inspection.report
			a.Provenance = nil
			b.Provenance = nil
			av, _ := json.Marshal(a)
			bv, _ := json.Marshal(b)
			if string(av) == string(bv) {
				h.Source = "SAVED_REPORT_CONSISTENT_WITH_COMPLETE_JOURNAL"
			}
		}
	} else if inspection.report != nil {
		r := *inspection.report
		h.OriginalReport = &r
		h.OriginalVerdict = &r.Verdict
		h.OriginalExecution = &r.Execution
		h.Source = "DERIVED_FROM_COMPLETE_UNSIGNED_JOURNAL"
	}
	if h.OriginalReport != nil {
		h.Provenance = classifyProvenance(*h.OriginalReport, inventory.Manifest, UnsignedReplay)
	}
	return h
}

// Inspect is read-only: no files are created, no controller nonce is consumed,
// and no expiry/removal/stop is triggered by inspection itself.
func Inspect(ctx context.Context, directory string) (StatusReport, error) {
	r := StatusReport{Version: StatusVersion, ExecutionDisposition: result.CleanupPending, Application: ApplicationUnverified, OperatorActions: []string{}, Limitations: []string{"Historical facts and current resource observations are separate snapshots.", "Journal/client timing is unauthenticated; response signatures do not attest execution or network conditions.", "Closed listeners do not prove application recovery. Wall-clock expiry displays are subject to clock changes; worker enforcement is independent."}, Live: LiveStatus{Runner: "UNKNOWN", Fixture: "UNKNOWN", Fault: "UNKNOWN", FaultExpirySource: "UNKNOWN", CheckedAt: time.Now().UTC(), Residuals: []fixture.ListenerState{}}}
	if err := localstate.Check(directory); err != nil {
		return r, err
	}
	r.ApplicationSource = "UNVERIFIED"
	r.Journal = inspectJournalFile(filepath.Join(directory, "events.jsonl"))
	inventory, p, err := loadInventory(directory)
	if err != nil {
		r.InventoryError = err.Error()
		r.ReconciliationNecessary = true
		r.OperatorActions = append(r.OperatorActions, "Restore the protected resource inventory or allow bounded fixture expiry; do not infer mutation targets from the journal.")
		if len(r.Journal.scan.Events) > 0 {
			r.RunID = r.Journal.scan.Manifest.Handle.RunID
		}
		return r, nil
	}
	r.InventoryUsable = true
	id := p.Snapshot().Target
	r.Target = &id
	r.RunID = inventory.Manifest.Handle.RunID
	r.ContractName = p.Snapshot().Contract.Metadata.Name
	r.PlanDigest = p.Digest()
	if len(r.Journal.scan.Events) > 0 && (r.Journal.scan.Manifest.Handle != inventory.Manifest.Handle || r.Journal.scan.Plan.Digest() != p.Digest()) {
		r.Journal.Integrity = JournalCorrupt
		r.Journal.Error = "journal scope differs from protected inventory"
		r.Journal.scan = journalScan{}
		r.Journal.report = nil
	}
	r.History = savedHistory(directory, r.Journal, inventory, p)
	r.Live.Runner = probeRunner(directory)
	if len(r.Journal.scan.Events) > 0 {
		derived := evaluate(r.Journal.scan.Plan, r.Journal.scan.Manifest, r.Journal.scan.Events)
		r.Application = applicationState(derived.FaultAttempted)
		r.ApplicationSource = "HISTORICAL_JOURNAL"
		if derived.Deadlines != nil && derived.Deadlines.Fault != nil {
			r.Live.ExpectedFaultExpiry = derived.Deadlines.Fault
			r.Live.FaultExpirySource = "RECORDED_ACKNOWLEDGMENT"
		}
	}
	r.LastFailure, err = lastFailure(directory, inventory, p)
	if err != nil {
		r.OperatorActions = append(r.OperatorActions, "Failure diagnostic is corrupt; preserve it for review.")
	}
	if r.LastFailure != nil {
		r.Journal.Operation = r.LastFailure.Failure.Operation
		if r.LastFailure.Failure.FaultAttempted != nil {
			hasAck := false
			for _, e := range r.Journal.scan.Events {
				hasAck = hasAck || e.State == Applied
			}
			if !hasAck || *r.LastFailure.Failure.FaultAttempted {
				r.Application = applicationState(r.LastFailure.Failure.FaultAttempted)
				r.ApplicationSource = "LOCAL_FAILURE_DIAGNOSTIC"
			}
		}
	}
	requested, requestErr := stopRequested(directory, inventory, p)
	r.StopRequested = requested
	if requestErr != nil {
		r.OperatorActions = append(r.OperatorActions, "Stop request is corrupt; no guessed cancellation identity is trusted.")
	}
	r.LastCleanup, err = lastReceipt(directory, inventory, p)
	receiptError := err != nil
	if receiptError {
		r.OperatorActions = append(r.OperatorActions, "Cleanup receipt is incomplete or corrupt; reconcile from protected inventory.")
	}
	deadline, cancel := context.WithTimeout(ctx, localpolicy.CleanupLimit)
	defer cancel()
	c, openErr := fixture.Open(inventory.FixtureDirectory)
	if openErr == nil {
		defer c.Close()
		if c.Identity != id {
			r.Live.Fixture = "IDENTITY_MISMATCH"
		} else if state, err := c.Status(deadline); err == nil && state.Claim != nil && state.Claim.RunID == r.RunID {
			r.Live.Fixture = "AUTHENTICATED"
			r.Live.Claim = state.Claim
			r.Live.Fault = "NONE"
			if state.ActiveFault != nil && *state.ActiveFault == inventory.Manifest.Handle {
				r.Live.Fault = "ACTIVE"
			}
			if state.Claim.Receipt != nil && state.Claim.Receipt.Handle == inventory.Manifest.Handle {
				expiry := state.Claim.Receipt.FaultExpiresAt
				r.Live.ExpectedFaultExpiry = &expiry
				r.Live.FaultExpirySource = "AUTHENTICATED_FIXTURE"
				r.Application = Acknowledged
				r.ApplicationSource = "AUTHENTICATED_FIXTURE"
			}
		} else {
			r.Live.Fixture = "UNAUTHENTICATED_OR_UNREACHABLE"
		}
	}
	r.Live.Residuals, _ = fixture.InspectIdentityListeners(deadline, id)
	closed := residualsClosed(r.Live.Residuals)
	if closed {
		r.Live.Fixture = "LISTENERS_CLOSED"
		r.Live.Fault = "ABSENT_WITH_FIXTURE"
	}
	lease, expiry := inventory.Manifest.Handle.ExpiresAt, id.ExpiresAt
	r.Live.LeaseExpiresAt = &lease
	r.Live.FixtureExpiresAt = &expiry
	r.Live.CheckedAt = time.Now().UTC()
	if r.Live.ExpectedFaultExpiry != nil {
		r.Live.FaultDeadlineExpired = boolean(!r.Live.CheckedAt.Before(*r.Live.ExpectedFaultExpiry))
	}
	active := r.Live.Runner == "RUNNING" && r.Journal.Integrity == JournalInterrupted && !requested && requestErr == nil && r.Live.Fixture == "AUTHENTICATED"
	r.ReconciliationNecessary = (!active && !closed) || requested && !closed || receiptError || requestErr != nil || (!active && (r.LastCleanup == nil || !r.LastCleanup.Completed))
	if active {
		r.ExecutionDisposition = result.ExecutionStatus("RUNNING")
	} else if r.Journal.report != nil {
		r.ExecutionDisposition = r.Journal.report.Execution.Status
	}
	if r.ReconciliationNecessary {
		r.ExecutionDisposition = result.CleanupPending
		r.OperatorActions = append(r.OperatorActions, "Run experiment cleanup against this private run directory; independent expiry remains active.")
	} else if requested && r.Journal.Integrity != JournalComplete {
		r.ExecutionDisposition = result.ExecutionStatus("INTERRUPTED_RESOURCES_RECONCILED")
	} else if r.Journal.Integrity != JournalComplete && !active {
		r.ExecutionDisposition = result.Error
		r.OperatorActions = append(r.OperatorActions, "Resources are closed, but historical execution evidence remains incomplete; preserve the journal.")
	}
	if !r.ReconciliationNecessary && closed && r.Journal.report != nil && r.Journal.report.Execution.Status == result.CleanupPending {
		r.ExecutionDisposition = result.ExecutionStatus("FINALIZED_WITH_RECONCILED_CLEANUP")
	}
	return r, nil
}
