// Package experiment executes the narrowly scoped, experimental local lifecycle.
// T0 run formats and scheduling remain in internal/run.
package experiment

import (
	"encoding/json"
	"time"

	"github.com/tamen25/themis/internal/fixture"
	"github.com/tamen25/themis/internal/result"
	"github.com/tamen25/themis/internal/safety"
)

const LegacyVersion = "themis.experiment/v1alpha1"
const LegacyJournalVersion = "themis.experiment-journal/v1alpha1"
const Version = "themis.experiment/v1alpha2"
const JournalVersion = "themis.experiment-journal/v1alpha2"

type State string

const (
	Authorized        State = "RUN_AUTHORIZED"
	Baseline          State = "BASELINE_STARTED"
	BaselineCompleted State = "BASELINE_COMPLETED"
	Revalidating      State = "FAULT_REVALIDATION_STARTED"
	Intent            State = "FAULT_INTENT_RECORDED"
	Applied           State = "FAULT_APPLIED"
	Intervention      State = "INTERVENTION_STARTED"
	Confirmed         State = "INTERVENTION_CONFIRMED"
	Unverified        State = "INTERVENTION_UNVERIFIED"
	Removal           State = "FAULT_REMOVAL_REQUESTED"
	Removed           State = "FAULT_REMOVED"
	RemovalUnknown    State = "FAULT_REMOVAL_UNKNOWN"
	Recovery          State = "RECOVERY_STARTED"
	Recovered         State = "RECOVERY_OBSERVED"
	RecoveryUnknown   State = "RECOVERY_UNVERIFIED"
	Aborted           State = "ABORTED"
	Cleaning          State = "CLEANUP_STARTED"
	Cleaned           State = "CLEANUP_COMPLETED"
	Pending           State = "CLEANUP_PENDING"
	Finalized         State = "RUN_FINALIZED"
)

type Manifest struct {
	Plan          json.RawMessage      `json:"plan"`
	Authorization safety.Authorization `json:"authorization"` // seal redacted, never a reusable capability
	Handle        fixture.FaultHandle  `json:"handle"`
	StartedAt     time.Time            `json:"startedAt"`
}

type Probe struct {
	Kind        string                `json:"kind"`
	StartedNS   int64                 `json:"startedNS"`
	CompletedNS int64                 `json:"completedNS"`
	Outcome     string                `json:"outcome"`
	StatusCode  int                   `json:"statusCode"`
	Response    *fixture.DataResponse `json:"response,omitempty"`
}
type Observation struct {
	Phase     string  `json:"phase"`
	Index     int     `json:"index"`
	RequestID string  `json:"requestID"`
	Probes    []Probe `json:"probes"`
}
type Event struct {
	Version     string                  `json:"version"`
	RunID       string                  `json:"runID"`
	Sequence    int                     `json:"sequence"`
	State       State                   `json:"state"`
	AtNS        int64                   `json:"atNS"`
	Manifest    *Manifest               `json:"manifest,omitempty"`
	Observation *Observation            `json:"observation,omitempty"`
	Receipt     *fixture.Receipt        `json:"receipt,omitempty"`
	Status      result.ExecutionStatus  `json:"status,omitempty"`
	Residuals   []fixture.ListenerState `json:"residuals,omitempty"`
	Operation   Operation               `json:"operation,omitempty"`
	Failure     *Failure                `json:"failure,omitempty"`
}
type Report struct {
	Version                string                   `json:"version"`
	RunID                  string                   `json:"runID"`
	ContractName           string                   `json:"contractName"`
	PlanDigest             string                   `json:"planDigest"`
	FixtureID              string                   `json:"fixtureID"`
	JournalDigest          string                   `json:"journalDigest"`
	Execution              result.Execution         `json:"execution"`
	Verdict                result.Verdict           `json:"verdict"`
	BaselineSatisfied      bool                     `json:"baselineSatisfied"`
	FaultAttempted         *bool                    `json:"faultAttempted"` // null when durable intent has no acknowledgment
	InterventionConfirmed  bool                     `json:"interventionConfirmed"`
	ConfirmedRequests      int                      `json:"confirmedRequests"`
	RecoveryObserved       bool                     `json:"recoveryObserved"`
	CleanupCompleted       bool                     `json:"cleanupCompleted"`
	SufficientObservations bool                     `json:"sufficientObservations"`
	Observations           []Observation            `json:"observations"`
	Assertions             []result.AssertionResult `json:"assertions"`
	Unknowns               []string                 `json:"unknowns"`
	EvidenceLimit          string                   `json:"evidenceLimit"`
	Provenance             *Provenance              `json:"provenance,omitempty"`
	Deadlines              *Deadlines               `json:"deadlines,omitempty"`
	Failure                *Failure                 `json:"failure,omitempty"`
}

type Inventory struct {
	Version          string   `json:"version"`
	FixtureDirectory string   `json:"fixtureDirectory"`
	Manifest         Manifest `json:"manifest"`
}
type CleanupResult struct {
	Version          string                  `json:"version"`
	RunID            string                  `json:"runID"`
	Completed        bool                    `json:"completed"`
	RecoveryVerified bool                    `json:"recoveryVerified"`
	CheckedAt        time.Time               `json:"checkedAt"`
	Residuals        []fixture.ListenerState `json:"residuals"`
	ActionID         string                  `json:"actionID,omitempty"`
	Kind             ActionKind              `json:"kind,omitempty"`
	PlanDigest       string                  `json:"planDigest,omitempty"`
	FixtureID        string                  `json:"fixtureID,omitempty"`
	FaultID          string                  `json:"faultID,omitempty"`
	Disposition      State                   `json:"disposition,omitempty"`
	ReceiptPersisted *bool                   `json:"receiptPersisted,omitempty"`
	Failure          *Failure                `json:"failure,omitempty"`
}

func transitionFor(version string, from, to State) bool {
	if version == LegacyJournalVersion {
		return transition(from, to)
	}
	if version != JournalVersion {
		return false
	}
	if from == Baseline && to != Aborted {
		return to == BaselineCompleted
	}
	if from == BaselineCompleted && to != Aborted {
		return to == Revalidating
	}
	if from == Revalidating && to != Aborted {
		return to == Intent
	}
	if to == Cleaning {
		return from == Recovered || from == RecoveryUnknown || from == Aborted
	}
	if to == Cleaned || to == Pending {
		return from == Cleaning
	}
	return transition(from, to)
}

func transition(from, to State) bool {
	if to == Aborted {
		return from != "" && from != Finalized && from != Cleaned && from != Pending && from != Aborted
	}
	if to == Cleaned || to == Pending {
		return from == Recovered || from == RecoveryUnknown || from == Aborted
	}
	switch from {
	case "":
		return to == Authorized
	case Authorized:
		return to == Baseline
	case Baseline:
		return to == Intent
	case Intent:
		return to == Applied
	case Applied:
		return to == Intervention
	case Intervention:
		return to == Confirmed || to == Unverified
	case Confirmed, Unverified:
		return to == Removal
	case Removal:
		return to == Removed || to == RemovalUnknown
	case Removed, RemovalUnknown:
		return to == Recovery
	case Recovery:
		return to == Recovered || to == RecoveryUnknown
	case Cleaned, Pending:
		return to == Finalized
	default:
		return false
	}
}
