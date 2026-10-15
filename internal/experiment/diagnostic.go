package experiment

import "time"

type Operation string

const (
	OpBaseline     Operation = "COLLECT_BASELINE"
	OpRevalidate   Operation = "REVALIDATE_TARGET_AND_AUTHORIZATION"
	OpIntent       Operation = "PERSIST_FAULT_INTENT"
	OpApply        Operation = "APPLY_FAULT"
	OpAcknowledge  Operation = "PERSIST_APPLICATION_ACKNOWLEDGMENT"
	OpIntervention Operation = "COLLECT_INTERVENTION"
	OpRemove       Operation = "REMOVE_FAULT"
	OpRecovery     Operation = "COLLECT_RECOVERY"
	OpCleanup      Operation = "CLEANUP_OWNED_RESOURCES"
	OpReceipt      Operation = "PERSIST_CLEANUP_RECEIPT"
	OpFinalize     Operation = "FINALIZE_RUN"
)

type Failure struct {
	Operation      Operation `json:"operation"`
	Code           string    `json:"code"`
	Reason         string    `json:"reason"`
	FaultAttempted *bool     `json:"faultAttempted"`
}
type FailureRecord struct {
	Version      string    `json:"version"`
	RunID        string    `json:"runID"`
	PlanDigest   string    `json:"planDigest"`
	FixtureID    string    `json:"fixtureID"`
	LastSequence int       `json:"lastSequence"`
	LastState    State     `json:"lastState"`
	At           time.Time `json:"at"`
	Failure      Failure   `json:"failure"`
}

func operationFor(state State) Operation {
	switch state {
	case Baseline, BaselineCompleted:
		return OpBaseline
	case Revalidating:
		return OpRevalidate
	case Intent:
		return OpApply
	case Applied:
		return OpIntervention
	case Intervention, Confirmed, Unverified:
		return OpIntervention
	case Removal, Removed, RemovalUnknown:
		return OpRemove
	case Recovery, Recovered, RecoveryUnknown:
		return OpRecovery
	case Cleaning, Cleaned, Pending:
		return OpCleanup
	case Finalized:
		return OpFinalize
	default:
		return ""
	}
}
func validOperation(op Operation) bool {
	switch op {
	case OpBaseline, OpRevalidate, OpIntent, OpApply, OpAcknowledge, OpIntervention, OpRemove, OpRecovery, OpCleanup, OpReceipt, OpFinalize:
		return true
	default:
		return false
	}
}
func boolean(value bool) *bool { return &value }
