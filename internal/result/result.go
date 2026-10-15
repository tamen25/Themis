// Package result models verification verdicts separately from execution outcomes.
package result

type Verdict string

const (
	Pass         Verdict = "PASS"
	Fail         Verdict = "FAIL"
	Inconclusive Verdict = "INCONCLUSIVE"
	NotRun       Verdict = "NOT_RUN"
)

type ExecutionStatus string

const (
	Succeeded      ExecutionStatus = "SUCCEEDED"
	Failed         ExecutionStatus = "FAILED"
	Cancelled      ExecutionStatus = "CANCELLED"
	TimedOut       ExecutionStatus = "TIMED_OUT"
	Error          ExecutionStatus = "ERROR"
	CleanupPending ExecutionStatus = "CLEANUP_PENDING"
)

type ExecutionError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Execution struct {
	Status ExecutionStatus `json:"status"`
	Error  *ExecutionError `json:"error,omitempty"`
}

type EvidenceStatus string

const (
	Missing      EvidenceStatus = "MISSING"
	Insufficient EvidenceStatus = "INSUFFICIENT"
	Sufficient   EvidenceStatus = "SUFFICIENT"
)

type AssertionResult struct {
	ID             string          `json:"id"`
	Verdict        Verdict         `json:"verdict"`
	Evidence       EvidenceStatus  `json:"evidence"`
	Reason         string          `json:"reason,omitempty"`
	ExecutionError *ExecutionError `json:"executionError,omitempty"`
}

// RunEvidence contains run-wide prerequisites. A baseline has no intervention
// claim; a future fault experiment must independently observe its intervention.
type RunEvidence struct {
	PreconditionsMet     bool
	InterventionRequired bool
	InterventionObserved bool
	CollectionError      *ExecutionError
}

// Aggregate is pure and order-independent. Credible required FAIL dominates,
// then INCONCLUSIVE, then NOT_RUN. The required IDs come from the contract, not
// from providers: an omitted result must not disappear from the verdict.
// Other results remain visible to callers but do not affect this verdict.
// No declared required IDs means NOT_RUN.
func Aggregate(requiredIDs []string, results []AssertionResult, evidence RunEvidence) Verdict {
	if len(requiredIDs) == 0 {
		return NotRun
	}
	required := make(map[string]bool, len(requiredIDs))
	seen := make(map[string]bool, len(requiredIDs))
	inconclusive, notRun := false, false
	for _, id := range requiredIDs {
		if id == "" || required[id] {
			inconclusive = true
		}
		required[id] = true
	}
	for _, r := range results {
		if !required[r.ID] {
			continue
		}
		if r.ID == "" || seen[r.ID] {
			inconclusive = true
		}
		seen[r.ID] = true
		if r.ExecutionError != nil {
			inconclusive = true
			continue
		}
		switch r.Verdict {
		case Pass, Fail:
			if r.Evidence != Sufficient || r.ID == "" {
				inconclusive = true
			} else if r.Verdict == Fail {
				return Fail
			}
		case NotRun:
			notRun = true
		default:
			// Includes INCONCLUSIVE, zero values and unknown provider verdicts.
			inconclusive = true
		}
	}
	for _, id := range requiredIDs {
		if !seen[id] {
			inconclusive = true
		}
	}
	if inconclusive || evidence.CollectionError != nil {
		return Inconclusive
	}
	if notRun {
		return NotRun
	}
	if !evidence.PreconditionsMet || (evidence.InterventionRequired && !evidence.InterventionObserved) {
		return Inconclusive
	}
	return Pass
}
