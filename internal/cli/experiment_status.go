package cli

import (
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/tamen25/themis/internal/experiment"
)

func terminalField(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return '\uFFFD'
		}
		return r
	}, value)
}

func renderStatus(w io.Writer, r experiment.StatusReport, output string) error {
	if output == "json" {
		return encode(w, r)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Run: %s\nExperiment: %s\nPlan: %s\n", r.RunID, r.ContractName, r.PlanDigest)
	if r.Target != nil {
		fmt.Fprintf(&b, "Target instance: %s\n", r.Target.InstanceID)
	}
	fmt.Fprintf(&b, "Inventory usable: %t\nJournal: %s\nLast valid state: %s\nRecorded operation: %s\n", r.InventoryUsable, r.Journal.Integrity, r.Journal.LastState, r.Journal.Operation)
	if r.InventoryError != "" {
		fmt.Fprintf(&b, "Inventory error: %s\n", terminalField(r.InventoryError))
	}
	if r.Journal.Error != "" {
		fmt.Fprintf(&b, "Journal diagnostic: %s\n", terminalField(r.Journal.Error))
	}
	fmt.Fprintf(&b, "Execution disposition: %s\nRunner: %s\nFault application: %s\nLive fixture: %s\nLive fault: %s\n", r.ExecutionDisposition, r.Live.Runner, r.Application, r.Live.Fixture, r.Live.Fault)
	fmt.Fprintf(&b, "Fault application source: %s\n", r.ApplicationSource)
	if r.Live.ExpectedFaultExpiry != nil {
		fmt.Fprintf(&b, "Expected fault expiry: %s (%s)\n", r.Live.ExpectedFaultExpiry.Format("2006-01-02T15:04:05.999999999Z07:00"), r.Live.FaultExpirySource)
	}
	if r.Live.ExpectedFaultExpiry == nil {
		fmt.Fprintln(&b, "Expected fault expiry: unknown; only lease/fixture bounds may be available")
	}
	if r.Live.LeaseExpiresAt != nil {
		fmt.Fprintf(&b, "Fault lease expires: %s\n", r.Live.LeaseExpiresAt.Format("2006-01-02T15:04:05Z07:00"))
	}
	if r.Live.FixtureExpiresAt != nil {
		fmt.Fprintf(&b, "Fixture lifetime expires: %s\n", r.Live.FixtureExpiresAt.Format("2006-01-02T15:04:05Z07:00"))
	}
	if r.Live.FaultDeadlineExpired != nil {
		fmt.Fprintf(&b, "Fault deadline expired: %t\n", *r.Live.FaultDeadlineExpired)
	}
	if r.History.OriginalReport != nil {
		h := r.History.OriginalReport
		fmt.Fprintf(&b, "Original measured verdict: %s\nOriginal execution: %s\nIntervention proven in original report: %t\nApplication assertion: %s\nRecovery proven in original report: %t\nOriginal cleanup: %t\nEvidence complete in original report: %t\nHistory source: %s\n", h.Verdict, h.Execution.Status, h.InterventionConfirmed, applicationAssertion(h), h.RecoveryObserved, h.CleanupCompleted, h.SufficientObservations, r.History.Source)
	} else {
		fmt.Fprintln(&b, "Original measured verdict: unavailable\nIntervention proven: unknown\nApplication contract: unknown\nRecovery proven: unknown\nEvidence completeness: incomplete or unavailable")
	}
	if r.LastCleanup != nil {
		fmt.Fprintf(&b, "Last recorded cleanup: %s at %s\n", r.LastCleanup.Disposition, r.LastCleanup.CheckedAt.Format("2006-01-02T15:04:05Z07:00"))
	} else {
		fmt.Fprintln(&b, "Last recorded cleanup: unavailable")
	}
	for _, probe := range r.Live.Residuals {
		fmt.Fprintf(&b, "Current listener %s: %s\n", probe.Endpoint, probe.Outcome)
	}
	fmt.Fprintf(&b, "Reconciliation necessary: %t\n", r.ReconciliationNecessary)
	for _, action := range r.OperatorActions {
		fmt.Fprintf(&b, "Operator action: %s\n", terminalField(action))
	}
	fmt.Fprintln(&b, "Provenance: unsigned local history; signed fixture messages do not authenticate client timing.")
	fmt.Fprintln(&b, "Resource disappearance establishes cleanup; application recovery requires recorded measurements.")
	_, err := io.WriteString(w, b.String())
	return err
}

func applicationAssertion(r *experiment.Report) string {
	for _, a := range r.Assertions {
		if a.ID == "application" {
			return string(a.Verdict)
		}
	}
	return "unavailable"
}

func renderCleanup(w io.Writer, r experiment.CleanupResult, output string) error {
	if output == "json" {
		return encode(w, r)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Run: %s\nAction: %s\nResources observed closed: %t\nDisposition: %s\n", r.RunID, r.Kind, r.Completed, r.Disposition)
	if r.ReceiptPersisted != nil {
		fmt.Fprintf(&b, "Cleanup receipt persisted: %t\n", *r.ReceiptPersisted)
	}
	if r.Failure != nil {
		fmt.Fprintf(&b, "Diagnostic: %s (%s)\n", terminalField(r.Failure.Reason), r.Failure.Code)
	}
	fmt.Fprintln(&b, "Historical experiment results are preserved. Resource cleanup does not establish application recovery.")
	_, err := io.WriteString(w, b.String())
	return err
}

func renderExperimentText(w io.Writer, r experiment.Report, p *experiment.Provenance) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Experiment: %s\nRun: %s\nExecution: %s\nVerdict from observations: %s\n", r.ContractName, r.RunID, r.Execution.Status, r.Verdict)
	attempted := "ambiguous"
	if r.FaultAttempted != nil {
		attempted = fmt.Sprint(*r.FaultAttempted)
	}
	fmt.Fprintf(&b, "Fault attempted: %s\nIntervention confirmed: %t\nRecovery observed: %t\nCleanup completed: %t\n", attempted, r.InterventionConfirmed, r.RecoveryObserved, r.CleanupCompleted)
	if p != nil {
		fmt.Fprintf(&b, "Provenance: %s\nFixture responses: %s\nClient timing: %s\nExecution attestation: %s\n", p.Source, p.FixtureResponses, p.ClientTiming, p.ExecutionAttestation)
	} else {
		fmt.Fprintln(&b, "Provenance: legacy unsigned journal; no authenticated execution attestation")
	}
	if r.Failure != nil {
		fmt.Fprintf(&b, "Failure: %s during %s (%s)\n", terminalField(r.Failure.Reason), r.Failure.Operation, r.Failure.Code)
	}
	fmt.Fprintln(&b, "Response signatures do not prove client timing or global network conditions.")
	_, err := io.WriteString(w, b.String())
	return err
}
