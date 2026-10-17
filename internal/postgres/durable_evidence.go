package postgres

import (
	"errors"
	"path/filepath"
	"time"

	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

type FailureTimeline struct {
	Anchor                                                 string
	IntentNS, LastAvailableStartNS, LastAvailableEndNS     int64
	KillStartNS, KillEndNS                                 int64
	KillExit                                               *int
	KillAcknowledged, KillAmbiguous                        bool
	FirstUnavailableStartNS, FirstUnavailableEndNS         int64
	RestoreStartNS, ReadyNS                                int64
	FailureUncertaintyNS, RecoveryUpperNS, RecoveryLowerNS int64
	Clock                                                  string
}
type DurableMeasurements struct {
	Backup                                                 DurableBackup
	BackupVerified, FailureObserved, SourceVolumePersisted bool
	Timeline                                               FailureTimeline
	RestoreExit                                            *int
	SchemaObserved, SchemaMatch, ReadWriteReady            bool
	IntegrityObserved, IntegrityOK                         bool
	StorageBefore, StorageAfter                            StorageObservation
	ExpectedCommits                                        int
	Receipts                                               []DurableReceipt
	ReceiptCoverage, DataLossExact                         bool
	Rows                                                   []Row
	Missing, Unexpected, Duplicates, Corrupt, Uncertain    []int
	RecoveryPoint                                          int
	// Cross-process receipt times have no shared monotonic clock. Deliberately
	// leave this unknown instead of manufacturing a time-based RPO estimate.
	AcknowledgedLossGapNS *int64
}
type DurableReport struct {
	Version      string                   `json:"version"`
	Run          string                   `json:"run"`
	Plan         string                   `json:"plan"`
	Verdict      result.Verdict           `json:"verdict"`
	Execution    result.ExecutionStatus   `json:"execution"`
	Live         bool                     `json:"liveTrustedExecution"`
	Provenance   string                   `json:"provenance"`
	At           time.Time                `json:"at"`
	Measurements DurableMeasurements      `json:"measurements"`
	Assertions   []result.AssertionResult `json:"assertions"`
	Cleanup      CleanupReceipt           `json:"cleanup"`
	Problem      string                   `json:"problem,omitempty"`
}

var durableRequired = []string{"authorization", "backup", "unclean-failure", "persistent-source", "restore", "readiness", "schema", "integrity", "receipts", "data-loss", "recovery-time", "cleanup", "unambiguous"}

func assessDurable(p DurablePlan, m DurableMeasurements, clean CleanupReceipt, problem string) []result.AssertionResult {
	var out []result.AssertionResult
	add := func(id string, observed, ok bool) {
		v, c := result.Inconclusive, result.Missing
		if observed {
			v, c = result.Pass, result.Sufficient
			if !ok {
				v = result.Fail
			}
		}
		out = append(out, result.AssertionResult{ID: id, Verdict: v, Evidence: c})
	}
	add("authorization", true, true)
	add("backup", m.BackupVerified, true)
	add("unclean-failure", m.FailureObserved && !m.Timeline.KillAmbiguous && m.Timeline.KillAcknowledged, true)
	add("persistent-source", m.SourceVolumePersisted, true)
	add("restore", m.RestoreExit != nil && *m.RestoreExit == 0, true)
	add("readiness", m.ReadWriteReady, true)
	add("schema", m.SchemaObserved, m.SchemaMatch)
	add("integrity", m.IntegrityObserved, m.IntegrityOK)
	add("receipts", m.ReceiptCoverage, true)
	add("data-loss", m.DataLossExact || len(m.Missing) > p.Contract.MaxLostCommits, len(m.Missing) <= p.Contract.MaxLostCommits)
	add("recovery-time", m.ReadWriteReady && m.FailureObserved && validTimeline(m.Timeline), m.Timeline.RecoveryUpperNS <= p.Contract.MaxRecoveryMillis*int64(time.Millisecond))
	add("cleanup", clean.Complete, true)
	add("unambiguous", problem == "" && len(m.Uncertain) == 0, true)
	return out
}
func validTimeline(t FailureTimeline) bool {
	return t.Anchor == DurableAnchor && t.IntentNS > 0 && t.LastAvailableStartNS >= t.IntentNS && t.LastAvailableEndNS >= t.LastAvailableStartNS && t.KillStartNS >= t.LastAvailableEndNS && t.KillEndNS >= t.KillStartNS && t.FirstUnavailableStartNS >= t.KillEndNS && t.FirstUnavailableEndNS >= t.FirstUnavailableStartNS && t.RestoreStartNS >= t.FirstUnavailableEndNS && t.ReadyNS >= t.RestoreStartNS && t.FailureUncertaintyNS == t.FirstUnavailableEndNS-t.LastAvailableStartNS && t.RecoveryUpperNS == t.ReadyNS-t.LastAvailableStartNS && t.RecoveryLowerNS == t.ReadyNS-t.FirstUnavailableEndNS && t.RecoveryUpperNS > 0
}
func DurableExitCode(r DurableReport) int {
	if r.Execution == result.CleanupPending {
		return 7
	}
	switch r.Verdict {
	case result.Pass:
		return 0
	case result.Fail:
		return 3
	}
	return 4
}
func ReplayDurable(dir string) (DurableReport, error) {
	var r DurableReport
	var p DurablePlan
	read := func(name string, v any) error {
		b, e := readBounded(filepath.Join(dir, name))
		if e != nil {
			return e
		}
		return localstate.Unmarshal(b, v)
	}
	if e := read("durable-report.json", &r); e != nil {
		return r, e
	}
	if e := read("durable-plan.json", &p); e != nil {
		return r, e
	}
	if e := p.Validate(); e != nil {
		return r, e
	}
	if r.Version != DurableVersion || r.Plan != p.Digest || r.Run != p.Inventory.Run {
		return r, errors.New("durable replay identity mismatch")
	}
	for _, name := range []string{"durable-prepare.jsonl", "durable-journal.jsonl"} {
		b, e := readBounded(filepath.Join(dir, name))
		if e != nil {
			return r, e
		}
		if e = VerifyDurableJournal(b, p.Digest); e != nil {
			return r, e
		}
	}
	r.Live = false
	r.Provenance = "unsigned historical candidate; embedded public keys do not authenticate execution"
	r.Verdict = result.Inconclusive
	r.Measurements.DataLossExact = false
	expected := BaselineCommits
	if p.Contract.Scenario == "ack-loss" {
		expected += 3
	}
	r.Measurements.ReceiptCoverage = verifyDurableReceipts(r.Measurements.Receipts, p, expected) == nil
	for n := range r.Assertions {
		r.Assertions[n].Verdict = result.Inconclusive
		r.Assertions[n].Evidence = result.Insufficient
		r.Assertions[n].Reason = "whole execution is not authenticated"
	}
	return r, nil
}
