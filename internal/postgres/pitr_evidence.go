package postgres

import (
	"errors"
	"path/filepath"
	"time"

	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

type PITRRow struct {
	ID           int
	Payload, XID string
}
type PITRMeasurements struct {
	Prepared                                                    PITRPrepared
	BackupVerified, WALVerified, FailureObserved                bool
	Destination                                                 DBIdentity
	TargetObservation, PromotedObservation, TimelineHistory     string
	TargetObserved, TargetFidelity, SchemaObserved, SchemaMatch bool
	Promoted, ReadWriteReady, IntegrityObserved, IntegrityOK    bool
	Timeline                                                    FailureTimeline
	Rows                                                        []PITRRow
	Receipts                                                    []PITRReceipt
	ReceiptCoverage, DataLossExact                              bool
	Missing, Unexpected, Duplicates, Corrupt, Uncertain         []int
	RecoveryPoint                                               int
	AcknowledgedLossGapNS                                       *int64
}
type PITRReport struct {
	Version       string                   `json:"version"`
	Run           string                   `json:"run"`
	Plan          string                   `json:"plan"`
	ExecutionPlan string                   `json:"executionPlan"`
	Verdict       result.Verdict           `json:"verdict"`
	Execution     result.ExecutionStatus   `json:"execution"`
	Live          bool                     `json:"liveTrustedExecution"`
	Provenance    string                   `json:"provenance"`
	At            time.Time                `json:"at"`
	Measurements  PITRMeasurements         `json:"measurements"`
	Assertions    []result.AssertionResult `json:"assertions"`
	Cleanup       CleanupReceipt           `json:"cleanup"`
	Problem       string                   `json:"problem,omitempty"`
}

var pitrRequired = []string{"authorization", "backup-and-wal", "unclean-failure", "target-proof", "target-fidelity", "promotion", "schema", "integrity", "readiness", "receipts", "acknowledged-loss", "recovery-time", "cleanup", "unambiguous"}

func assessPITR(p PITRPlan, m PITRMeasurements, c CleanupReceipt, problem string) []result.AssertionResult {
	var out []result.AssertionResult
	add := func(id string, observed, ok bool) {
		v, e := result.Inconclusive, result.Missing
		if observed {
			v, e = result.Pass, result.Sufficient
			if !ok {
				v = result.Fail
			}
		}
		out = append(out, result.AssertionResult{ID: id, Verdict: v, Evidence: e})
	}
	add("authorization", true, true)
	add("backup-and-wal", m.BackupVerified && m.WALVerified, true)
	add("unclean-failure", m.FailureObserved && m.Timeline.KillAcknowledged && !m.Timeline.KillAmbiguous, true)
	add("target-proof", m.TargetObserved, true)
	add("target-fidelity", m.TargetObserved && m.ReceiptCoverage, m.TargetFidelity)
	add("promotion", m.Promoted, true)
	add("schema", m.SchemaObserved, m.SchemaMatch)
	add("integrity", m.IntegrityObserved, m.IntegrityOK)
	add("readiness", m.ReadWriteReady, true)
	add("receipts", m.ReceiptCoverage, true)
	add("acknowledged-loss", m.DataLossExact || len(m.Missing) > p.Contract.MaxLostCommits, len(m.Missing) <= p.Contract.MaxLostCommits)
	add("recovery-time", m.ReadWriteReady && m.FailureObserved && validTimeline(m.Timeline), m.Timeline.RecoveryUpperNS <= p.Contract.MaxRecoveryMillis*int64(time.Millisecond))
	add("cleanup", c.Complete, true)
	add("unambiguous", problem == "" && len(m.Uncertain) == 0, true)
	return out
}
func PITRExitCode(r PITRReport) int {
	if r.Execution == result.CleanupPending || (r.Version == PITRVersion && !r.Cleanup.Complete) {
		return 7
	}
	if r.Verdict == result.Pass {
		return 0
	}
	if r.Verdict == result.Fail {
		return 3
	}
	return 4
}

// Replay deliberately never authenticates an unsigned execution, including one
// with internally consistent fabricated measurements and a replacement key.
func ReplayPITR(dir string) (r PITRReport, err error) {
	b, err := readBounded(filepath.Join(dir, "pitr-report.json"))
	if err != nil {
		return r, err
	}
	if err = localstate.Unmarshal(b, &r); err != nil {
		return r, err
	}
	if r.Version != PITRVersion || !hexID.MatchString(r.Run) || !hexID.MatchString(r.Plan) {
		return r, errors.New("PITR historical report identity invalid")
	}
	r.Live = false
	r.Verdict = result.Inconclusive
	r.Provenance = "unsigned historical claims; embedded keys and receipts do not attest execution"
	r.Measurements.DataLossExact = false
	for n := range r.Assertions {
		r.Assertions[n].Verdict = result.Inconclusive
		r.Assertions[n].Evidence = result.Insufficient
		r.Assertions[n].Reason = "whole execution unauthenticated"
	}
	return r, nil
}
