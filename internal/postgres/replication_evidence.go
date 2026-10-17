package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

type ReplicationMeasurements struct {
	StorageBefore                                                                                               map[string]ReplicationStorage
	StorageAfter                                                                                                ReplicationStorage
	Prepared                                                                                                    ReplicationPrepared
	Authorization, ReplicationVerified, FailureObserved, Fenced, PrimaryAbsentAfterReady                        bool
	BeforeFailure                                                                                               ReplicationObservation
	Timeline                                                                                                    FailureTimeline
	FenceStartNS, FenceEndNS, PromotionStartNS, PromotionEndNS                                                  int64
	FenceExit, PromotionExit                                                                                    *int
	FenceAcknowledged, PromotionAcknowledged, PromotionObserved                                                 bool
	PromotionObservation, TimelineHistory                                                                       string
	Destination                                                                                                 DBIdentity
	LastReceivedLSN, LastReplayedLSN                                                                            string
	Rows                                                                                                        []PITRRow
	Receipts                                                                                                    []ReplicationReceipt
	ReceiptCoverage, DataLossExact, SchemaObserved, SchemaMatch, IntegrityObserved, IntegrityOK, ReadWriteReady bool
	Missing, Unexpected, Duplicates, Corrupt, Uncertain                                                         []int
	RecoveryPoint                                                                                               int
	AcknowledgedLossGapNS                                                                                       *int64
}
type ReplicationReport struct {
	Version       string                   `json:"version"`
	Run           string                   `json:"run"`
	Plan          string                   `json:"plan"`
	ExecutionPlan string                   `json:"executionPlan"`
	Verdict       result.Verdict           `json:"verdict"`
	Execution     result.ExecutionStatus   `json:"execution"`
	Live          bool                     `json:"liveTrustedExecution"`
	Provenance    string                   `json:"provenance"`
	At            time.Time                `json:"at"`
	Measurements  ReplicationMeasurements  `json:"measurements"`
	Assertions    []result.AssertionResult `json:"assertions"`
	Cleanup       CleanupReceipt           `json:"cleanup"`
	Problem       string                   `json:"problem,omitempty"`
}

var replicationRequired = []string{"authorization", "replication", "fencing", "promotion", "readiness", "receipts", "schema", "integrity", "acknowledged-loss", "failover-time", "cleanup", "unambiguous"}

func validReplicationTimeline(m ReplicationMeasurements) bool {
	return validTimeline(m.Timeline) && m.FenceStartNS >= m.Timeline.FirstUnavailableEndNS && m.FenceEndNS >= m.FenceStartNS && m.PromotionStartNS >= m.FenceEndNS && m.PromotionEndNS >= m.PromotionStartNS && m.Timeline.ReadyNS >= m.PromotionEndNS
}
func assessReplication(p ReplicationPlan, m ReplicationMeasurements, c CleanupReceipt, problem string) []result.AssertionResult {
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
	add("authorization", m.Authorization, true)
	add("replication", m.ReplicationVerified, true)
	add("fencing", m.Fenced && m.FailureObserved && m.Timeline.KillAcknowledged && !m.Timeline.KillAmbiguous, true)
	add("promotion", m.PromotionAcknowledged && m.PromotionObserved && m.PrimaryAbsentAfterReady, true)
	add("readiness", m.ReadWriteReady, true)
	add("receipts", m.ReceiptCoverage, true)
	add("schema", m.SchemaObserved, m.SchemaMatch)
	add("integrity", m.IntegrityObserved, m.IntegrityOK && len(m.Unexpected)+len(m.Duplicates)+len(m.Corrupt) == 0)
	add("acknowledged-loss", m.DataLossExact, len(m.Missing) <= p.Contract.MaxLostCommits)
	bound := p.Contract.MaxFailoverMillis * int64(time.Millisecond)
	measured := m.ReadWriteReady && m.Fenced && m.ReplicationVerified && m.PromotionObserved && validReplicationTimeline(m)
	decided := measured && (m.Timeline.RecoveryUpperNS <= bound || m.Timeline.RecoveryLowerNS > bound)
	add("failover-time", decided, m.Timeline.RecoveryUpperNS <= bound)
	add("cleanup", c.Complete, true)
	add("unambiguous", problem == "" && len(m.Uncertain) == 0, true)
	return out
}
func ReplicationExitCode(r ReplicationReport) int {
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
func ReplayReplication(dir string) (r ReplicationReport, err error) {
	b, err := readBounded(filepath.Join(dir, "replication-report.json"))
	if err != nil {
		return r, err
	}
	if err = localstate.Unmarshal(b, &r); err != nil {
		return r, err
	}
	if r.Version != ReplicationVersion || !hexID.MatchString(r.Run) || !hexID.MatchString(r.Plan) {
		return r, errors.New("replication historical identity invalid")
	}
	r.Live = false
	r.Verdict = result.Inconclusive
	r.Provenance = "unsigned historical claims; embedded keys and receipts do not attest whole execution"
	r.Measurements.DataLossExact = false
	for n := range r.Assertions {
		r.Assertions[n].Verdict = result.Inconclusive
		r.Assertions[n].Evidence = result.Insufficient
		r.Assertions[n].Reason = "whole execution unauthenticated"
	}
	return r, nil
}

func replicationObserveData(ctx context.Context, d Docker, p ReplicationPlan, s ReplicationPrepared, m *ReplicationMeasurements) error {
	rs, err := loadReplicationReceipts(p)
	if err != nil {
		return errors.New("independent acknowledged COMMIT evidence unavailable")
	}
	if digest("replication-ledger", rs) != s.ReceiptHash {
		return errors.New("acknowledged COMMIT ledger differs from approval")
	}
	m.Receipts = rs
	m.ReceiptCoverage = true
	v, err := d.replicationSQL(ctx, p.Inventory.Standby.ID, `SELECT coalesce(json_agg(x ORDER BY id),'[]'::json) FROM (SELECT id,payload,xmin::text AS "XID" FROM themis_app.transactions) x;`)
	if err != nil {
		return err
	}
	if json.Unmarshal([]byte(v), &m.Rows) != nil {
		return errors.New("promoted transaction observations invalid")
	}
	m.Missing, m.Corrupt, m.Unexpected, m.Duplicates = nil, nil, nil, nil
	m.RecoveryPoint = 0
	seen := map[int]bool{}
	actual := map[int]PITRRow{}
	for _, r := range m.Rows {
		if seen[r.ID] {
			m.Duplicates = append(m.Duplicates, r.ID)
		}
		seen[r.ID] = true
		actual[r.ID] = r
		if r.ID < 1 || r.ID > replicationCommits {
			m.Unexpected = append(m.Unexpected, r.ID)
		}
	}
	for _, r := range rs {
		got, ok := actual[r.ID]
		if !ok {
			m.Missing = append(m.Missing, r.ID)
			continue
		}
		if got.Payload != r.Payload || got.XID != r.XID {
			m.Corrupt = append(m.Corrupt, r.ID)
			continue
		}
		if r.ID == m.RecoveryPoint+1 {
			m.RecoveryPoint = r.ID
		}
	}
	m.DataLossExact = true
	v, err = d.replicationSQL(ctx, p.Inventory.Standby.ID, schemaSQL)
	if err != nil {
		return err
	}
	m.SchemaObserved, m.SchemaMatch = true, v == s.Schema
	v, err = d.replicationSQL(ctx, p.Inventory.Standby.ID, "SELECT id||':'||balance FROM themis_app.accounts ORDER BY id;")
	if err != nil {
		return err
	}
	m.IntegrityObserved, m.IntegrityOK = true, v == "1:9980\n2:10020"
	return nil
}
