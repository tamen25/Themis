package postgres

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

// ReplicationEvidence is a pure review of a frozen public export. Observation
// signatures use embedded setup keys; nothing here asserts honest live sensors.
type ReplicationEvidence struct {
	PublicPlan PublicReplicationPlan
	Plan       ReplicationPlan
	Report     ReplicationReport
	Candidate  result.Verdict
	Complete   bool
	Signatures int
	Problems   []string
}

const PublicReplicationVersion = "themis.postgres-replication-public/v1alpha1"

// PublicReplicationPlan deliberately excludes private ownership paths, actors,
// sockets, capabilities and resource inventories. Original SHA-256 plan and
// inventory references are opaque commitments, not recompiled private records.
type PublicReplicationPlan struct {
	Version                                    string
	OriginalPlan, OriginalInventory, Run       string
	Contract                                   ReplicationContract
	PrimaryID, StandbyID, PrimaryIP, StandbyIP string
	NetworkID                                  string
	Primary, Standby                           DBIdentity
	LedgerKey                                  []byte
	AuthorityKeyIDs                            []string
	Digest                                     string
}

func PublicReplicationPlanFrom(p ReplicationPlan) PublicReplicationPlan {
	i := p.Inventory
	keys := []string{}
	for _, key := range [][]byte{i.PrepareKey, i.TerminationKey, i.PromotionKey, i.LedgerKey, i.CleanupKey} {
		keys = append(keys, publicKeyHash(key))
	}
	sort.Strings(keys)
	v := PublicReplicationPlan{Version: PublicReplicationVersion, OriginalPlan: p.Digest, OriginalInventory: replicationInventoryHash(i), Run: i.Run, Contract: p.Contract, PrimaryID: i.Primary.ID, StandbyID: i.Standby.ID, PrimaryIP: i.PrimaryIP, StandbyIP: i.StandbyIP, NetworkID: i.Network.ID, Primary: i.Primary.DB, Standby: i.Standby.DB, LedgerKey: i.LedgerKey, AuthorityKeyIDs: keys}
	v.Digest = publicReplicationDigest(v)
	return v
}
func publicKeyHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func publicReplicationDigest(v PublicReplicationPlan) string {
	v.Digest = ""
	return digest(PublicReplicationVersion, v)
}
func (v PublicReplicationPlan) validate() error {
	if v.Version != PublicReplicationVersion || v.Digest != publicReplicationDigest(v) || v.Contract.Validate() != nil || !hexID.MatchString(v.OriginalPlan) || !hexID.MatchString(v.OriginalInventory) || !hexID.MatchString(v.Run) || !hexID.MatchString(v.PrimaryID) || !hexID.MatchString(v.StandbyID) || v.PrimaryID == v.StandbyID || v.Primary.System == "" || v.Primary.System != v.Standby.System || v.Primary.Boot == "" || v.Standby.Boot == "" || v.Primary.Boot == v.Standby.Boot || !replicationIP(v.PrimaryIP) || !replicationIP(v.StandbyIP) || v.PrimaryIP == v.StandbyIP || len(v.LedgerKey) != 32 || len(v.AuthorityKeyIDs) != 5 || !sort.StringsAreSorted(v.AuthorityKeyIDs) {
		return errors.New("invalid public replication plan digest or identities")
	}
	ledger := false
	if !hexID.MatchString(v.NetworkID) {
		return errors.New("invalid original network identity summary")
	}
	for n, key := range v.AuthorityKeyIDs {
		if !hexID.MatchString(key) || n > 0 && key == v.AuthorityKeyIDs[n-1] {
			return errors.New("invalid public authority commitments")
		}
		if key == publicKeyHash(v.LedgerKey) {
			ledger = true
		}
	}
	if !ledger {
		return errors.New("ledger key commitment absent")
	}
	return nil
}

// CheckReplicationEvidence never loads private state or calls Docker. Only these
// exact public bytes are inspected. Missing evidence is reported, never invented.
func CheckReplicationEvidence(files map[string][]byte) (v ReplicationEvidence, err error) {
	v.Candidate = result.Inconclusive
	v.Problems = []string{}
	read := func(name string, out any) error {
		b, ok := files[name]
		if !ok {
			return errors.New("missing public replication artifact")
		}
		return localstate.Unmarshal(b, out)
	}
	if err = read("artifacts/replication-plan.json", &v.PublicPlan); err != nil {
		return v, err
	}
	if err = v.PublicPlan.validate(); err != nil {
		return v, err
	}
	if err = read("artifacts/replication-report.json", &v.Report); err != nil {
		return v, err
	}
	x := v.PublicPlan
	v.Plan = ReplicationPlan{Version: ReplicationVersion, Contract: x.Contract, Digest: x.OriginalPlan, Inventory: ReplicationInventory{Run: x.Run, Primary: Resource{ID: x.PrimaryID, DB: x.Primary}, Standby: Resource{ID: x.StandbyID, DB: x.Standby}, PrimaryIP: x.PrimaryIP, StandbyIP: x.StandbyIP, LedgerKey: x.LedgerKey}}
	p, r := v.Plan, v.Report
	m := r.Measurements
	s := m.Prepared
	if r.Version != ReplicationVersion || r.Run != p.Inventory.Run || r.Plan != p.Digest || r.ExecutionPlan != s.Digest || r.Cleanup.Version != ReplicationVersion || r.Cleanup.Run != r.Run {
		return v, errors.New("replication report identity mismatch")
	}
	switch r.Execution {
	case result.Succeeded, result.Failed, result.Cancelled, result.TimedOut, result.Error, result.CleanupPending:
	default:
		return v, errors.New("unsupported replication execution status")
	}
	if s.Version != ReplicationVersion || s.Plan != p.Digest || s.Inventory != x.OriginalInventory || !hexID.MatchString(s.Invocation) || s.Receipts != replicationCommits || s.Schema == "" || s.Digest != replicationPreparedDigest(s) || !ed25519.Verify(p.Inventory.LedgerKey, []byte(s.Digest), s.Signature) || !validReplicationState(p.Inventory, s.State, s.LastAckLSN) {
		return v, errors.New("invalid embedded preparation signature or state")
	}
	v.Signatures++
	var prepared ReplicationPrepared
	if b, ok := files["artifacts/replication-prepared.json"]; ok {
		if localstate.Unmarshal(b, &prepared) != nil || !reflect.DeepEqual(prepared, s) {
			return v, errors.New("preparation artifact differs from report")
		}
	} else {
		v.Problems = append(v.Problems, "MISSING_PREPARED_ARTIFACT")
	}
	var receipts []ReplicationReceipt
	if b, ok := files["artifacts/replication-receipts.json"]; ok {
		if localstate.Unmarshal(b, &receipts) != nil {
			return v, errors.New("invalid public receipts")
		}
		if verifyReplicationReceipts(receipts, p) != nil {
			return v, errors.New("receipt signature, coverage or binding invalid")
		}
		if digest("replication-ledger", receipts) != s.ReceiptHash {
			return v, errors.New("prepared receipt commitment mismatch")
		}
		if receipts[len(receipts)-1].FlushLSN != s.LastAckLSN {
			return v, errors.New("prepared last acknowledgement differs from receipt ledger")
		}
		v.Signatures += len(receipts)
	} else {
		v.Problems = append(v.Problems, "MISSING_RECEIPTS")
	}
	if len(m.Receipts) > 0 {
		if verifyReplicationReceipts(m.Receipts, p) != nil || !reflect.DeepEqual(m.Receipts, receipts) {
			return v, errors.New("reported receipts differ from verified ledger")
		}
	} else if m.ReceiptCoverage || m.DataLossExact {
		return v, errors.New("receipt coverage claimed without measurements")
	}
	parse := func(name string) ([]Event, error) {
		b, ok := files[name]
		if !ok {
			v.Problems = append(v.Problems, "MISSING_"+strings.ToUpper(filepath.Base(name)))
			return nil, nil
		}
		if verifyJournal(b, p.Digest, ReplicationVersion) != nil {
			return nil, errors.New("invalid replication journal chain")
		}
		var events []Event
		for _, line := range bytes.Split(bytes.TrimSuffix(b, []byte{'\n'}), []byte{'\n'}) {
			var e Event
			if localstate.Unmarshal(line, &e) != nil {
				return nil, errors.New("invalid replication event")
			}
			events = append(events, e)
		}
		return events, nil
	}
	prep, e := parse("artifacts/replication-prepare.jsonl")
	if e != nil {
		return v, e
	}
	if len(prep) > 0 {
		var intent struct {
			Plan     string              `json:"plan"`
			Contract ReplicationContract `json:"contract"`
			Run      string              `json:"run"`
			Primary  string              `json:"primary"`
			Standby  string              `json:"standby"`
		}
		if localstate.Unmarshal(prep[0].Detail, &intent) != nil || intent.Plan != p.Digest || intent.Contract != p.Contract || intent.Run != x.Run || intent.Primary != x.PrimaryID || intent.Standby != x.StandbyID {
			return v, errors.New("preparation contract, plan or original target identity differs from public projection")
		}
		if prep[0].Kind != "PREPARE_INTENT" || prep[len(prep)-1].Kind != "PREPARED" {
			v.Problems = append(v.Problems, "PREPARATION_INCOMPLETE")
		} else {
			var last ReplicationPrepared
			if localstate.Unmarshal(prep[len(prep)-1].Detail, &last) != nil || !reflect.DeepEqual(last, s) {
				return v, errors.New("preparation journal seal mismatch")
			}
			acks := []ReplicationReceipt{}
			expectedID := 1
			pending := false
			for _, event := range prep[1 : len(prep)-1] {
				switch event.Kind {
				case "COMMIT_INTENT":
					var intent struct {
						ID int `json:"id"`
					}
					if pending || localstate.Unmarshal(event.Detail, &intent) != nil || intent.ID != expectedID {
						return v, errors.New("preparation intent order invalid")
					}
					pending = true
				case "COMMIT_ACKNOWLEDGED":
					var ack ReplicationReceipt
					if !pending || localstate.Unmarshal(event.Detail, &ack) != nil || ack.ID != expectedID {
						return v, errors.New("preparation acknowledgement order invalid")
					}
					acks = append(acks, ack)
					expectedID++
					pending = false
				default:
					return v, errors.New("unsupported preparation lifecycle")
				}
			}
			if pending || len(acks) != replicationCommits || !reflect.DeepEqual(acks, receipts) {
				return v, errors.New("preparation journal receipt mismatch")
			}
		}
	}
	events, e := parse("artifacts/replication-journal.jsonl")
	if e != nil {
		return v, e
	}
	seen := map[string]Event{}
	lastRank := -1
	order := []string{"FAILOVER_ADMITTED", "PRIMARY_TERMINATION_INTENT", "LAST_PRIMARY_WRITE_AND_REPLICATION", "TERMINATION_OUTCOME", "PRIMARY_STOPPED_OBSERVED", "FENCE_REMOVE_INTENT", "FENCE_COMMAND_OUTCOME", "PRIMARY_ABSENCE_VERIFIED", "PROMOTION_INTENT", "PROMOTION_COMMAND_OUTCOME", "PROMOTION_INDEPENDENTLY_OBSERVED", "WRITE_READY", "CLEANUP_OBSERVED", "FINAL"}
	rank := map[string]int{}
	for n, k := range order {
		rank[k] = n
	}
	for _, event := range events {
		n, ok := rank[event.Kind]
		if !ok || n <= lastRank {
			return v, errors.New("invalid or repeated failover lifecycle")
		}
		lastRank = n
		seen[event.Kind] = event
	}
	if len(events) > 0 {
		var admitted struct {
			ExecutionPlan string `json:"executionPlan"`
			Invocation    string `json:"invocation"`
		}
		if events[0].Kind != "FAILOVER_ADMITTED" || localstate.Unmarshal(events[0].Detail, &admitted) != nil || admitted.ExecutionPlan != s.Digest || admitted.Invocation != s.Invocation {
			return v, errors.New("invocation or execution plan mismatch")
		}
		if clean, ok := seen["CLEANUP_OBSERVED"]; ok {
			var c CleanupReceipt
			if localstate.Unmarshal(clean.Detail, &c) != nil || !reflect.DeepEqual(c, r.Cleanup) {
				return v, errors.New("cleanup journal/report mismatch")
			}
		} else {
			v.Problems = append(v.Problems, "MISSING_CLEANUP_OBSERVATION")
		}
		if final, ok := seen["FINAL"]; ok {
			var f struct {
				Verdict   result.Verdict         `json:"verdict"`
				Execution result.ExecutionStatus `json:"execution"`
			}
			if localstate.Unmarshal(final.Detail, &f) != nil || f.Verdict != r.Verdict || f.Execution != r.Execution {
				return v, errors.New("historical verdict or execution differs from final event")
			}
		} else {
			v.Problems = append(v.Problems, "MISSING_FINAL")
		}
	}
	if m.ReadWriteReady {
		for _, kind := range order {
			if _, ok := seen[kind]; !ok {
				return v, errors.New("claimed recovery lacks required lifecycle observations")
			}
		}
		var recorded ReplicationMeasurements
		if localstate.Unmarshal(seen["WRITE_READY"].Detail, &recorded) != nil || !reflect.DeepEqual(recorded, m) {
			return v, errors.New("recovery measurements differ from journal")
		}
		var before ReplicationObservation
		if localstate.Unmarshal(seen["LAST_PRIMARY_WRITE_AND_REPLICATION"].Detail, &before) != nil || !reflect.DeepEqual(before, m.BeforeFailure) {
			return v, errors.New("pre-failure replication observation differs from report")
		}
		if !m.ReceiptCoverage || !m.DataLossExact || !validReplicationTimeline(m) || !validReplicationState(p.Inventory, m.BeforeFailure, s.LastAckLSN) {
			return v, errors.New("invalid recovery predicates or coverage")
		}
	}
	if m.DataLossExact {
		if !m.ReceiptCoverage || m.Rows == nil || !m.PromotionObserved {
			return v, errors.New("exact data-loss claim lacks observed rows, receipts or promotion")
		}
		actual := map[int]PITRRow{}
		duplicates := []int{}
		unexpected := []int{}
		corrupt := []int{}
		missing := []int{}
		point := 0
		for _, row := range m.Rows {
			if _, ok := actual[row.ID]; ok {
				duplicates = append(duplicates, row.ID)
			}
			actual[row.ID] = row
			if row.ID < 1 || row.ID > replicationCommits {
				unexpected = append(unexpected, row.ID)
			}
		}
		for _, receipt := range receipts {
			row, ok := actual[receipt.ID]
			if !ok {
				missing = append(missing, receipt.ID)
				continue
			}
			if row.Payload != receipt.Payload || row.XID != receipt.XID {
				corrupt = append(corrupt, receipt.ID)
				continue
			}
			if receipt.ID == point+1 {
				point = receipt.ID
			}
		}
		if !equalInts(m.Missing, missing) || !equalInts(m.Corrupt, corrupt) || !equalInts(m.Unexpected, unexpected) || !equalInts(m.Duplicates, duplicates) || m.RecoveryPoint != point {
			return v, errors.New("data-loss predicates differ from receipt/row comparison")
		}
	}
	// Recheck critical effect identities and observations independently of the
	// report booleans. These remain unsigned local claims, never physical proof.
	detail := func(kind string, out any) error {
		e, ok := seen[kind]
		if !ok {
			return errors.New("claimed effect lacks journal observation")
		}
		return localstate.Unmarshal(e.Detail, out)
	}
	if m.FailureObserved {
		var intent struct {
			Primary       string `json:"primary"`
			ExecutionPlan string `json:"executionPlan"`
			Invocation    string `json:"invocation"`
		}
		var stopped FailureTimeline
		if detail("PRIMARY_TERMINATION_INTENT", &intent) != nil || intent.Primary != x.PrimaryID || intent.ExecutionPlan != s.Digest || intent.Invocation != s.Invocation || detail("PRIMARY_STOPPED_OBSERVED", &stopped) != nil || stopped.FirstUnavailableEndNS != m.Timeline.FirstUnavailableEndNS || stopped.KillAcknowledged != m.Timeline.KillAcknowledged || stopped.KillAmbiguous != m.Timeline.KillAmbiguous {
			return v, errors.New("termination identity or independent stop observation mismatch")
		}
	}
	if m.Fenced {
		var absent struct {
			Primary string `json:"originalPrimary"`
		}
		var removal struct {
			Primary string `json:"primary"`
		}
		var ack struct {
			Exit         *int `json:"exit"`
			Acknowledged bool `json:"acknowledged"`
		}
		if !m.FailureObserved || !m.FenceAcknowledged || m.FenceExit == nil || *m.FenceExit != 0 || detail("FENCE_REMOVE_INTENT", &removal) != nil || removal.Primary != x.PrimaryID || detail("PRIMARY_ABSENCE_VERIFIED", &absent) != nil || absent.Primary != x.PrimaryID || detail("FENCE_COMMAND_OUTCOME", &ack) != nil || !ack.Acknowledged || !reflect.DeepEqual(ack.Exit, m.FenceExit) {
			return v, errors.New("fencing identity or acknowledgement mismatch")
		}
	}
	if m.PromotionObserved {
		var intent struct {
			Standby    string `json:"standby"`
			Invocation string `json:"invocation"`
		}
		var observed struct {
			Database DBIdentity `json:"database"`
			Timeline string     `json:"timeline"`
			History  string     `json:"history"`
		}
		fields := strings.Fields(m.TimelineHistory)
		want, e := pitrLSN(s.LastAckLSN)
		branch := uint64(0)
		if len(fields) > 1 {
			branch, _ = pitrLSN(fields[1])
		}
		if !m.Fenced || !m.PromotionAcknowledged || m.PromotionExit == nil || *m.PromotionExit != 0 || m.PromotionObservation != "f|00000002|" || m.Destination != x.Standby || len(fields) < 3 || fields[0] != "1" || e != nil || branch < want || detail("PROMOTION_INTENT", &intent) != nil || intent.Standby != x.StandbyID || intent.Invocation != s.Invocation || detail("PROMOTION_INDEPENDENTLY_OBSERVED", &observed) != nil || observed.Database != m.Destination || observed.Timeline != m.PromotionObservation || observed.History != m.TimelineHistory {
			return v, errors.New("promotion identity, timeline or observation mismatch")
		}
	}
	allowedActions := map[string]bool{"removed-container:" + x.PrimaryID: true, "removed-container:" + x.StandbyID: true, "removed-volume:themis-pgr-" + x.Run + "-primary": true, "removed-volume:themis-pgr-" + x.Run + "-standby": true, "removed-network:" + x.NetworkID: true, "private-control-state-retention:operator-managed": true}
	actions := map[string]bool{}
	for _, action := range r.Cleanup.Actions {
		if !allowedActions[action] || actions[action] {
			return v, errors.New("cleanup claims an unknown or repeated original resource")
		}
		actions[action] = true
	}
	if !r.Cleanup.Complete && r.Execution != result.CleanupPending || r.Execution == result.CleanupPending && r.Cleanup.Complete {
		return v, errors.New("cleanup disposition inconsistent")
	}
	a := assessReplication(p, m, r.Cleanup, r.Problem)
	v.Candidate = result.Aggregate(replicationRequired, a, result.RunEvidence{PreconditionsMet: true})
	if !reflect.DeepEqual(a, r.Assertions) || v.Candidate != r.Verdict {
		return v, errors.New("historical verdict does not match recomputed assertions")
	}
	v.Complete = len(v.Problems) == 0
	return v, nil
}

func equalInts(a, b []int) bool {
	return len(a) == len(b) && reflect.DeepEqual(append([]int{}, a...), append([]int{}, b...))
}
