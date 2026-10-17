package postgres

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

type Event struct {
	Version  string          `json:"version"`
	Plan     string          `json:"plan"`
	Sequence int             `json:"sequence"`
	OffsetNS int64           `json:"offsetNs"`
	Kind     string          `json:"kind"`
	Detail   json.RawMessage `json:"detail"`
	Previous string          `json:"previous"`
	Hash     string          `json:"hash"`
}
type syncWriter interface {
	io.Writer
	Sync() error
}
type journal struct {
	w              syncWriter
	start          time.Time
	plan, previous string
	sequence       int
	poisoned       bool
	version        string
}

func (j *journal) append(kind string, detail any) error {
	if j.poisoned {
		return errors.New("journal poisoned; no subsequent effect permitted")
	}
	b, e := json.Marshal(detail)
	if e != nil {
		j.poisoned = true
		return e
	}
	version := j.version
	if version == "" {
		version = Version
	}
	v := Event{Version: version, Plan: j.plan, Sequence: j.sequence + 1, OffsetNS: time.Since(j.start).Nanoseconds(), Kind: kind, Detail: b, Previous: j.previous}
	v.Hash = digest(eventDomain(version), v)
	b, e = json.Marshal(v)
	if e != nil {
		j.poisoned = true
		return e
	}
	b = append(b, '\n')
	if len(b) > 65536 {
		j.poisoned = true
		return errors.New("journal event exceeds bound")
	}
	n, e := j.w.Write(b)
	if e == nil && n != len(b) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = j.w.Sync()
	}
	if e != nil {
		j.poisoned = true
		return e
	}
	j.sequence++
	j.previous = v.Hash
	return nil
}
func VerifyJournal(data []byte, plan string) error {
	return verifyJournal(data, plan, Version)
}
func eventDomain(version string) string {
	if version == PITRVersion {
		return "themis.postgres.pitr.event.v1"
	}
	if version == DurableVersion {
		return "themis.postgres.durable.event.v1"
	}
	return "themis.postgres.event.v1"
}
func VerifyDurableJournal(data []byte, plan string) error {
	return verifyJournal(data, plan, DurableVersion)
}
func verifyJournal(data []byte, plan, version string) error {
	if len(data) > 1<<20 || len(data) == 0 || data[len(data)-1] != '\n' {
		return errors.New("journal truncated or oversized")
	}
	s := bufio.NewScanner(bytes.NewReader(data))
	s.Buffer(make([]byte, 4096), 65537)
	seq := 0
	prev := ""
	var offset int64
	for s.Scan() {
		var v Event
		if e := localstate.Unmarshal(s.Bytes(), &v); e != nil {
			return e
		}
		h := v.Hash
		v.Hash = ""
		seq++
		if v.Version != version || v.Plan != plan || v.Sequence != seq || v.Previous != prev || v.OffsetNS < offset || v.Kind == "" || digest(eventDomain(version), v) != h {
			return errors.New("journal chain or identity invalid")
		}
		prev = h
		offset = v.OffsetNS
	}
	return s.Err()
}

type Receipt struct {
	Version   string `json:"version"`
	Plan      string `json:"plan"`
	ID        int    `json:"id"`
	Payload   string `json:"payload"`
	XID       string `json:"xid"`
	AckNS     int64  `json:"ackNs"`
	Previous  string `json:"previous"`
	Signature []byte `json:"signature"`
}

func receiptMessage(r Receipt) []byte {
	r.Signature = nil
	return []byte(digest("themis.postgres.commit-receipt.v1", r))
}
func payload(id int) string { return digest("themis.postgres.synthetic-payload.v1", id) }
func verifyReceipts(rs []Receipt, p Plan, expected int) error {
	if len(rs) != expected {
		return errors.New("independent receipt coverage incomplete")
	}
	prev := ""
	var ns int64
	for n, r := range rs {
		if r.Version != Version || r.Plan != p.Digest || r.ID != n+1 || r.Payload != payload(r.ID) || r.XID == "" || r.AckNS <= ns || r.Previous != prev ||
			!ed25519.Verify(p.Inventory.LedgerKey, receiptMessage(r), r.Signature) {
			return errors.New("receipt signature, order or identity invalid")
		}
		prev = digest("receipt", r)
		ns = r.AckNS
	}
	return nil
}

type Row struct {
	ID      int    `json:"id"`
	Payload string `json:"payload"`
}
type Measurements struct {
	BackupBytes          int64     `json:"backupBytes"`
	BackupSHA256         string    `json:"backupSha256"`
	BackupReadable       bool      `json:"backupReadable"`
	PgDumpVersion        string    `json:"pgDumpVersion"`
	PgRestoreVersion     string    `json:"pgRestoreVersion"`
	DumpExit             *int      `json:"dumpExit,omitempty"`
	RestoreExit          *int      `json:"restoreExit,omitempty"`
	RestoreMillis        int64     `json:"restoreMillis"`
	RestoreToReadinessNS int64     `json:"restoreToReadinessNs"`
	SourceStopped        bool      `json:"sourceStopped"`
	SchemaMatch          bool      `json:"schemaMatch"`
	SchemaObserved       bool      `json:"schemaObserved"`
	ReadWriteReady       bool      `json:"readWriteReady"`
	IntegrityObserved    bool      `json:"integrityObserved"`
	IntegrityOK          bool      `json:"integrityOk"`
	ExpectedCommits      int       `json:"expectedCommits"`
	Receipts             []Receipt `json:"receipts"`
	ReceiptCoverage      bool      `json:"receiptCoverage"`
	Rows                 []Row     `json:"restoredRows"`
	Missing              []int     `json:"missingAcknowledgedIds"`
	Unexpected           []int     `json:"unexpectedIds"`
	Duplicates           []int     `json:"duplicateIds"`
	Corrupt              []int     `json:"corruptIds"`
	RecoveryPoint        int       `json:"contiguousAcknowledgedRecoveryPoint"`
	DataLossExact        bool      `json:"dataLossExact"`
	DataLossGapNS        int64     `json:"acknowledgedDataLossGapNs"`
	Uncertain            []int     `json:"uncertainIds"`
}
type Report struct {
	Version      string                   `json:"version"`
	Run          string                   `json:"run"`
	Plan         string                   `json:"plan"`
	Verdict      result.Verdict           `json:"verdict"`
	Execution    result.ExecutionStatus   `json:"execution"`
	Live         bool                     `json:"liveTrustedExecution"`
	Provenance   string                   `json:"provenance"`
	At           time.Time                `json:"at"`
	Measurements Measurements             `json:"measurements"`
	Assertions   []result.AssertionResult `json:"assertions"`
	Cleanup      CleanupReceipt           `json:"cleanup"`
	Problem      string                   `json:"problem,omitempty"`
}

var required = []string{"authorization", "backup", "restore", "readiness", "schema", "integrity", "receipts", "data-loss", "restore-time", "cleanup", "unambiguous"}

func assess(p Plan, m Measurements, clean CleanupReceipt, problem string) []result.AssertionResult {
	var out []result.AssertionResult
	add := func(id string, observed, ok bool) {
		v := result.Inconclusive
		coverage := result.Missing
		if observed {
			coverage = result.Sufficient
			v = result.Pass
			if !ok {
				v = result.Fail
			}
		}
		out = append(out, result.AssertionResult{ID: id, Verdict: v, Evidence: coverage})
	}
	add("authorization", true, true)
	add("backup", m.DumpExit != nil && *m.DumpExit == 0 && m.BackupReadable, true)
	add("restore", m.RestoreExit != nil && *m.RestoreExit == 0, true)
	add("readiness", m.ReadWriteReady, true)
	add("schema", m.SchemaObserved, m.SchemaMatch)
	add("integrity", m.IntegrityObserved, m.IntegrityOK)
	add("receipts", m.ReceiptCoverage, true)
	add("data-loss", m.DataLossExact || len(m.Missing) > p.Contract.MaxLostCommits, len(m.Missing) <= p.Contract.MaxLostCommits)
	add("restore-time", m.ReadWriteReady && m.SourceStopped && m.RestoreToReadinessNS > 0, m.RestoreToReadinessNS <= p.Contract.MaxRestoreMillis*int64(time.Millisecond))
	add("cleanup", clean.Complete, true)
	add("unambiguous", problem == "", true)
	return out
}
func ExitCode(r Report) int {
	if r.Execution == result.CleanupPending {
		return 7
	}
	switch r.Verdict {
	case result.Pass:
		return 0
	case result.Fail:
		return 3
	default:
		return 4
	}
}

// Replay validates structure and receipt signatures, but an embedded public key
// cannot authenticate a whole execution. A historical candidate PASS stays INC.
func Replay(dir string) (Report, error) {
	read := func(name string, v any) error {
		b, e := readBounded(filepath.Join(dir, name))
		if e != nil {
			return e
		}
		return localstate.Unmarshal(b, v)
	}
	var r Report
	var p Plan
	if e := read("report.json", &r); e != nil {
		return r, e
	}
	if e := read("plan.json", &p); e != nil {
		return r, e
	}
	if e := p.Validate(); e != nil {
		return r, e
	}
	if r.Plan != p.Digest || r.Run != p.Inventory.Run || r.Version != Version {
		return r, errors.New("report identity mismatch")
	}
	b, e := readBounded(filepath.Join(dir, "journal.jsonl"))
	if e != nil {
		return r, e
	}
	if e = VerifyJournal(b, p.Digest); e != nil {
		return r, e
	}
	r.Live = false
	r.Provenance = "unsigned historical candidate; individual embedded-key receipts do not authenticate whole execution"
	expected := BaselineCommits
	if p.Contract.Scenario == "ack-loss" {
		expected += 3
	}
	r.Measurements.ReceiptCoverage = verifyReceipts(r.Measurements.Receipts, p, expected) == nil
	r.Measurements.DataLossExact = false
	for n := range r.Assertions {
		r.Assertions[n].Verdict = result.Inconclusive
		r.Assertions[n].Evidence = result.Insufficient
		r.Assertions[n].Reason = "unsigned historical assertion; execution not authenticated"
	}
	r.Verdict = result.Inconclusive
	return r, nil
}

func readBounded(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if len(b) > 1<<20 {
		return nil, errors.New("evidence exceeds 1MiB")
	}
	return b, e
}
