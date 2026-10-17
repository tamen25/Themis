package postgres

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/tamen25/themis/internal/localstate"
)

// Hooks alter outcomes or pause after actual operations in opt-in tests. Public
// contracts cannot select a command, SQL statement, hook or process pause.
type replicationOptions struct {
	after           func(string, ReplicationPlan) error
	acknowledgement func(int, string, error) (string, error)
	termination     func(context.Context, Docker, string) ([]byte, error)
	promotion       func(context.Context, Docker, string) (string, error)
}

func replicationAfter(o replicationOptions, stage string, p ReplicationPlan) error {
	if o.after != nil {
		return o.after(stage, p)
	}
	return nil
}

type ReplicationReceipt struct {
	Version, Plan, Session       string
	ID                           int
	Payload, XID, Mode, FlushLSN string
	AckOffsetNS                  int64
	AckAtUTC                     time.Time
	Previous                     string
	Signature                    []byte
}

func replicationReceiptMessage(r ReplicationReceipt) []byte {
	r.Signature = nil
	return []byte(digest("themis.postgres.replication.commit.v1", r))
}
func verifyReplicationReceipts(rs []ReplicationReceipt, p ReplicationPlan) error {
	if len(rs) != replicationCommits {
		return errors.New("independent replication acknowledgement coverage incomplete")
	}
	previous, session := "", ""
	var offset int64
	seen := map[string]bool{}
	var lastLSN uint64
	for n, r := range rs {
		lsn, e := pitrLSN(r.FlushLSN)
		if r.Version != ReplicationVersion || r.Plan != p.Digest || !hexID.MatchString(r.Session) || r.ID != n+1 || r.Payload != payload(r.ID) || !validPITRXID(r.XID) || seen[r.XID] || r.Mode != "remote_apply" || r.Previous != previous || r.AckOffsetNS <= offset || r.AckAtUTC.IsZero() || e != nil || lsn == 0 || lsn < lastLSN || !ed25519.Verify(p.Inventory.LedgerKey, replicationReceiptMessage(r), r.Signature) {
			return errors.New("replication COMMIT signature, mode, order or identity invalid")
		}
		if session != "" && session != r.Session {
			return errors.New("unexpected receipt process clock session")
		}
		session = r.Session
		seen[r.XID] = true
		offset = r.AckOffsetNS
		lastLSN = lsn
		previous = digest("replication-receipt", r)
	}
	return nil
}
func loadReplicationReceipts(p ReplicationPlan) (rs []ReplicationReceipt, err error) {
	for n := 1; n <= replicationCommits; n++ {
		var r ReplicationReceipt
		if err = localstate.Read(filepath.Join(p.Inventory.Directory, fmt.Sprintf("replication-receipt-%02d.json", n)), &r); err != nil {
			return rs, err
		}
		rs = append(rs, r)
	}
	return rs, verifyReplicationReceipts(rs, p)
}
func replicationCommit(ctx context.Context, d Docker, p ReplicationPlan, key []byte, j *journal, session, previous string, id int, o replicationOptions) (r ReplicationReceipt, err error) {
	if err = j.append("COMMIT_INTENT", map[string]int{"id": id}); err != nil {
		return r, err
	}
	sql := fmt.Sprintf("BEGIN; SET LOCAL synchronous_commit='remote_apply'; INSERT INTO themis_app.transactions VALUES(%d,'%s'); UPDATE themis_app.accounts SET balance=balance-1 WHERE id=1; UPDATE themis_app.accounts SET balance=balance+1 WHERE id=2; SELECT json_build_object('ID',%d,'Payload','%s','XID',pg_current_xact_id()::text,'Mode',current_setting('synchronous_commit')); COMMIT; SELECT pg_current_wal_flush_lsn()::text;", id, payload(id), id, payload(id))
	v, e := d.replicationSQL(ctx, p.Inventory.Primary.ID, sql)
	if o.acknowledgement != nil {
		v, e = o.acknowledgement(id, v, e)
	}
	lines := strings.Split(v, "\n")
	var ack struct {
		ID                 int
		Payload, XID, Mode string
	}
	if e != nil || len(lines) != 8 || lines[0] != "BEGIN" || lines[1] != "SET" || lines[2] != "INSERT 0 1" || lines[3] != "UPDATE 1" || lines[4] != "UPDATE 1" || lines[6] != "COMMIT" || json.Unmarshal([]byte(lines[5]), &ack) != nil || ack.ID != id || ack.Payload != payload(id) || !validPITRXID(ack.XID) || ack.Mode != "remote_apply" {
		_ = j.append("COMMIT_OUTCOME_UNCERTAIN", map[string]any{"id": id, "toolExit": toolExit(e), "cleanToolExit": e == nil})
		return r, errors.New("COMMIT acknowledgement ambiguous; no receipt published")
	}
	if n, e := pitrLSN(lines[7]); e != nil || n == 0 {
		return r, errors.New("acknowledgement WAL flush position missing")
	}
	r = ReplicationReceipt{Version: ReplicationVersion, Plan: p.Digest, Session: session, ID: id, Payload: ack.Payload, XID: ack.XID, Mode: ack.Mode, FlushLSN: lines[7], AckOffsetNS: time.Since(j.start).Nanoseconds(), AckAtUTC: time.Now().UTC(), Previous: previous}
	r.Signature = ed25519.Sign(key, replicationReceiptMessage(r))
	if err = localstate.WriteNew(filepath.Join(p.Inventory.Directory, fmt.Sprintf("replication-receipt-%02d.json", id)), r); err != nil {
		return r, errors.New("acknowledged COMMIT receipt publication failed; outcome uncertain")
	}
	return r, j.append("COMMIT_ACKNOWLEDGED", r)
}

type ReplicationPrepared struct {
	Storage                                                   map[string]ReplicationStorage
	Version, Plan, Inventory, Invocation, ReceiptHash, Schema string
	State                                                     ReplicationObservation
	LastAckLSN                                                string
	Receipts                                                  int
	Digest                                                    string
	Signature                                                 []byte
}

func replicationPreparedDigest(s ReplicationPrepared) string {
	s.Digest = ""
	s.Signature = nil
	return digest("themis.postgres.replication.prepared.v1", s)
}
func loadReplicationPrepared(p ReplicationPlan) (s ReplicationPrepared, err error) {
	if err = localstate.Read(filepath.Join(p.Inventory.Directory, "replication-prepared.json"), &s); err != nil {
		return s, err
	}
	if s.Version != ReplicationVersion || s.Plan != p.Digest || s.Inventory != replicationInventoryHash(p.Inventory) || !hexID.MatchString(s.Invocation) || s.Receipts != replicationCommits || s.Schema == "" || s.Digest != replicationPreparedDigest(s) || !ed25519.Verify(p.Inventory.LedgerKey, []byte(s.Digest), s.Signature) || !validReplicationState(p.Inventory, s.State, s.LastAckLSN) {
		return s, errors.New("replication preparation seal or synchronous state invalid")
	}
	rs, err := loadReplicationReceipts(p)
	if err != nil {
		return s, err
	}
	if digest("replication-ledger", rs) != s.ReceiptHash || rs[len(rs)-1].FlushLSN != s.LastAckLSN {
		return s, errors.New("prepared COMMIT evidence changed")
	}
	return s, nil
}
func validReplicationState(i ReplicationInventory, o ReplicationObservation, minimum string) bool {
	if o.Primary != i.Primary.DB || o.Standby != i.Standby.DB || o.SynchronousStandbyNames != replicationNames || o.SynchronousCommit != "remote_apply" || !o.PrimaryWritable || !o.Fsync || !o.FullPageWrites || o.Slots != 0 || o.SenderState != "streaming" || o.SyncState != "sync" || o.SenderUser != "themis_repl" || o.SenderApplication != "themis_standby" || o.SenderAddress != i.StandbyIP || o.ReceiverState != "streaming" || o.ReceiverHost != i.PrimaryIP || o.ReceiverPort != 5432 || !o.InRecovery || !o.ReadOnly || o.ReplayPaused || !o.AuthenticationVerified {
		return false
	}
	want, e := pitrLSN(minimum)
	if e != nil {
		return false
	}
	for _, s := range []string{o.CurrentLSN, o.SentLSN, o.WriteLSN, o.FlushLSN, o.ReplayLSN, o.ReceivedLSN, o.ReplayedLSN} {
		n, e := pitrLSN(s)
		if e != nil || n == 0 || n < want {
			return false
		}
	}
	return true
}
func waitReplication(ctx context.Context, d Docker, i ReplicationInventory, minimum string) (o ReplicationObservation, err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		o, err = observeReplication(ctx, d, i)
		if err == nil && validReplicationState(i, o, minimum) {
			return o, nil
		}
		if err = replicationWait(ctx); err != nil {
			return o, errors.New("independent synchronous sender/receiver/replay evidence insufficient")
		}
	}
}
func PrepareReplication(ctx context.Context, dir string) (ReplicationPrepared, error) {
	return prepareReplication(ctx, dir, replicationOptions{})
}
func prepareReplication(ctx context.Context, dir string, o replicationOptions) (s ReplicationPrepared, err error) {
	p, err := loadReplicationPlan(dir)
	if err != nil {
		return s, err
	}
	i := p.Inventory
	l, err := acquire(i.Directory)
	if err != nil {
		return s, err
	}
	defer l.Close()
	var g ReplicationGrant
	if err = localstate.Read(filepath.Join(i.Directory, "replication-prepare-authorization.json"), &g); err != nil {
		return s, err
	}
	if err = validateReplicationGrant(p, g, "prepare", "", "", time.Now(), true); err != nil {
		return s, err
	}
	if err = localstate.WriteNew(filepath.Join(i.Directory, "replication-preparation-claim.json"), map[string]string{"plan": p.Digest}); err != nil {
		return s, errors.New("preparation invocation already consumed")
	}
	f, err := localstate.OpenNew(filepath.Join(i.Directory, "replication-prepare.jsonl"))
	if err != nil {
		return s, err
	}
	defer f.Close()
	j := journal{w: f, start: time.Now(), plan: p.Digest, version: ReplicationVersion}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	d := Docker{i.Endpoint, i.Engine}
	k, err := loadReplicationKeys(i)
	if err != nil {
		return s, err
	}
	for _, r := range i.resources() {
		if err = d.replicationTarget(ctx, i, r); err != nil {
			return s, err
		}
	}
	if err = j.append("PREPARE_INTENT", map[string]any{"plan": p.Digest, "contract": p.Contract, "run": i.Run, "primary": i.Primary.ID, "standby": i.Standby.ID}); err != nil {
		return s, err
	}
	if _, err = d.replicationSQL(ctx, i.Primary.ID, "ALTER SYSTEM SET synchronous_standby_names='FIRST 1 (themis_standby)'; SELECT pg_reload_conf();"); err != nil {
		return s, err
	}
	if _, err = waitReplication(ctx, d, i, "0/0"); err != nil {
		return s, err
	}
	if _, err = d.replicationSQL(ctx, i.Primary.ID, seedSQL); err != nil {
		return s, errors.New("fixed replicated application setup failed")
	}
	session, previous := localstate.RandomID(), ""
	for id := 1; id <= replicationCommits; id++ {
		r, e := replicationCommit(ctx, d, p, k.Ledger, &j, session, previous, id, o)
		if e != nil {
			return s, e
		}
		previous = digest("replication-receipt", r)
	}
	rs, err := loadReplicationReceipts(p)
	if err != nil {
		return s, err
	}
	s = ReplicationPrepared{Version: ReplicationVersion, Plan: p.Digest, Inventory: replicationInventoryHash(i), Invocation: localstate.RandomID(), ReceiptHash: digest("replication-ledger", rs), Receipts: replicationCommits, LastAckLSN: rs[len(rs)-1].FlushLSN}
	s.State, err = waitReplication(ctx, d, i, s.LastAckLSN)
	if err != nil {
		return s, err
	}
	s.Schema, err = d.replicationSQL(ctx, i.Primary.ID, schemaSQL)
	if err != nil {
		return s, err
	}
	var m ReplicationMeasurements
	if err = replicationObserveData(ctx, d, p, s, &m); err != nil {
		return s, err
	}
	if !m.ReceiptCoverage || !m.SchemaMatch || !m.IntegrityOK || len(m.Missing)+len(m.Corrupt)+len(m.Unexpected)+len(m.Duplicates) != 0 {
		return s, errors.New("physical standby application fidelity not established")
	}
	s.Storage = map[string]ReplicationStorage{}
	for _, r := range i.resources() {
		s.Storage[r.Role], err = d.replicationBudget(ctx, r)
		if err != nil {
			return s, err
		}
	}
	if err = validateReplicationGrant(p, g, "prepare", "", "", time.Now(), false); err != nil {
		return s, err
	}
	s.Digest = replicationPreparedDigest(s)
	s.Signature = ed25519.Sign(k.Ledger, []byte(s.Digest))
	if err = j.append("PREPARED", s); err != nil {
		return s, err
	}
	data, err := readBounded(filepath.Join(i.Directory, "replication-prepare.jsonl"))
	if err != nil || verifyJournal(data, p.Digest, ReplicationVersion) != nil {
		return s, errors.New("preparation journal incomplete")
	}
	err = localstate.WriteNew(filepath.Join(i.Directory, "replication-prepared.json"), s)
	return s, err
}
