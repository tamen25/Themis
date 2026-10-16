package postgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

const seedSQL = `CREATE SCHEMA themis_app;
CREATE TABLE themis_app.transactions(id integer PRIMARY KEY CHECK(id BETWEEN 1 AND 64),payload text NOT NULL CHECK(payload ~ '^[a-f0-9]{64}$'));
CREATE TABLE themis_app.accounts(id integer PRIMARY KEY CHECK(id IN (1,2)),balance bigint NOT NULL CHECK(balance>=0));
INSERT INTO themis_app.accounts VALUES(1,10000),(2,10000);
CREATE TABLE themis_app.health(singleton integer PRIMARY KEY CHECK(singleton=1),counter integer NOT NULL CHECK(counter>=0));
INSERT INTO themis_app.health VALUES(1,0);`

const schemaSQL = `SELECT json_build_object('columns',(SELECT json_agg(x ORDER BY table_name,ordinal_position) FROM (SELECT table_name,ordinal_position,column_name,data_type,is_nullable FROM information_schema.columns WHERE table_schema='themis_app') x),'constraints',(SELECT json_agg(x ORDER BY name,definition) FROM (SELECT cl.relname AS name,pg_get_constraintdef(co.oid) AS definition FROM pg_constraint co JOIN pg_class cl ON cl.oid=co.conrelid JOIN pg_namespace n ON n.oid=cl.relnamespace WHERE n.nspname='themis_app') x));`
const emptySQL = `SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%' AND c.relkind IN ('r','p','v','m','f','S');`

type backupInfo struct {
	Plan, Run, Source, Restore, SHA256 string
	Bytes                              int64
	Signature                          []byte
}

func backupMessage(b backupInfo) []byte {
	b.Signature = nil
	return []byte(digest("themis.postgres.backup.v1", b))
}

func backupFile(dir string, p Plan) (*os.File, backupInfo, error) {
	var info backupInfo
	if e := localstate.Read(filepath.Join(dir, "backup-info.json"), &info); e != nil {
		return nil, info, e
	}
	if info.Plan != p.Digest || info.Run != p.Inventory.Run || info.Source != p.Inventory.Source.ID || info.Restore != p.Inventory.Restore.ID ||
		info.Bytes < 6 || info.Bytes > BackupBytes || !ed25519.Verify(p.Inventory.LedgerKey, backupMessage(info), info.Signature) {
		return nil, info, errors.New("backup attestation mismatch")
	}
	path := filepath.Join(dir, "backup.dump")
	if e := localstate.Check(path); e != nil {
		return nil, info, e
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, info, e
	}
	fail := func() (*os.File, backupInfo, error) {
		f.Close()
		return nil, info, errors.New("backup size, header or digest mismatch")
	}
	st, e := f.Stat()
	if e != nil || st.Size() != info.Bytes {
		return fail()
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, BackupBytes+1))
	if e != nil || n != info.Bytes || hex.EncodeToString(h.Sum(nil)) != info.SHA256 {
		return fail()
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return fail()
	}
	var magic [5]byte
	if _, e = io.ReadFull(f, magic[:]); e != nil || string(magic[:]) != "PGDMP" {
		return fail()
	}
	_, e = f.Seek(0, io.SeekStart)
	if e != nil {
		return fail()
	}
	return f, info, nil
}

// runOptions is test-only instrumentation around real operations, not a public
// SQL or process hook. Production Run always uses its zero value.
type runOptions struct {
	after           func(string, Plan) error
	backupOutput    func(io.Writer) io.Writer
	restoreInput    func(io.Reader) io.Reader
	acknowledgement func(int, string, error) (string, error)
}

func Run(ctx context.Context, dir string) (Report, error) { return run(ctx, dir, runOptions{}) }

func run(ctx context.Context, dir string, opts runOptions) (report Report, err error) {
	i, e := loadInventory(dir)
	if e != nil {
		return report, e
	}
	l, e := acquire(i.Directory)
	if e != nil {
		return report, e
	}
	defer l.Close()
	var p Plan
	if e = localstate.Read(filepath.Join(i.Directory, "plan.json"), &p); e != nil {
		return report, e
	}
	if e = p.Validate(); e != nil {
		return report, e
	}
	if digest("inventory", i) != digest("inventory", p.Inventory) {
		return report, errors.New("plan inventory mismatch")
	}
	var g Grant
	if e = localstate.Read(filepath.Join(i.Directory, "authorization.json"), &g); e != nil {
		return report, e
	}
	if e = validateGrant(p, g, time.Now(), true); e != nil {
		return report, e
	}
	var k keys
	if e = localstate.Read(filepath.Join(i.Directory, "keys.json"), &k); e != nil {
		return report, e
	}
	if len(k.Ledger) != 64 || !bytes.Equal(ed25519.PrivateKey(k.Ledger).Public().(ed25519.PublicKey), i.LedgerKey) {
		return report, errors.New("ledger signer mismatch")
	}
	if e = localstate.WriteNew(filepath.Join(i.Directory, "invocation.json"), map[string]string{"plan": p.Digest, "run": i.Run}); e != nil {
		return report, errors.New("invocation consumed or cannot be durably claimed; no retry")
	}
	jf, e := localstate.OpenNew(filepath.Join(i.Directory, "journal.jsonl"))
	if e != nil {
		return report, e
	}
	defer jf.Close()
	if e = localstate.SyncDirectory(i.Directory); e != nil {
		return report, e
	}
	started := time.Now()
	j := journal{w: jf, start: started, plan: p.Digest}
	report = Report{Version: Version, Run: i.Run, Plan: p.Digest, Live: true, Provenance: "live local trusted adapter; individually signed host COMMIT receipts; unsigned whole report", At: time.Now().UTC()}
	deadline := started.Add(time.Duration(p.Contract.MaxRuntimeSeconds) * time.Second)
	if g.ExecuteBefore.Before(deadline) {
		deadline = g.ExecuteBefore
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	d := Docker{i.Endpoint, i.Engine}
	var problem error
	defer func() {
		if problem != nil {
			report.Problem = problem.Error()
		}
		// Cleanup authority is independent of the experiment deadline and journal.
		report.Cleanup = cleanup(context.Background(), i, p.Contract.Scenario == "cleanup-denied")
		if e := localstate.WriteNew(filepath.Join(i.Directory, "cleanup-initial.json"), report.Cleanup); e != nil {
			report.Cleanup.Complete = false
			report.Problem = "cleanup receipt publication failed"
		}
		if e := j.append("CLEANUP_OBSERVED", report.Cleanup); e != nil {
			report.Problem = "journal failed; evidence incomplete"
		}
		report.Assertions = assess(p, report.Measurements, report.Cleanup, report.Problem)
		report.Verdict = result.Aggregate(required, report.Assertions, result.RunEvidence{PreconditionsMet: true})
		report.Execution = result.Succeeded
		if report.Verdict == result.Fail {
			report.Execution = result.Failed
		}
		if report.Problem != "" {
			report.Execution = result.Error
			if errors.Is(ctx.Err(), context.Canceled) {
				report.Execution = result.Cancelled
			}
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				report.Execution = result.TimedOut
			}
		}
		if !report.Cleanup.Complete {
			report.Execution = result.CleanupPending
		}
		if e := j.append("REPORT", struct {
			Verdict   result.Verdict
			Execution result.ExecutionStatus
		}{report.Verdict, report.Execution}); e != nil {
			report.Problem = "journal failed; evidence incomplete"
			if report.Verdict == result.Pass {
				report.Verdict = result.Inconclusive
			}
			if report.Cleanup.Complete {
				report.Execution = result.Error
			}
		}
		if e := localstate.WriteNew(filepath.Join(i.Directory, "report.json"), report); e != nil {
			err = e
		}
	}()
	step := func(kind string, r Resource) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if e := validateGrant(p, g, time.Now(), false); e != nil {
			return e
		}
		if e := d.target(ctx, i, r); e != nil {
			return e
		}
		return j.append(kind, map[string]string{"container": r.ID})
	}
	hook := func(stage string) error {
		if opts.after != nil {
			return opts.after(stage, p)
		}
		return nil
	}
	work := func() error {
		if e := step("SEED_INTENT", i.Source); e != nil {
			return e
		}
		for _, r := range []Resource{i.Source, i.Restore} {
			v, e := d.sql(ctx, r.ID, emptySQL)
			if e != nil || v != "0" {
				return errors.New("source or restore destination is not empty")
			}
		}
		if _, e := d.sql(ctx, i.Source.ID, seedSQL); e != nil {
			return e
		}
		schema, e := d.sql(ctx, i.Source.ID, schemaSQL)
		if e != nil {
			return e
		}
		if e = j.append("SCHEMA_BASELINE", map[string]string{"sha256": digest("schema", schema)}); e != nil {
			return e
		}
		m := &report.Measurements
		m.ExpectedCommits = BaselineCommits
		if p.Contract.Scenario == "ack-loss" {
			m.ExpectedCommits += 3
		}
		previous := ""
		commit := func(id int) error {
			if e := step("COMMIT_INTENT", i.Source); e != nil {
				return e
			}
			sql := fmt.Sprintf("BEGIN; INSERT INTO themis_app.transactions VALUES(%d,'%s'); UPDATE themis_app.accounts SET balance=balance-1 WHERE id=1; UPDATE themis_app.accounts SET balance=balance+1 WHERE id=2; SELECT json_build_object('id',%d,'payload','%s','xid',pg_current_xact_id()::text); COMMIT;", id, payload(id), id, payload(id))
			v, e := d.sql(ctx, i.Source.ID, sql)
			if opts.acknowledgement != nil {
				v, e = opts.acknowledgement(id, v, e)
			}
			if e != nil {
				m.Uncertain = append(m.Uncertain, id)
				return errors.New("commit acknowledgement ambiguous; no receipt published")
			}
			lines := strings.Split(v, "\n")
			if len(lines) != 6 || lines[0] != "BEGIN" || lines[1] != "INSERT 0 1" || lines[2] != "UPDATE 1" || lines[3] != "UPDATE 1" || lines[5] != "COMMIT" {
				m.Uncertain = append(m.Uncertain, id)
				return errors.New("commit acknowledgement incomplete; no receipt published")
			}
			var ack struct {
				ID           int
				Payload, XID string
			}
			if json.Unmarshal([]byte(lines[4]), &ack) != nil || ack.ID != id || ack.Payload != payload(id) || ack.XID == "" {
				m.Uncertain = append(m.Uncertain, id)
				return errors.New("commit identity ambiguous")
			}
			r := Receipt{Version: Version, Plan: p.Digest, ID: id, Payload: ack.Payload, XID: ack.XID, AckNS: time.Since(started).Nanoseconds(), Previous: previous}
			r.Signature = ed25519.Sign(k.Ledger, receiptMessage(r))
			previous = digest("receipt", r)
			// C deliberately withholds a real acknowledged receipt, not a DB write.
			if !(p.Contract.Scenario == "missing-receipt" && id == 8) {
				if e = localstate.WriteNew(filepath.Join(i.Directory, fmt.Sprintf("receipt-%02d.json", id)), r); e != nil {
					m.Uncertain = append(m.Uncertain, id)
					return e
				}
				m.Receipts = append(m.Receipts, r)
			}
			return j.append("COMMIT_ACKNOWLEDGED", map[string]any{"id": id, "receiptRetained": !(p.Contract.Scenario == "missing-receipt" && id == 8)})
		}
		for id := 1; id <= BaselineCommits; id++ {
			if e = commit(id); e != nil {
				return e
			}
		}
		if e = step("BACKUP_INTENT", i.Source); e != nil {
			return e
		}
		if e = hook("before-backup"); e != nil {
			return e
		}
		b, e := d.output(ctx, nil, "exec", "--user", "999:999", i.Source.ID, "pg_dump", "--version")
		if e != nil {
			return e
		}
		m.PgDumpVersion = strings.TrimSpace(string(b))
		b, e = d.output(ctx, nil, "exec", "--user", "999:999", i.Restore.ID, "pg_restore", "--version")
		if e != nil {
			return e
		}
		m.PgRestoreVersion = strings.TrimSpace(string(b))
		if !strings.Contains(m.PgDumpVersion, "18.6") || !strings.Contains(m.PgRestoreVersion, "18.6") {
			return errors.New("backup tool version mismatch")
		}
		pending := filepath.Join(i.Directory, "backup.pending")
		f, e := localstate.OpenNew(pending)
		if e != nil {
			return e
		}
		var writer io.Writer = f
		if opts.backupOutput != nil {
			writer = opts.backupOutput(f)
		}
		e = d.command(ctx, nil, writer, BackupBytes, "exec", "--user", "999:999", i.Source.ID, "pg_dump", "-w", "-Fc", "-Z0", "--lock-wait-timeout=2s", "--no-owner", "--no-acl", "-h", "127.0.0.1", "-p", "5432", "-U", "themis", "-d", Database)
		m.DumpExit = toolExit(e)
		if je := j.append("BACKUP_TOOL_EXIT", map[string]any{"exitCode": m.DumpExit}); je != nil {
			f.Close()
			return je
		}
		if e != nil {
			f.Close()
			return e
		}
		zero := 0
		m.DumpExit = &zero
		if e = f.Sync(); e != nil {
			f.Close()
			return e
		}
		if e = f.Close(); e != nil {
			return e
		}
		data, e := os.ReadFile(pending)
		if e != nil {
			return e
		}
		sum := sha256.Sum256(data)
		m.BackupBytes = int64(len(data))
		m.BackupSHA256 = hex.EncodeToString(sum[:])
		if len(data) < 6 || string(data[:5]) != "PGDMP" {
			return errors.New("invalid custom backup")
		}
		if e = os.Link(pending, filepath.Join(i.Directory, "backup.dump")); e != nil {
			return e
		}
		if e = localstate.SyncDirectory(i.Directory); e != nil {
			return e
		}
		bi := backupInfo{Plan: p.Digest, Run: i.Run, Source: i.Source.ID, Restore: i.Restore.ID, SHA256: m.BackupSHA256, Bytes: m.BackupBytes}
		bi.Signature = ed25519.Sign(k.Ledger, backupMessage(bi))
		if e = localstate.WriteNew(filepath.Join(i.Directory, "backup-info.json"), bi); e != nil {
			return e
		}
		if e = hook("backup-published"); e != nil {
			return e
		}
		archive, _, e := backupFile(i.Directory, p)
		if e != nil {
			return e
		}
		b, e = d.output(ctx, archive, "exec", "--user", "999:999", "-i", i.Restore.ID, "pg_restore", "--list")
		archive.Close()
		if e != nil {
			return e
		}
		for _, table := range p.Contract.RequiredTables {
			if !strings.Contains(string(b), "TABLE themis_app "+table+" ") {
				return errors.New("backup table inventory incomplete")
			}
		}
		m.BackupReadable = true
		if e = j.append("BACKUP_VERIFIED", bi); e != nil {
			return e
		}
		for id := BaselineCommits + 1; id <= m.ExpectedCommits; id++ {
			if e = commit(id); e != nil {
				return e
			}
		}
		if e = d.target(ctx, i, i.Restore); e != nil {
			return e
		}
		fresh, e := d.sql(ctx, i.Restore.ID, emptySQL)
		if e != nil || fresh != "0" {
			return errors.New("restore destination is not fresh and empty; source shutdown denied")
		}
		if e = step("SOURCE_STOP_INTENT", i.Source); e != nil {
			return e
		}
		if _, e = d.output(ctx, nil, "stop", "--time", "1", i.Source.ID); e != nil {
			return e
		}
		var stopped Container
		if e = d.inspect(ctx, "container", i.Source.ID, &stopped); e != nil {
			return e
		}
		if stopped.ID != i.Source.ID || stopped.State.Running {
			return errors.New("source shutdown not observed")
		}
		outage := time.Now()
		m.SourceStopped = true
		if e = j.append("SOURCE_STOPPED", map[string]string{"id": i.Source.ID, "anchor": "observed process stopped; provisioning and backup excluded"}); e != nil {
			return e
		}
		if e = step("RESTORE_INTENT", i.Restore); e != nil {
			return e
		}
		v, e := d.sql(ctx, i.Restore.ID, emptySQL)
		if e != nil || v != "0" {
			return errors.New("restore destination is not fresh and empty")
		}
		if e = hook("before-restore"); e != nil {
			return e
		}
		archive, _, e = backupFile(i.Directory, p)
		if e != nil {
			return e
		}
		defer archive.Close()
		var reader io.Reader = archive
		if opts.restoreInput != nil {
			reader = opts.restoreInput(archive)
		}
		restoreStart := time.Now()
		e = d.command(ctx, reader, io.Discard, 65536, "exec", "--user", "999:999", "-i", i.Restore.ID, "pg_restore", "-w", "--single-transaction", "--exit-on-error", "--no-owner", "--no-privileges", "-h", "127.0.0.1", "-p", "5432", "-U", "themis", "-d", Database)
		m.RestoreMillis = time.Since(restoreStart).Milliseconds()
		m.RestoreExit = toolExit(e)
		if je := j.append("RESTORE_TOOL_EXIT", map[string]any{"exitCode": m.RestoreExit}); je != nil {
			return je
		}
		if e != nil {
			return e
		}
		m.RestoreExit = &zero
		if e = j.append("RESTORE_COMPLETED", map[string]int64{"millis": m.RestoreMillis}); e != nil {
			return e
		}
		if e = hook("restored"); e != nil {
			return e
		}
		if e = step("VERIFY_INTENT", i.Restore); e != nil {
			return e
		}
		actualSchema, e := d.sql(ctx, i.Restore.ID, schemaSQL)
		if e != nil {
			return e
		}
		m.SchemaMatch = actualSchema == schema
		m.SchemaObserved = true
		if e = observe(ctx, d, i.Restore, m, p); e != nil {
			return e
		}
		v, e = d.sql(ctx, i.Restore.ID, "BEGIN; UPDATE themis_app.health SET counter=counter+1 WHERE singleton=1; COMMIT; SELECT counter FROM themis_app.health WHERE singleton=1;")
		if e != nil || v != "BEGIN\nUPDATE 1\nCOMMIT\n1" {
			return errors.New("restored application read/write health not verified")
		}
		m.ReadWriteReady = true
		m.RestoreToReadinessNS = time.Since(outage).Nanoseconds()
		if e = j.append("RECOVERY_MEASURED", m); e != nil {
			return e
		}
		return nil
	}
	problem = work()
	return report, nil
}

func observe(ctx context.Context, d Docker, r Resource, m *Measurements, p Plan) error {
	v, e := d.sql(ctx, r.ID, `SELECT coalesce(json_agg(x ORDER BY id),'[]'::json) FROM (SELECT id,payload FROM themis_app.transactions) x;`)
	if e != nil {
		return e
	}
	if e = json.Unmarshal([]byte(v), &m.Rows); e != nil {
		return errors.New("invalid restored row observation")
	}
	v, e = d.sql(ctx, r.ID, "SELECT id||':'||balance FROM themis_app.accounts ORDER BY id;")
	if e != nil {
		return e
	}
	m.IntegrityObserved = true
	m.IntegrityOK = v == fmt.Sprintf("1:%d\n2:%d", 10000-len(m.Rows), 10000+len(m.Rows)) && len(m.Rows) >= BaselineCommits && len(m.Rows) <= m.ExpectedCommits
	seen := map[int]string{}
	for _, row := range m.Rows {
		if _, ok := seen[row.ID]; ok {
			m.Duplicates = append(m.Duplicates, row.ID)
			m.IntegrityOK = false
		}
		seen[row.ID] = row.Payload
		if row.ID < 1 || row.ID > m.ExpectedCommits {
			m.Unexpected = append(m.Unexpected, row.ID)
			m.IntegrityOK = false
		}
		if row.Payload != payload(row.ID) {
			m.Corrupt = append(m.Corrupt, row.ID)
			m.IntegrityOK = false
		}
	}
	for id := 1; id <= BaselineCommits; id++ {
		if seen[id] != payload(id) {
			m.IntegrityOK = false
		}
	}
	// Reload the independently published host ledger; in-memory acknowledgements
	// are not substituted for durable missing or damaged receipts.
	m.Receipts = nil
	for id := 1; id <= m.ExpectedCommits; id++ {
		var receipt Receipt
		if e := localstate.Read(filepath.Join(p.Inventory.Directory, fmt.Sprintf("receipt-%02d.json", id)), &receipt); e != nil {
			m.Uncertain = append(m.Uncertain, id)
			continue
		}
		if receipt.ID != id || receipt.Version != Version || receipt.Plan != p.Digest || receipt.Payload != payload(id) || receipt.XID == "" || receipt.AckNS <= 0 || !ed25519.Verify(p.Inventory.LedgerKey, receiptMessage(receipt), receipt.Signature) {
			m.Uncertain = append(m.Uncertain, id)
			continue
		}
		m.Receipts = append(m.Receipts, receipt)
		if _, ok := seen[id]; !ok {
			m.Missing = append(m.Missing, id)
		}
	}
	m.ReceiptCoverage = verifyReceipts(m.Receipts, p, m.ExpectedCommits) == nil
	m.DataLossExact = m.ReceiptCoverage
	for _, receipt := range m.Receipts {
		if receipt.ID == m.RecoveryPoint+1 && seen[receipt.ID] == receipt.Payload {
			m.RecoveryPoint = receipt.ID
		} else {
			break
		}
	}
	if m.DataLossExact && len(m.Missing) > 0 && m.RecoveryPoint > 0 {
		m.DataLossGapNS = m.Receipts[len(m.Receipts)-1].AckNS - m.Receipts[m.RecoveryPoint-1].AckNS
	}
	return nil
}
