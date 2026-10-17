package postgres

import (
	"archive/tar"
	"bytes"
	"context"
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

func RunDurable(ctx context.Context, dir string) (DurableReport, error) {
	return runDurable(ctx, dir, durableOptions{})
}
func runDurable(ctx context.Context, dir string, opts durableOptions) (report DurableReport, err error) {
	p, e := loadDurablePlan(dir)
	if e != nil {
		return report, e
	}
	i := p.Inventory
	l, e := acquire(i.Directory)
	if e != nil {
		return report, e
	}
	defer l.Close()
	archive, backup, e := openDurableBackup(p)
	if e != nil {
		return report, e
	}
	defer archive.Close()
	prepared, e := loadPrepared(p)
	if e != nil {
		return report, e
	}
	var g DurableGrant
	if e = localstate.Read(filepath.Join(i.Directory, "durable-failure-authorization.json"), &g); e != nil {
		return report, e
	}
	if e = validateDurableGrant(p, g, "sigkill-source-once", &backup, time.Now(), true); e != nil {
		return report, e
	}
	k, e := durableSigner(p)
	if e != nil {
		return report, e
	}
	if e = localstate.WriteNew(filepath.Join(i.Directory, "durable-invocation.json"), map[string]string{"plan": p.Digest, "backup": backup.SHA256}); e != nil {
		return report, errors.New("failure invocation consumed; ambiguous effects must not be retried")
	}
	f, e := localstate.OpenNew(filepath.Join(i.Directory, "durable-journal.jsonl"))
	if e != nil {
		return report, e
	}
	defer f.Close()
	if e = localstate.SyncDirectory(i.Directory); e != nil {
		return report, e
	}
	j := journal{w: f, start: time.Now(), plan: p.Digest, version: DurableVersion}
	deadline := j.start.Add(120 * time.Second)
	if g.ExecuteBefore.Before(deadline) {
		deadline = g.ExecuteBefore
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	report = DurableReport{Version: DurableVersion, Run: i.Run, Plan: p.Digest, Live: true, Provenance: "live owned local durable logical recovery; separately signed COMMIT and backup receipts; whole report unsigned", At: time.Now().UTC()}
	m := &report.Measurements
	m.Backup = backup
	m.ExpectedCommits = BaselineCommits
	if p.Contract.Scenario == "ack-loss" {
		m.ExpectedCommits += 3
	}
	m.Timeline.Anchor = DurableAnchor
	m.Timeline.Clock = "one runner monotonic clock; UTC metadata only; failure bounded by availability query start and stopped observation end"
	d := Docker{i.Endpoint, i.Engine}
	var problem error
	defer func() {
		if problem != nil {
			report.Problem = problem.Error()
		}
		report.Cleanup = durableCleanup(context.Background(), i, p.Contract.Scenario == "cleanup-denied")
		if e := localstate.WriteNew(filepath.Join(i.Directory, "durable-cleanup-initial.json"), report.Cleanup); e != nil {
			report.Cleanup.Complete = false
			report.Problem = "cleanup receipt publication failed"
		}
		if e := j.append("CLEANUP_OBSERVED", report.Cleanup); e != nil {
			report.Problem = "journal incomplete; execution cannot establish PASS"
		}
		if data, e := readBounded(filepath.Join(i.Directory, "durable-journal.jsonl")); e != nil || VerifyDurableJournal(data, p.Digest) != nil {
			report.Problem = "execution journal corruption; cleanup uses independent authority"
		}
		report.Assertions = assessDurable(p, *m, report.Cleanup, report.Problem)
		report.Verdict = result.Aggregate(durableRequired, report.Assertions, result.RunEvidence{PreconditionsMet: true})
		report.Execution = result.Succeeded
		if report.Verdict == result.Fail {
			report.Execution = result.Failed
		}
		if report.Problem != "" {
			report.Execution = result.Error
			if ctx.Err() == context.Canceled {
				report.Execution = result.Cancelled
			}
			if ctx.Err() == context.DeadlineExceeded {
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
			report.Problem = "journal incomplete; execution cannot establish PASS"
			if report.Verdict == result.Pass {
				report.Verdict = result.Inconclusive
			}
			if report.Cleanup.Complete {
				report.Execution = result.Error
			}
		}
		if e := localstate.WriteNew(filepath.Join(i.Directory, "durable-report.json"), report); e != nil {
			err = e
		}
	}()
	hook := func(stage string) error {
		if opts.after != nil {
			return opts.after(stage, p)
		}
		return nil
	}
	check := func(r Resource) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if e := validateDurableGrant(p, g, "sigkill-source-once", &backup, time.Now(), false); e != nil {
			return e
		}
		return d.durableTarget(ctx, i, r)
	}
	work := func() error {
		b, e := readBounded(filepath.Join(i.Directory, "durable-prepare.jsonl"))
		if e != nil {
			return e
		}
		if e = VerifyDurableJournal(b, p.Digest); e != nil {
			return e
		}
		lines := bytes.Split(bytes.TrimSpace(b), []byte{'\n'})
		var last Event
		if e = localstate.Unmarshal(lines[len(lines)-1], &last); e != nil || last.Hash != prepared.JournalHead {
			return errors.New("preparation journal differs from sealed publication")
		}
		for _, r := range []Resource{i.Source, i.Restore} {
			if e = check(r); e != nil {
				return e
			}
			if _, e = d.durableBudget(ctx, r); e != nil {
				return e
			}
		}
		v, e := d.sql(ctx, i.Restore.ID, emptySQL)
		if e != nil || v != "0" {
			return errors.New("fresh restore destination required before failure")
		}
		// Revalidate the independent publication before any failure effect. A
		// missing receipt is allowed to yield an observed but inconclusive run.
		if e = validateDurableFile(archive, backup); e != nil {
			return e
		}
		m.BackupVerified = true
		if e = j.append("BACKUP_REVALIDATED", backup); e != nil {
			return e
		}
		session, previous := localstate.RandomID(), prepared.ReceiptHead
		for id := BaselineCommits + 1; id <= m.ExpectedCommits; id++ {
			if e = check(i.Source); e != nil {
				return e
			}
			r, e := durableCommit(ctx, d, p, k, &j, session, previous, id, opts)
			if e != nil {
				m.Uncertain = append(m.Uncertain, id)
				return e
			}
			previous = digest("durable-receipt", r)
		}
		m.StorageBefore, e = d.durableBudget(ctx, i.Source)
		if e != nil {
			return e
		}
		if p.Contract.Scenario == "missing-receipt" {
			// The approved synthetic case withholds publication from the verifier,
			// without fabricating or changing the real database COMMIT.
			if e = withholdDurableReceipt(i.Directory, 8); e != nil {
				return e
			}
		}
		var flight <-chan error
		var stopFlight context.CancelFunc
		if p.Contract.Scenario == "inflight-crash" {
			flight, stopFlight, e = startDurableInflight(ctx, d, p, &j)
			if e != nil {
				return e
			}
			defer stopFlight()
			m.Uncertain = append(m.Uncertain, 17)
		}
		if e = hook("before-failure-intent"); e != nil {
			return e
		}
		if e = check(i.Source); e != nil {
			return e
		}
		if e = check(i.Restore); e != nil {
			return e
		}
		v, e = d.sql(ctx, i.Restore.ID, emptySQL)
		if e != nil || v != "0" {
			return errors.New("restore destination changed before failure intent; SIGKILL denied")
		}
		if e = validateDurableFile(archive, backup); e != nil {
			return e
		}
		// A one-time claim and synced intent precede SIGKILL. Never reopen an
		// old invocation after a crash, regardless of whether Docker replied.
		if e = localstate.WriteNew(filepath.Join(i.Directory, "durable-failure-intent.json"), struct{ Plan, Source, Backup, Signal string }{p.Digest, i.Source.ID, backup.SHA256, "SIGKILL"}); e != nil {
			return e
		}
		m.Timeline.IntentNS = time.Since(j.start).Nanoseconds()
		if e = j.append("SOURCE_SIGKILL_INTENT", map[string]string{"source": i.Source.ID, "signal": "SIGKILL", "backupSha256": backup.SHA256}); e != nil {
			return e
		}
		if e = hook("failure-intent"); e != nil {
			return e
		}
		if e = check(i.Source); e != nil {
			return e
		}
		t := &m.Timeline
		t.LastAvailableStartNS = time.Since(j.start).Nanoseconds()
		v, e = d.sql(ctx, i.Source.ID, "SELECT 'available:'||pg_postmaster_start_time()::text;")
		t.LastAvailableEndNS = time.Since(j.start).Nanoseconds()
		if e != nil || v != "available:"+i.Source.DB.Boot {
			return errors.New("last source availability not independently verified")
		}
		if e = j.append("SOURCE_LAST_AVAILABLE", struct{ StartNS, EndNS int64 }{t.LastAvailableStartNS, t.LastAvailableEndNS}); e != nil {
			return e
		}
		// Recheck exact original container immediately before the only effect.
		if _, e = d.durableContainer(ctx, i, i.Source, true); e != nil {
			return e
		}
		if e = d.verifyEngine(ctx); e != nil {
			return e
		}
		if e = validateDurableGrant(p, g, "sigkill-source-once", &backup, time.Now(), false); e != nil {
			return e
		}
		t.KillStartNS = time.Since(j.start).Nanoseconds()
		ack, killErr := d.output(ctx, nil, "container", "kill", "--signal", "KILL", i.Source.ID)
		t.KillEndNS = time.Since(j.start).Nanoseconds()
		t.KillExit = toolExit(killErr)
		if killErr == nil {
			zero := 0
			t.KillExit = &zero
		}
		t.KillAcknowledged = killErr == nil && strings.TrimSpace(string(ack)) == i.Source.ID
		t.KillAmbiguous = !t.KillAcknowledged
		if e = j.append("SOURCE_KILL_ACKNOWLEDGEMENT", t); e != nil {
			return e
		}
		if e = hook("source-killed"); e != nil {
			return e
		}
		t.FirstUnavailableStartNS = time.Since(j.start).Nanoseconds()
		stopped, e := d.durableContainer(ctx, i, i.Source, false)
		t.FirstUnavailableEndNS = time.Since(j.start).Nanoseconds()
		if e != nil || stopped.State.Running || stopped.State.Pid != 0 || stopped.State.ExitCode != 137 || stopped.State.OOMKilled || stopped.State.FinishedAt == "" {
			return errors.New("exact source unclean termination not independently observed")
		}
		m.FailureObserved = true
		t.FailureUncertaintyNS = t.FirstUnavailableEndNS - t.LastAvailableStartNS
		if e = verifyPersistentVersion(ctx, d, i.Source); e != nil {
			return e
		}
		m.SourceVolumePersisted = true
		// Close the pre-failure handle. Restore must prove that the published
		// pathname still opens independently after source loss, including on
		// Windows where an open read handle prevents deletion of that pathname.
		if e = archive.Close(); e != nil {
			return e
		}
		if e = j.append("SOURCE_UNAVAILABLE_OBSERVED", map[string]any{"source": i.Source.ID, "exitCode": stopped.State.ExitCode, "observationEndNs": t.FirstUnavailableEndNS, "persistentVolumeVerified": true}); e != nil {
			return e
		}
		if flight != nil {
			select {
			case <-flight:
			case <-ctx.Done():
				return ctx.Err()
			}
			if e = j.append("INFLIGHT_OUTCOME_UNCERTAIN", map[string]int{"id": 17}); e != nil {
				return e
			}
		}
		if e = hook("source-observed"); e != nil {
			return e
		}
		if !t.KillAcknowledged {
			return errors.New("SIGKILL acknowledgement ambiguous; no retry")
		}
		if e = check(i.Restore); e != nil {
			return e
		}
		v, e = d.sql(ctx, i.Restore.ID, emptySQL)
		if e != nil || v != "0" {
			return errors.New("restore destination no longer empty")
		}
		// Reopen the protected host artifact after the source is unavailable.
		fresh, _, e := openDurableBackup(p)
		if e != nil {
			return e
		}
		defer fresh.Close()
		if e = hook("before-restore"); e != nil {
			return e
		}
		if e = validateDurableFile(fresh, backup); e != nil {
			return e
		}
		if e = j.append("RESTORE_INTENT", map[string]string{"destination": i.Restore.ID, "backupSha256": backup.SHA256}); e != nil {
			return e
		}
		t.RestoreStartNS = time.Since(j.start).Nanoseconds()
		var input io.Reader = fresh
		if opts.restoreInput != nil {
			input = opts.restoreInput(input)
		}
		e = d.command(ctx, input, io.Discard, 65536, "exec", "--user", "999:999", "-i", i.Restore.ID, "pg_restore", "-w", "--single-transaction", "--exit-on-error", "--no-owner", "--no-privileges", "-h", "127.0.0.1", "-p", "5432", "-U", "themis", "-d", Database)
		m.RestoreExit = toolExit(e)
		if e == nil {
			zero := 0
			m.RestoreExit = &zero
		}
		if je := j.append("RESTORE_TOOL_EXIT", map[string]any{"exitCode": m.RestoreExit}); je != nil {
			return je
		}
		if e != nil {
			return e
		}
		if e = hook("restored"); e != nil {
			return e
		}
		if e = validateDurableFile(fresh, backup); e != nil {
			return e
		}
		if e = check(i.Restore); e != nil {
			return e
		}
		schema, e := d.sql(ctx, i.Restore.ID, schemaSQL)
		if e != nil {
			return e
		}
		m.SchemaObserved = true
		m.SchemaMatch = schema == prepared.Schema
		if e = observeDurable(ctx, d, p, m); e != nil {
			return e
		}
		v, e = d.sql(ctx, i.Restore.ID, "BEGIN; UPDATE themis_app.health SET counter=counter+1 WHERE singleton=1; COMMIT; SELECT counter FROM themis_app.health WHERE singleton=1;")
		if e != nil || v != "BEGIN\nUPDATE 1\nCOMMIT\n1" {
			return errors.New("restored application committed read/write readiness unverified")
		}
		m.StorageAfter, e = d.durableBudget(ctx, i.Restore)
		if e != nil {
			return e
		}
		m.ReadWriteReady = true
		t.ReadyNS = time.Since(j.start).Nanoseconds()
		t.RecoveryUpperNS = t.ReadyNS - t.LastAvailableStartNS
		t.RecoveryLowerNS = t.ReadyNS - t.FirstUnavailableEndNS
		if e = j.append("RECOVERY_VERIFIED", m); e != nil {
			return e
		}
		return nil
	}
	problem = work()
	return report, nil
}

func withholdDurableReceipt(dir string, id int) error {
	// Rename inside the original protected directory, preserving the actual
	// signed receipt for review but excluding it from retained verifier input.
	source := filepath.Join(dir, fmt.Sprintf("durable-receipt-%02d.json", id))
	destination := filepath.Join(dir, fmt.Sprintf("durable-withheld-%02d.json", id))
	if e := os.Link(source, destination); e != nil {
		return e
	}
	if e := os.Remove(source); e != nil {
		return e
	}
	return localstate.SyncDirectory(dir)
}

func verifyPersistentVersion(ctx context.Context, d Docker, r Resource) error {
	var b bytes.Buffer
	if e := d.command(ctx, nil, &b, 65536, "cp", r.ID+":/var/lib/postgresql/18/docker/PG_VERSION", "-"); e != nil {
		return e
	}
	tr := tar.NewReader(&b)
	h, e := tr.Next()
	if e != nil || h.Typeflag != tar.TypeReg || h.Name != "PG_VERSION" || h.Size != 3 {
		return errors.New("persistent PostgreSQL version metadata unavailable")
	}
	v, e := io.ReadAll(io.LimitReader(tr, 4))
	if e != nil || string(v) != "18\n" {
		return errors.New("persistent source bytes not verified")
	}
	if _, e = tr.Next(); e != io.EOF {
		return errors.New("unexpected persistence metadata archive")
	}
	return nil
}

func startDurableInflight(ctx context.Context, d Docker, p DurablePlan, j *journal) (<-chan error, context.CancelFunc, error) {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	if e := j.append("INFLIGHT_BEGIN_INTENT", map[string]int{"id": 17}); e != nil {
		cancel()
		return nil, cancel, e
	}
	go func() {
		_, e := d.sql(ctx, p.Inventory.Source.ID, fmt.Sprintf("SET application_name='themis_inflight'; SET statement_timeout='60000'; BEGIN; INSERT INTO themis_app.transactions VALUES(17,'%s'); UPDATE themis_app.accounts SET balance=balance-1 WHERE id=1; UPDATE themis_app.accounts SET balance=balance+1 WHERE id=2; SELECT pg_sleep(60); COMMIT;", payload(17)))
		done <- e
	}()
	for {
		v, e := d.sql(ctx, p.Inventory.Source.ID, "SELECT count(*) FROM pg_stat_activity WHERE application_name='themis_inflight' AND state='active' AND wait_event='PgSleep' AND xact_start IS NOT NULL;")
		if e == nil && v == "1" {
			return done, cancel, j.append("INFLIGHT_TRANSACTION_OBSERVED", map[string]int{"id": 17})
		}
		select {
		case <-done:
			cancel()
			return nil, cancel, errors.New("inflight transaction ended before independent observation")
		case <-ctx.Done():
			cancel()
			return nil, cancel, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func observeDurable(ctx context.Context, d Docker, p DurablePlan, m *DurableMeasurements) error {
	v, e := d.sql(ctx, p.Inventory.Restore.ID, `SELECT coalesce(json_agg(x ORDER BY id),'[]'::json) FROM (SELECT id,payload FROM themis_app.transactions) x;`)
	if e != nil {
		return e
	}
	if e = json.Unmarshal([]byte(v), &m.Rows); e != nil {
		return errors.New("restored dataset observation invalid")
	}
	v, e = d.sql(ctx, p.Inventory.Restore.ID, "SELECT id||':'||balance FROM themis_app.accounts ORDER BY id;")
	if e != nil {
		return e
	}
	m.IntegrityObserved = true
	m.IntegrityOK = v == fmt.Sprintf("1:%d\n2:%d", 10000-len(m.Rows), 10000+len(m.Rows)) && len(m.Rows) >= BaselineCommits && len(m.Rows) <= m.ExpectedCommits
	seen := map[int]string{}
	for _, r := range m.Rows {
		if _, ok := seen[r.ID]; ok {
			m.Duplicates = append(m.Duplicates, r.ID)
			m.IntegrityOK = false
		}
		seen[r.ID] = r.Payload
		if r.ID < 1 || r.ID > m.ExpectedCommits {
			m.Unexpected = append(m.Unexpected, r.ID)
			m.IntegrityOK = false
		}
		if r.Payload != payload(r.ID) {
			m.Corrupt = append(m.Corrupt, r.ID)
			m.IntegrityOK = false
		}
	}
	for id := 1; id <= BaselineCommits; id++ {
		if seen[id] != payload(id) {
			m.IntegrityOK = false
		}
	}
	for id := 1; id <= m.ExpectedCommits; id++ {
		var r DurableReceipt
		if e = localstate.Read(filepath.Join(p.Inventory.Directory, fmt.Sprintf("durable-receipt-%02d.json", id)), &r); e != nil || r.ID != id || !validDurableReceipt(r, p) {
			m.Uncertain = append(m.Uncertain, id)
			continue
		}
		m.Receipts = append(m.Receipts, r)
		if _, ok := seen[id]; !ok {
			m.Missing = append(m.Missing, id)
		}
	}
	m.ReceiptCoverage = verifyDurableReceipts(m.Receipts, p, m.ExpectedCommits) == nil
	m.DataLossExact = m.ReceiptCoverage
	for _, r := range m.Receipts {
		if r.ID != m.RecoveryPoint+1 || seen[r.ID] != r.Payload {
			break
		}
		m.RecoveryPoint = r.ID
	}
	return nil
}
