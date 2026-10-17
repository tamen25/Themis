package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

func RunPITR(ctx context.Context, dir string) (PITRReport, error) {
	return runPITR(ctx, dir, pitrOptions{})
}
func runPITR(ctx context.Context, dir string, opts pitrOptions) (report PITRReport, err error) {
	p, err := loadPITRPlan(dir)
	if err != nil {
		return report, err
	}
	i := p.Inventory
	l, err := acquire(i.Directory)
	if err != nil {
		return report, err
	}
	defer l.Close()
	s, err := loadPITRPrepared(p)
	if err != nil {
		return report, err
	}
	if err = verifyPITRCapsule(p, s); err != nil {
		return report, err
	}
	var g PITRGrant
	if err = localstate.Read(filepath.Join(i.Directory, "pitr-sigkill-physical-target-once-authorization.json"), &g); err != nil {
		return report, err
	}
	if err = validatePITRGrant(p, g, "sigkill-physical-target-once", s.Digest, time.Now(), true); err != nil {
		return report, err
	}
	if err = localstate.WriteNew(filepath.Join(i.Directory, "pitr-invocation.json"), map[string]string{"executionPlan": s.Digest}); err != nil {
		return report, errors.New("PITR invocation consumed; ambiguous effects cannot be retried")
	}
	f, err := localstate.OpenNew(filepath.Join(i.Directory, "pitr-journal.jsonl"))
	if err != nil {
		return report, err
	}
	defer f.Close()
	j := journal{w: f, start: time.Now(), plan: p.Digest, version: PITRVersion}
	deadline := j.start.Add(120 * time.Second)
	if g.ExecuteBefore.Before(deadline) {
		deadline = g.ExecuteBefore
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	report = PITRReport{Version: PITRVersion, Run: i.Run, Plan: p.Digest, ExecutionPlan: s.Digest, Live: true, At: time.Now().UTC(), Provenance: "live owned local physical recovery; host receipt signatures scoped to bytes; whole execution unsigned"}
	m := &report.Measurements
	m.Prepared = s
	m.Timeline.Anchor = DurableAnchor
	m.Timeline.Clock = "one runner monotonic clock; preparation receipt sessions are separate; loss time gap unknown"
	d := Docker{i.Endpoint, i.Engine}
	var problem error
	defer func() {
		if problem != nil {
			report.Problem = problem.Error()
		}
		if ctx.Err() != nil && report.Problem == "" {
			report.Problem = "execution canceled or deadline elapsed before finalization"
		}
		if e := pitrAfter(opts, "CLEANUP_STARTING", p); e != nil && report.Problem == "" {
			report.Problem = "cleanup admission interrupted"
		}
		if e := retainPITRLogs(context.Background(), i); e != nil && report.Problem == "" {
			report.Problem = "sanitized PostgreSQL logs unavailable"
		}
		report.Cleanup = pitrCleanup(context.Background(), i, p.Contract.Scenario == "cleanup-denied")
		if e := localstate.WriteNew(filepath.Join(i.Directory, "pitr-cleanup-initial.json"), report.Cleanup); e != nil {
			report.Cleanup.Complete = false
			report.Problem = "cleanup receipt publication failed"
		}
		if e := j.append("CLEANUP_OBSERVED", report.Cleanup); e != nil {
			report.Problem = "execution journal incomplete"
		}
		b, e := readBounded(filepath.Join(i.Directory, "pitr-journal.jsonl"))
		if e != nil || verifyJournal(b, p.Digest, PITRVersion) != nil {
			report.Problem = "execution journal corrupt"
		}
		// This snapshot admits finalization after independent cleanup. A stop
		// received during cleanup still blocks PASS; later signals do not rewrite
		// an already admitted historical outcome or create conflicting statuses.
		finalContextError := ctx.Err()
		if finalContextError != nil && report.Problem == "" {
			report.Problem = "execution canceled or deadline elapsed before finalization"
		}
		report.Assertions = assessPITR(p, *m, report.Cleanup, report.Problem)
		report.Verdict = result.Aggregate(pitrRequired, report.Assertions, result.RunEvidence{PreconditionsMet: true})
		report.Execution = result.Succeeded
		if report.Verdict == result.Fail {
			report.Execution = result.Failed
		}
		if report.Problem != "" {
			report.Execution = result.Error
		}
		if finalContextError == context.Canceled {
			report.Execution = result.Cancelled
		}
		if finalContextError == context.DeadlineExceeded {
			report.Execution = result.TimedOut
		}
		if !report.Cleanup.Complete {
			report.Execution = result.CleanupPending
		}
		if e = j.append("FINAL", map[string]any{"verdict": report.Verdict, "execution": report.Execution}); e != nil {
			report.Verdict = result.Inconclusive
			report.Execution = result.Error
			if !report.Cleanup.Complete {
				report.Execution = result.CleanupPending
			}
			report.Problem = "final journal publication failed"
		}
		err = localstate.WriteNew(filepath.Join(i.Directory, "pitr-report.json"), report)
	}()
	work := func() error {
		if err := d.pitrSource(ctx, i); err != nil {
			return err
		}
		if err := pitrSourceConfiguration(ctx, d, i); err != nil {
			return err
		}
		for _, r := range []Resource{i.Restore, i.Archive} {
			if _, err := d.pitrContainer(ctx, i, r, true, true); err != nil {
				return err
			}
		}
		if _, err := pitrExec(ctx, d, i.Restore.ID, "test", "!", "-e", "/var/lib/postgresql/18/docker"); err != nil {
			return errors.New("fresh physical restore destination no longer empty")
		}
		if err := verifyPITRCapsule(p, s); err != nil {
			return err
		}
		if err := pitrCheckArchive(ctx, d, p, s); err != nil {
			return err
		}
		m.BackupVerified = true
		m.WALVerified = true
		var flight <-chan error
		if p.Contract.Scenario == "inflight-crash" {
			var end context.CancelFunc
			var e error
			flight, end, e = startPITRInflight(ctx, d, p, &j)
			if e != nil {
				return e
			}
			defer end()
			m.Uncertain = []int{21}
		}
		if err := j.append("SOURCE_SIGKILL_INTENT", map[string]string{"source": i.Source.ID, "executionPlan": s.Digest}); err != nil {
			return err
		}
		t := &m.Timeline
		t.IntentNS = time.Since(j.start).Nanoseconds()
		if err := pitrAfter(opts, "FAILURE_INTENT", p); err != nil {
			return err
		}
		if err := d.pitrSource(ctx, i); err != nil {
			return err
		}
		t.LastAvailableStartNS = time.Since(j.start).Nanoseconds()
		v, e := d.sql(ctx, i.Source.ID, "SELECT 'available:'||pg_postmaster_start_time()::text;")
		t.LastAvailableEndNS = time.Since(j.start).Nanoseconds()
		if e != nil || v != "available:"+i.Source.DB.Boot {
			return errors.New("source availability unverified")
		}
		if err := j.append("SOURCE_LAST_AVAILABLE", t); err != nil {
			return err
		}
		if _, err := d.pitrContainer(ctx, i, i.Source, true, true); err != nil {
			return err
		}
		if err := validatePITRGrant(p, g, "sigkill-physical-target-once", s.Digest, time.Now(), false); err != nil {
			return err
		}
		t.KillStartNS = time.Since(j.start).Nanoseconds()
		ack, e := d.output(ctx, nil, "container", "kill", "--signal", "KILL", i.Source.ID)
		t.KillEndNS = time.Since(j.start).Nanoseconds()
		t.KillExit = toolExit(e)
		t.KillAcknowledged = e == nil && strings.TrimSpace(string(ack)) == i.Source.ID
		t.KillAmbiguous = !t.KillAcknowledged
		if err := j.append("KILL_COMMAND_OUTCOME", t); err != nil {
			return err
		}
		t.FirstUnavailableStartNS = time.Since(j.start).Nanoseconds()
		stopped, e := d.pitrContainer(ctx, i, i.Source, false, true)
		t.FirstUnavailableEndNS = time.Since(j.start).Nanoseconds()
		if e != nil || stopped.State.Running || stopped.State.Pid != 0 || stopped.State.ExitCode != 137 || stopped.State.OOMKilled || stopped.State.FinishedAt == "" {
			return errors.New("exact source SIGKILL not independently observed")
		}
		m.FailureObserved = true
		// Assertions require the independently reopened artifacts after source
		// loss, rather than borrowing the successful pre-fault check.
		m.BackupVerified, m.WALVerified = false, false
		t.FailureUncertaintyNS = t.FirstUnavailableEndNS - t.LastAvailableStartNS
		if err := verifyPersistentVersion(ctx, d, i.Source); err != nil {
			return err
		}
		if err := j.append("SOURCE_STOPPED_OBSERVED", t); err != nil {
			return err
		}
		if flight != nil {
			select {
			case <-flight:
			case <-ctx.Done():
				return ctx.Err()
			}
			if err := j.append("INFLIGHT_OUTCOME_UNCERTAIN", map[string]int{"id": 21}); err != nil {
				return err
			}
		}
		if err := pitrAfter(opts, "SOURCE_STOPPED", p); err != nil {
			return err
		}
		if !t.KillAcknowledged {
			return errors.New("SIGKILL outcome ambiguous; no retry")
		}
		if p.Contract.Scenario == "missing-wal" {
			last := s.WAL[len(s.WAL)-1]
			src := pitrCapsule(i, last.Name)
			if err := os.Link(src, src+".withheld"); err != nil {
				return err
			}
			if err := os.Remove(src); err != nil {
				return err
			}
		}
		if err := verifyPITRCapsule(p, s); err != nil {
			return errors.New("independent backup or required WAL unavailable after source loss")
		}
		if err := pitrCheckArchive(ctx, d, p, s); err != nil {
			return err
		}
		m.BackupVerified, m.WALVerified = true, true
		if err := j.append("INDEPENDENT_CAPSULE_VERIFIED", map[string]string{"executionPlan": s.Digest}); err != nil {
			return err
		}
		t.RestoreStartNS = time.Since(j.start).Nanoseconds()
		if err := pitrRestore(ctx, d, p, s, opts); err != nil {
			return err
		}
		if err := pitrAfter(opts, "RECOVERY_STARTED", p); err != nil {
			return err
		}
		if err := pitrObserveTarget(ctx, d, p, s, m); err != nil {
			return err
		}
		if err := j.append("TARGET_INDEPENDENTLY_OBSERVED", m); err != nil {
			return err
		}
		if err := pitrAfter(opts, "TARGET_PAUSED", p); err != nil {
			return err
		}
		if !m.TargetFidelity || !m.SchemaMatch || !m.IntegrityOK {
			return errors.New("recovery target application fidelity failed; promotion withheld")
		}
		if _, err := d.sql(ctx, i.Restore.ID, "SELECT pg_wal_replay_resume();"); err != nil {
			return err
		}
		if err := pitrObservePromotion(ctx, d, p, s, m); err != nil {
			return err
		}
		if err := pitrAfter(opts, "PROMOTED", p); err != nil {
			return err
		}
		if err := pitrObserveData(ctx, d, p, s, m); err != nil {
			return err
		}
		if !m.TargetFidelity || !m.SchemaMatch || !m.IntegrityOK {
			return errors.New("promoted application data or invariant mismatch")
		}
		v, e = d.sql(ctx, i.Restore.ID, "BEGIN; UPDATE themis_app.health SET counter=counter+1 WHERE singleton=1; COMMIT; SELECT counter FROM themis_app.health WHERE singleton=1;")
		if e != nil || v != "BEGIN\nUPDATE 1\nCOMMIT\n1" {
			return errors.New("restored application committed write/read not verified")
		}
		if _, err := d.durableBudget(ctx, i.Restore); err != nil {
			return err
		}
		m.ReadWriteReady = true
		t.ReadyNS = time.Since(j.start).Nanoseconds()
		t.RecoveryUpperNS = t.ReadyNS - t.LastAvailableStartNS
		t.RecoveryLowerNS = t.ReadyNS - t.FirstUnavailableEndNS
		if err := j.append("RECOVERY_READY", m); err != nil {
			return err
		}
		return pitrAfter(opts, "RECOVERY_READY", p)
	}
	problem = work()
	return report, nil
}
func pitrRestore(ctx context.Context, d Docker, p PITRPlan, s PITRPrepared, opts pitrOptions) error {
	i := p.Inventory
	if _, err := d.pitrContainer(ctx, i, i.Restore, true, true); err != nil {
		return err
	}
	if _, err := pitrExec(ctx, d, i.Restore.ID, "test", "!", "-e", "/var/lib/postgresql/18/docker"); err != nil {
		return errors.New("preexisting physical restore directory refused")
	}
	if _, err := pitrExec(ctx, d, i.Restore.ID, "mkdir", "-m", "700", "-p", "/var/lib/postgresql/18/docker", "/var/lib/postgresql/themis-restore-wal"); err != nil {
		return err
	}
	f, err := os.Open(pitrCapsule(i, "base.tar"))
	if err != nil {
		return err
	}
	defer f.Close()
	if err = pitrValidateHandle(f, s.Base, PITRBackupBytes); err != nil {
		return err
	}
	var input io.Reader = f
	if opts.restoreInput != nil {
		input = opts.restoreInput(input)
	}
	_, err = d.output(ctx, input, "exec", "-i", "--user", "999:999", i.Restore.ID, "tar", "-xmf", "-", "--no-same-owner", "--keep-old-files", "-C", "/var/lib/postgresql/18/docker")
	if err != nil {
		return err
	}
	if err = pitrValidateHandle(f, s.Base, PITRBackupBytes); err != nil {
		return err
	}
	if _, err = pitrExec(ctx, d, i.Restore.ID, "pg_verifybackup", "--exit-on-error", "/var/lib/postgresql/18/docker"); err != nil {
		return errors.New("destination physical backup verification failed")
	}
	files := map[string]string{}
	for _, w := range s.WAL {
		b, err := pitrReadWAL(i, w)
		if err != nil {
			return err
		}
		files[strings.TrimPrefix(w.Name, "wal/")] = string(b)
	}
	if err = pitrDeliver(ctx, d, i.Restore.ID, "/var/lib/postgresql/themis-restore-wal", files); err != nil {
		return err
	}
	for _, w := range s.WAL {
		b, err := pitrExec(ctx, d, i.Restore.ID, "sha256sum", "--", "/var/lib/postgresql/themis-restore-wal/"+strings.TrimPrefix(w.Name, "wal/"))
		fields := strings.Fields(string(b))
		if err != nil || len(fields) != 2 || fields[0] != w.SHA256 {
			return errors.New("destination WAL hash mismatch")
		}
	}
	config := "include = '/var/lib/postgresql/18/docker/postgresql.conf'\nrecovery_target_name = '" + p.TargetName + "'\n"
	if err = pitrDeliver(ctx, d, i.Restore.ID, "/var/lib/postgresql/themis-recovery", map[string]string{"postgresql.conf": config}); err != nil {
		return err
	}
	if err = pitrDeliver(ctx, d, i.Restore.ID, "/var/lib/postgresql/18/docker", map[string]string{"recovery.signal": ""}); err != nil {
		return err
	}
	if err = pitrAfter(opts, "BEFORE_RECOVERY_START", p); err != nil {
		return err
	}
	return pitrDeliver(ctx, d, i.Restore.ID, "/var/lib/postgresql/themis-recovery", map[string]string{"start": "start\n"})
}
func pitrObserveTarget(ctx context.Context, d Docker, p PITRPlan, s PITRPrepared, m *PITRMeasurements) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	for {
		v, err := d.sql(ctx, p.Inventory.Restore.ID, "SELECT CASE WHEN pg_is_in_recovery() THEN 't' ELSE 'f' END||'|'||pg_get_wal_replay_pause_state()||'|'||pg_last_wal_replay_lsn()||'|'||current_setting('recovery_target_name')||'|'||current_setting('recovery_target_timeline')||'|'||current_setting('recovery_target_action');")
		if err == nil {
			m.TargetObservation = v
			if validPITRTarget(p, s, v) {
				break
			}
			if strings.HasPrefix(v, "f|") || strings.Contains(v, "|paused|") {
				return errors.New("wrong recovery target or replay position; no promotion")
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("intended PITR target not independently proven")
		case <-time.After(100 * time.Millisecond):
		}
	}
	i := p.Inventory
	if _, err := d.pitrContainer(ctx, i, i.Restore, true, true); err != nil {
		return err
	}
	id, err := d.databaseIdentity(ctx, i.Restore)
	if err != nil {
		return err
	}
	if id.System != i.Source.DB.System || id.Database != Database || id.Version != "180006" || id.Boot == i.Source.DB.Boot {
		return errors.New("physical system identifier or independent destination boot invalid")
	}
	m.Destination = id
	m.TargetObserved = true
	return pitrObserveData(ctx, d, p, s, m)
}
func pitrObserveData(ctx context.Context, d Docker, p PITRPlan, s PITRPrepared, m *PITRMeasurements) error {
	i := p.Inventory
	var err error
	m.Receipts, err = loadPITRReceipts(p, s.Receipts)
	if err != nil {
		return err
	}
	m.ReceiptCoverage = true
	v, err := d.sql(ctx, i.Restore.ID, `SELECT coalesce(json_agg(x ORDER BY id),'[]'::json) FROM (SELECT id,payload,xmin::text AS "XID" FROM themis_app.transactions) x;`)
	if err != nil {
		return err
	}
	if err = json.Unmarshal([]byte(v), &m.Rows); err != nil {
		return errors.New("invalid restored row evidence")
	}
	m.Missing, m.Unexpected, m.Duplicates, m.Corrupt = nil, nil, nil, nil
	m.RecoveryPoint = 0
	seen := map[int]int{}
	actual := map[int]PITRRow{}
	m.TargetFidelity = len(m.Rows) == PITRBoundary
	for _, r := range m.Rows {
		seen[r.ID]++
		actual[r.ID] = r
		if seen[r.ID] > 1 {
			m.Duplicates = append(m.Duplicates, r.ID)
		}
		if r.ID < 1 || r.ID > PITRBoundary {
			m.Unexpected = append(m.Unexpected, r.ID)
			m.TargetFidelity = false
		}
	}
	for _, r := range m.Receipts {
		got, exists := actual[r.ID]
		if !exists {
			m.Missing = append(m.Missing, r.ID)
			if r.ID <= PITRBoundary {
				m.TargetFidelity = false
			}
			continue
		}
		if got.Payload != r.Payload || got.XID != r.XID {
			m.Corrupt = append(m.Corrupt, r.ID)
			m.TargetFidelity = false
		}
		if r.ID == m.RecoveryPoint+1 && got.Payload == r.Payload && got.XID == r.XID {
			m.RecoveryPoint = r.ID
		}
	}
	if len(m.Duplicates) > 0 {
		m.TargetFidelity = false
	}
	m.DataLossExact = true
	v, err = d.sql(ctx, i.Restore.ID, schemaSQL)
	if err != nil {
		return err
	}
	m.SchemaObserved = true
	m.SchemaMatch = v == s.Schema
	v, err = d.sql(ctx, i.Restore.ID, "SELECT id||':'||balance FROM themis_app.accounts ORDER BY id;")
	if err != nil {
		return err
	}
	m.IntegrityObserved = true
	m.IntegrityOK = v == "1:9980\n2:10020"
	return nil
}
func validPITRTarget(p PITRPlan, s PITRPrepared, v string) bool {
	return v == "t|paused|"+s.TargetLSN+"|"+p.TargetName+"|1|pause"
}
func pitrObservePromotion(ctx context.Context, d Docker, p PITRPlan, s PITRPrepared, m *PITRMeasurements) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		v, err := d.sql(ctx, p.Inventory.Restore.ID, "SELECT CASE WHEN pg_is_in_recovery() THEN 't' ELSE 'f' END||'|'||(SELECT timeline_id FROM pg_control_checkpoint());")
		if err == nil && v == "f|2" {
			m.PromotedObservation = v
			break
		}
		select {
		case <-ctx.Done():
			return errors.New("PITR promotion/new timeline unverified")
		case <-time.After(100 * time.Millisecond):
		}
	}
	b, err := pitrExec(ctx, d, p.Inventory.Restore.ID, "cat", "/var/lib/postgresql/18/docker/pg_wal/00000002.history")
	if err != nil {
		return err
	}
	m.TimelineHistory = string(b)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 1 {
		return errors.New("unexpected PITR timeline ancestry")
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 3 || fields[0] != "1" || fields[1] != s.TargetLSN {
		return errors.New("PITR timeline branch point mismatch")
	}
	m.Promoted = true
	return nil
}
func startPITRInflight(ctx context.Context, d Docker, p PITRPlan, j *journal) (<-chan error, context.CancelFunc, error) {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	if err := j.append("INFLIGHT_BEGIN_INTENT", map[string]int{"id": 21}); err != nil {
		cancel()
		return nil, cancel, err
	}
	go func() {
		_, err := d.sql(ctx, p.Inventory.Source.ID, fmt.Sprintf("SET application_name='themis_pitr_inflight'; SET statement_timeout='60000'; BEGIN; INSERT INTO themis_app.transactions VALUES(21,'%s'); SELECT pg_sleep(60); COMMIT;", payload(21)))
		done <- err
	}()
	for {
		v, err := d.sql(ctx, p.Inventory.Source.ID, "SELECT count(*) FROM pg_stat_activity WHERE application_name='themis_pitr_inflight' AND state='active' AND wait_event='PgSleep' AND xact_start IS NOT NULL;")
		if err == nil && v == "1" {
			return done, cancel, j.append("INFLIGHT_TRANSACTION_OBSERVED", map[string]int{"id": 21})
		}
		select {
		case <-done:
			cancel()
			return nil, cancel, errors.New("inflight transaction ended before observation")
		case <-ctx.Done():
			cancel()
			return nil, cancel, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Keep numeric receipt identities explicit when PostgreSQL returns text XIDs.
func validPITRXID(xid string) bool {
	n, err := strconv.ParseUint(xid, 10, 64)
	return err == nil && n > 0
}
