package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

func RunReplication(ctx context.Context, dir string) (ReplicationReport, error) {
	return runReplication(ctx, dir, replicationOptions{})
}
func runReplication(ctx context.Context, dir string, o replicationOptions) (report ReplicationReport, err error) {
	p, err := loadReplicationPlan(dir)
	if err != nil {
		return report, err
	}
	i := p.Inventory
	l, err := acquire(i.Directory)
	if err != nil {
		return report, err
	}
	defer l.Close()
	s, err := loadReplicationPrepared(p)
	if err != nil {
		return report, err
	}
	var termination, promotion ReplicationGrant
	for _, pair := range []struct {
		scope string
		grant *ReplicationGrant
	}{{"terminate-and-fence", &termination}, {"promote-fenced-standby", &promotion}} {
		if err = localstate.Read(filepath.Join(i.Directory, "replication-"+pair.scope+"-authorization.json"), pair.grant); err != nil {
			return report, err
		}
		if err = validateReplicationGrant(p, *pair.grant, pair.scope, s.Digest, s.Invocation, time.Now(), true); err != nil {
			return report, err
		}
	}
	if err = localstate.WriteNew(filepath.Join(i.Directory, "replication-invocation.json"), map[string]string{"executionPlan": s.Digest, "invocation": s.Invocation}); err != nil {
		return report, errors.New("failover invocation consumed; no automatic retry or resume")
	}
	f, err := localstate.OpenNew(filepath.Join(i.Directory, "replication-journal.jsonl"))
	if err != nil {
		return report, err
	}
	defer f.Close()
	j := journal{w: f, start: time.Now(), plan: p.Digest, version: ReplicationVersion}
	deadline := j.start.Add(120 * time.Second)
	for _, g := range []ReplicationGrant{termination, promotion} {
		if g.ExecuteBefore.Before(deadline) {
			deadline = g.ExecuteBefore
		}
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	report = ReplicationReport{Version: ReplicationVersion, Run: i.Run, Plan: p.Digest, ExecutionPlan: s.Digest, Live: true, At: time.Now().UTC(), Provenance: "live owned local physical streaming failover; host receipt signatures scoped to bytes; whole execution unsigned"}
	m := &report.Measurements
	m.Prepared = s
	m.Authorization = true
	m.Timeline.Anchor = DurableAnchor
	m.Timeline.Clock = "one runner monotonic clock; last primary committed write to promoted committed write/read; preparation receipt clock separate"
	d := Docker{i.Endpoint, i.Engine}
	var problem error
	defer func() {
		if problem != nil {
			report.Problem = problem.Error()
		}
		if e := replicationAfter(o, "CLEANUP_STARTING", p); e != nil && report.Problem == "" {
			report.Problem = "cleanup admission interrupted"
		}
		if e := retainReplicationLog(context.Background(), i, i.Standby); e != nil && report.Problem == "" {
			report.Problem = "sanitized standby PostgreSQL log unavailable"
		}
		report.Cleanup = replicationCleanup(context.Background(), i, p.Contract.Scenario == "cleanup-denied")
		if e := localstate.WriteNew(filepath.Join(i.Directory, "replication-cleanup-initial.json"), report.Cleanup); e != nil {
			report.Cleanup.Complete = false
			report.Problem = "cleanup receipt publication failed"
		}
		if e := j.append("CLEANUP_OBSERVED", report.Cleanup); e != nil {
			report.Problem = "execution journal incomplete"
		}
		data, e := readBounded(filepath.Join(i.Directory, "replication-journal.jsonl"))
		if e != nil || verifyJournal(data, p.Digest, ReplicationVersion) != nil {
			report.Problem = "execution journal corrupt"
		}
		finalContextError := ctx.Err()
		if finalContextError != nil && report.Problem == "" {
			report.Problem = "execution canceled or deadline elapsed before finalization"
		}
		report.Assertions = assessReplication(p, *m, report.Cleanup, report.Problem)
		report.Verdict = result.Aggregate(replicationRequired, report.Assertions, result.RunEvidence{PreconditionsMet: true})
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
		err = localstate.WriteNew(filepath.Join(i.Directory, "replication-report.json"), report)
	}()
	work := func() error {
		if e := j.append("FAILOVER_ADMITTED", map[string]string{"executionPlan": s.Digest, "invocation": s.Invocation}); e != nil {
			return e
		}
		var e error
		m.BeforeFailure, e = waitReplication(ctx, d, i, s.LastAckLSN)
		if e != nil {
			return e
		}
		m.ReplicationVerified = true
		var baselineData ReplicationMeasurements
		if e = replicationObserveData(ctx, d, p, s, &baselineData); e != nil {
			return e
		}
		if len(baselineData.Missing)+len(baselineData.Corrupt)+len(baselineData.Duplicates)+len(baselineData.Unexpected) != 0 || !baselineData.SchemaMatch || !baselineData.IntegrityOK {
			return errors.New("pre-failover physical replica fidelity invalid")
		}
		m.StorageBefore = map[string]ReplicationStorage{}
		for _, r := range i.resources() {
			m.StorageBefore[r.Role], e = d.replicationBudget(ctx, r)
			if e != nil {
				return e
			}
		}
		if e = j.append("PRIMARY_TERMINATION_INTENT", map[string]string{"primary": i.Primary.ID, "executionPlan": s.Digest, "invocation": s.Invocation}); e != nil {
			return e
		}
		t := &m.Timeline
		t.IntentNS = time.Since(j.start).Nanoseconds()
		if e = replicationAfter(o, "FAILURE_INTENT", p); e != nil {
			return e
		}
		if e = d.replicationTarget(ctx, i, i.Primary); e != nil {
			return e
		}
		t.LastAvailableStartNS = time.Since(j.start).Nanoseconds()
		v, e := d.replicationSQL(ctx, i.Primary.ID, "BEGIN; SET LOCAL synchronous_commit='remote_apply'; UPDATE themis_app.health SET counter=counter+1 WHERE singleton=1; COMMIT; SELECT counter FROM themis_app.health WHERE singleton=1;")
		t.LastAvailableEndNS = time.Since(j.start).Nanoseconds()
		if e != nil || v != "BEGIN\nSET\nUPDATE 1\nCOMMIT\n1" {
			return errors.New("last primary committed write availability unverified")
		}
		m.BeforeFailure, e = waitReplication(ctx, d, i, s.LastAckLSN)
		if e != nil {
			return e
		}
		if e = j.append("LAST_PRIMARY_WRITE_AND_REPLICATION", m.BeforeFailure); e != nil {
			return e
		}
		if _, e = d.replicationContainer(ctx, i, i.Primary, true, true); e != nil {
			return e
		}
		if e = validateReplicationGrant(p, termination, "terminate-and-fence", s.Digest, s.Invocation, time.Now(), false); e != nil {
			return e
		}
		if e = validateReplicationGrant(p, promotion, "promote-fenced-standby", s.Digest, s.Invocation, time.Now(), false); e != nil {
			return e
		}
		if e = replicationJournalHealthy(p, &j); e != nil {
			return e
		}
		t.KillStartNS = time.Since(j.start).Nanoseconds()
		var ack []byte
		if o.termination != nil {
			ack, e = o.termination(ctx, d, i.Primary.ID)
		} else {
			ack, e = d.output(ctx, nil, "container", "kill", "--signal", "KILL", i.Primary.ID)
		}
		t.KillEndNS = time.Since(j.start).Nanoseconds()
		t.KillExit = toolExit(e)
		t.KillAcknowledged = e == nil && strings.TrimSpace(string(ack)) == i.Primary.ID
		t.KillAmbiguous = !t.KillAcknowledged
		if e = j.append("TERMINATION_OUTCOME", t); e != nil {
			return e
		}
		t.FirstUnavailableStartNS = time.Since(j.start).Nanoseconds()
		stopped, e := d.replicationContainer(ctx, i, i.Primary, false, true)
		t.FirstUnavailableEndNS = time.Since(j.start).Nanoseconds()
		if e != nil || stopped.State.Running || stopped.State.Pid != 0 || stopped.State.ExitCode != 137 || stopped.State.OOMKilled || stopped.State.FinishedAt == "" {
			return errors.New("original primary SIGKILL not independently verified; promotion denied")
		}
		m.FailureObserved = true
		t.FailureUncertaintyNS = t.FirstUnavailableEndNS - t.LastAvailableStartNS
		if e = j.append("PRIMARY_STOPPED_OBSERVED", t); e != nil {
			return e
		}
		if e = replicationAfter(o, "PRIMARY_STOPPED", p); e != nil {
			return e
		}
		if !t.KillAcknowledged {
			return errors.New("termination ambiguous; no retry or promotion")
		}
		if e = replicationFence(ctx, d, p, s, termination, &j, m, o); e != nil {
			return e
		}
		if e = replicationAfter(o, "PRIMARY_FENCED", p); e != nil {
			return e
		}
		if p.Contract.Scenario == "missing-receipt" {
			src := filepath.Join(i.Directory, "replication-receipt-20.json")
			if e = os.Rename(src, src+".withheld"); e != nil {
				return e
			}
		}
		if _, e = loadReplicationPrepared(p); e != nil {
			return errors.New("independent acknowledged COMMIT coverage insufficient; promotion withheld")
		}
		if e = replicationPromote(ctx, d, p, s, promotion, &j, m, o); e != nil {
			return e
		}
		if e = replicationAfter(o, "PROMOTED", p); e != nil {
			return e
		}
		if e = replicationObserveData(ctx, d, p, s, m); e != nil {
			return e
		}
		if !m.SchemaMatch || !m.IntegrityOK || len(m.Corrupt)+len(m.Unexpected)+len(m.Duplicates) != 0 {
			return errors.New("promoted application data or invariants invalid")
		}
		v, e = d.replicationSQL(ctx, i.Standby.ID, "BEGIN; UPDATE themis_app.health SET counter=counter+1 WHERE singleton=1; COMMIT; SELECT counter FROM themis_app.health WHERE singleton=1;")
		if e != nil || v != "BEGIN\nUPDATE 1\nCOMMIT\n2" {
			return errors.New("promoted application COMMIT/read not verified")
		}
		// Record the first successful committed write/read immediately. Later
		// identity, fencing and budget checks still gate PASS but cannot inflate
		// the measured time to that already completed readiness observation.
		t.ReadyNS = time.Since(j.start).Nanoseconds()
		if e = d.replicationTarget(ctx, i, i.Standby); e != nil {
			return e
		}
		present, e := d.exists(ctx, "container", i.Primary.ID)
		if e != nil || present {
			return errors.New("primary fencing lost after promotion")
		}
		m.PrimaryAbsentAfterReady = true
		m.StorageAfter, e = d.replicationBudget(ctx, i.Standby)
		if e != nil {
			return e
		}
		m.ReadWriteReady = true
		t.RecoveryUpperNS = t.ReadyNS - t.LastAvailableStartNS
		t.RecoveryLowerNS = t.ReadyNS - t.FirstUnavailableEndNS
		if e = j.append("WRITE_READY", m); e != nil {
			return e
		}
		return replicationAfter(o, "WRITE_READY", p)
	}
	problem = work()
	return report, nil
}

func replicationFence(ctx context.Context, d Docker, p ReplicationPlan, s ReplicationPrepared, g ReplicationGrant, j *journal, m *ReplicationMeasurements, o replicationOptions) error {
	i := p.Inventory
	if !m.FailureObserved || !m.Timeline.KillAcknowledged {
		return errors.New("fencing requires independently observed original termination")
	}
	if err := j.append("FENCE_REMOVE_INTENT", map[string]string{"primary": i.Primary.ID}); err != nil {
		return err
	}
	if err := replicationAfter(o, "FENCE_INTENT", p); err != nil {
		return err
	}
	if err := validateReplicationGrant(p, g, "terminate-and-fence", s.Digest, s.Invocation, time.Now(), false); err != nil {
		return err
	}
	c, err := d.replicationContainer(ctx, i, i.Primary, false, true)
	if err != nil || c.State.Running || c.State.Pid != 0 || c.State.ExitCode != 137 || c.HostConfig.RestartPolicy.Name != "no" {
		return errors.New("primary stopped/restart fence changed; promotion denied")
	}
	if err = retainReplicationLog(ctx, i, i.Primary); err != nil {
		return err
	}
	if err = replicationJournalHealthy(p, j); err != nil {
		return err
	}
	if err = validateReplicationGrant(p, g, "terminate-and-fence", s.Digest, s.Invocation, time.Now(), false); err != nil {
		return err
	}
	m.FenceStartNS = time.Since(j.start).Nanoseconds()
	ack, e := d.output(ctx, nil, "container", "rm", i.Primary.ID)
	m.FenceEndNS = time.Since(j.start).Nanoseconds()
	m.FenceExit = toolExit(e)
	m.FenceAcknowledged = e == nil && strings.TrimSpace(string(ack)) == i.Primary.ID
	if err := j.append("FENCE_COMMAND_OUTCOME", map[string]any{"exit": m.FenceExit, "acknowledged": m.FenceAcknowledged}); err != nil {
		return err
	}
	present, e := d.exists(ctx, "container", i.Primary.ID)
	if e != nil || present || !m.FenceAcknowledged {
		return errors.New("primary removal or independent absence ambiguous; promotion denied")
	}
	m.Fenced = true
	return j.append("PRIMARY_ABSENCE_VERIFIED", map[string]string{"originalPrimary": i.Primary.ID})
}
func replicationPromote(ctx context.Context, d Docker, p ReplicationPlan, s ReplicationPrepared, g ReplicationGrant, j *journal, m *ReplicationMeasurements, o replicationOptions) error {
	i := p.Inventory
	if !m.Fenced || !m.ReplicationVerified {
		return errors.New("promotion forbidden without verified fencing and replication")
	}
	if err := j.append("PROMOTION_INTENT", map[string]string{"standby": i.Standby.ID, "invocation": s.Invocation}); err != nil {
		return err
	}
	if err := replicationAfter(o, "PROMOTION_INTENT", p); err != nil {
		return err
	}
	if err := validateReplicationGrant(p, g, "promote-fenced-standby", s.Digest, s.Invocation, time.Now(), false); err != nil {
		return err
	}
	if err := d.replicationTarget(ctx, i, i.Standby); err != nil {
		return err
	}
	present, err := d.exists(ctx, "container", i.Primary.ID)
	if err != nil || present {
		return errors.New("primary absence not freshly proven; promotion denied")
	}
	v, err := d.replicationSQL(ctx, i.Standby.ID, "SELECT CASE WHEN pg_is_in_recovery() AND current_setting('transaction_read_only')='on' THEN 'replica' ELSE 'invalid' END||'|'||pg_last_wal_receive_lsn()||'|'||pg_last_wal_replay_lsn();")
	parts := strings.Split(v, "|")
	if err != nil || len(parts) != 3 || parts[0] != "replica" {
		return errors.New("approved promotion target is not an observed read-only physical replica")
	}
	want, e := pitrLSN(s.LastAckLSN)
	if e != nil {
		return e
	}
	for _, lsn := range parts[1:] {
		n, e := pitrLSN(lsn)
		if e != nil || n < want {
			return errors.New("standby receive/replay coverage insufficient")
		}
	}
	m.LastReceivedLSN, m.LastReplayedLSN = parts[1], parts[2]
	if err = replicationJournalHealthy(p, j); err != nil {
		return err
	}
	if err = validateReplicationGrant(p, g, "promote-fenced-standby", s.Digest, s.Invocation, time.Now(), false); err != nil {
		return err
	}
	if err = localstate.WriteNew(filepath.Join(i.Directory, "replication-promotion-invocation.json"), map[string]string{"invocation": s.Invocation, "executionPlan": s.Digest, "standby": i.Standby.ID}); err != nil {
		return errors.New("promotion invocation consumed; no retry")
	}
	m.PromotionStartNS = time.Since(j.start).Nanoseconds()
	m.Timeline.RestoreStartNS = m.PromotionStartNS
	if o.promotion != nil {
		v, err = o.promotion(ctx, d, i.Standby.ID)
	} else {
		v, err = d.replicationSQL(ctx, i.Standby.ID, "SELECT pg_promote(true,10);")
	}
	m.PromotionEndNS = time.Since(j.start).Nanoseconds()
	m.PromotionExit = toolExit(err)
	m.PromotionAcknowledged = err == nil && v == "t"
	if e := j.append("PROMOTION_COMMAND_OUTCOME", map[string]any{"exit": m.PromotionExit, "acknowledged": m.PromotionAcknowledged}); e != nil {
		return e
	}
	if !m.PromotionAcknowledged {
		return errors.New("promotion outcome ambiguous; no retry")
	}
	v, err = d.replicationSQL(ctx, i.Standby.ID, "SELECT CASE WHEN pg_is_in_recovery() THEN 't' ELSE 'f' END||'|'||left(pg_walfile_name(pg_current_wal_lsn()),8)||'|'||current_setting('synchronous_standby_names');")
	m.PromotionObservation = v
	if err != nil || v != "f|00000002|" {
		return errors.New("promotion recovery exit, timeline or effective write configuration unverified")
	}
	m.Destination, err = d.databaseIdentity(ctx, i.Standby)
	if err != nil || m.Destination != i.Standby.DB {
		return errors.New("promoted database system or original boot changed")
	}
	history, err := pitrExec(ctx, d, i.Standby.ID, "cat", "/var/lib/postgresql/18/docker/pg_wal/00000002.history")
	if err != nil {
		return err
	}
	m.TimelineHistory = string(history)
	fields := strings.Fields(strings.TrimSpace(string(history)))
	if len(fields) < 3 || fields[0] != "1" {
		return errors.New("promoted timeline ancestry invalid")
	}
	branch, err := pitrLSN(fields[1])
	if err != nil || branch < want {
		return errors.New("promoted timeline does not cover acknowledged WAL")
	}
	m.PromotionObserved = true
	return j.append("PROMOTION_INDEPENDENTLY_OBSERVED", map[string]any{"database": m.Destination, "timeline": m.PromotionObservation, "history": m.TimelineHistory})
}

func replicationJournalHealthy(p ReplicationPlan, j *journal) error {
	b, err := readBounded(filepath.Join(p.Inventory.Directory, "replication-journal.jsonl"))
	if err != nil || j.poisoned || verifyJournal(b, p.Digest, ReplicationVersion) != nil {
		j.poisoned = true
		return errors.New("durable failover intent journal unavailable or corrupt; effect denied")
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	var last Event
	if json.Unmarshal([]byte(lines[len(lines)-1]), &last) != nil || last.Sequence != j.sequence || last.Hash != j.previous {
		j.poisoned = true
		return errors.New("failover intent does not match the original writer; effect denied")
	}
	return nil
}
