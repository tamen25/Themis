package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

func liveSetup(t *testing.T, scenario string) (string, Plan) {
	t.Helper()
	if os.Getenv("THEMIS_POSTGRES_DOCKER") != "1" {
		t.Skip("real PostgreSQL Docker opt-in not enabled")
	}
	endpoint, engine, root := os.Getenv("THEMIS_POSTGRES_ENDPOINT"), os.Getenv("THEMIS_POSTGRES_ENGINE"), os.Getenv("THEMIS_POSTGRES_TEST_STATE")
	if endpoint == "" || engine == "" || root == "" {
		t.Fatal("explicit local endpoint, expected engine and private test-state root required")
	}
	dir := filepath.Join(root, localstate.RandomID())
	i, e := Setup(context.Background(), dir, endpoint, engine)
	if e != nil {
		t.Fatalf("real setup failed; inspect private setup inventory %s: %v", dir, e)
	}
	t.Cleanup(func() {
		r, e := Reconcile(context.Background(), dir)
		if e != nil || !r.Complete {
			t.Errorf("owned test cleanup pending: %v %s", e, r.Reason)
		}
	})
	p, e := PlanFile(dir, Example(scenario))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Approve(dir, p.Digest); e != nil {
		t.Fatal(e)
	}
	t.Logf("real PostgreSQL 18.6 engine=%s source=%s restore=%s sourceSystem=%s restoreSystem=%s plan=%s", engine, i.Source.ID, i.Restore.ID, i.Source.DB.System, i.Restore.DB.System, p.Digest)
	return dir, p
}

func exportLive(t *testing.T, dir string, r Report) {
	t.Helper()
	b, _ := json.Marshal(r)
	t.Log(string(b))
	if root := os.Getenv("THEMIS_POSTGRES_EVIDENCE"); root != "" {
		out := filepath.Join(root, strings.ReplaceAll(t.Name(), "/", "-"))
		if e := os.MkdirAll(out, 0700); e != nil {
			t.Fatal(e)
		}
		for _, name := range []string{"report.json", "journal.jsonl"} {
			data, e := os.ReadFile(filepath.Join(dir, name))
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(out, name), data, 0600); e != nil {
				t.Fatal(e)
			}
		}
		// Public verification key and exact identities, never private inventory,
		// grants, credentials, backup, application files or signing keys.
		var p Plan
		if e := localstate.Read(filepath.Join(dir, "plan.json"), &p); e != nil {
			t.Fatal(e)
		}
		identity := map[string]any{"plan": p.Digest, "run": p.Inventory.Run, "engine": p.Inventory.Engine, "endpoint": p.Inventory.Endpoint, "source": p.Inventory.Source.ID, "restore": p.Inventory.Restore.ID, "sourceSystem": p.Inventory.Source.DB.System, "restoreSystem": p.Inventory.Restore.DB.System, "image": Image, "ledgerPublicKey": p.Inventory.LedgerKey}
		data, _ := json.MarshalIndent(identity, "", "  ")
		if e := os.WriteFile(filepath.Join(out, "identity.json"), data, 0600); e != nil {
			t.Fatal(e)
		}
	}
}

func TestRealPostgresScenarios(t *testing.T) {
	for _, tc := range []struct {
		scenario string
		verdict  result.Verdict
		code     int
	}{{"healthy", result.Pass, 0}, {"ack-loss", result.Fail, 3}, {"missing-receipt", result.Inconclusive, 4}, {"cleanup-denied", result.Inconclusive, 7}} {
		t.Run(tc.scenario, func(t *testing.T) {
			dir, p := liveSetup(t, tc.scenario)
			r, e := Run(context.Background(), dir)
			if e != nil {
				t.Fatal(e)
			}
			exportLive(t, dir, r)
			if r.Verdict != tc.verdict || ExitCode(r) != tc.code {
				t.Fatalf("expected %s/%d got %s/%d: %s", tc.verdict, tc.code, r.Verdict, ExitCode(r), r.Problem)
			}
			if r.Measurements.DumpExit == nil || *r.Measurements.DumpExit != 0 || r.Measurements.RestoreExit == nil || *r.Measurements.RestoreExit != 0 || !r.Measurements.ReadWriteReady {
				t.Fatal("no real backup/restore/readwrite proof")
			}
			if tc.scenario == "ack-loss" && (fmt.Sprint(r.Measurements.Missing) != "[17 18 19]" || r.Measurements.RecoveryPoint != 16 || !r.Measurements.DataLossExact) {
				t.Fatal("loss measurement incorrect")
			}
			if tc.scenario == "missing-receipt" && (r.Measurements.ReceiptCoverage || r.Measurements.DataLossExact) {
				t.Fatal("missing receipt manufactured coverage")
			}
			before, _ := os.ReadFile(filepath.Join(dir, "report.json"))
			journalBefore, _ := os.ReadFile(filepath.Join(dir, "journal.jsonl"))
			if VerifyJournal(journalBefore, p.Digest) != nil {
				t.Fatal("invalid durable journal")
			}
			for n := 0; n < 2; n++ {
				clean, e := Reconcile(context.Background(), dir)
				if e != nil || !clean.Complete {
					t.Fatalf("reconcile %d failed: %v %s", n, e, clean.Reason)
				}
			}
			after, _ := os.ReadFile(filepath.Join(dir, "report.json"))
			journalAfter, _ := os.ReadFile(filepath.Join(dir, "journal.jsonl"))
			if string(before) != string(after) || string(journalBefore) != string(journalAfter) {
				t.Fatal("reconciliation rewrote history")
			}
			replay, e := Replay(dir)
			if e != nil || replay.Verdict == result.Pass || replay.Live {
				t.Fatalf("offline PASS or invalid replay: %v", e)
			}
			if _, e = Run(context.Background(), dir); e == nil {
				t.Fatal("consumed invocation retried")
			}
		})
	}
}

func TestRealPostgresNegativeRecovery(t *testing.T) {
	for _, kind := range []string{"backup-digest", "backup-truncated", "nonempty-restore", "schema-missing", "table-missing", "corrupt-payload", "duplicate-rows", "forged-receipt", "lost-ack", "storage-exhausted"} {
		t.Run(kind, func(t *testing.T) {
			dir, p := liveSetup(t, "healthy")
			d := Docker{p.Inventory.Endpoint, p.Inventory.Engine}
			opts := runOptions{after: func(stage string, p Plan) error {
				switch {
				case kind == "backup-digest" && stage == "backup-published":
					f, e := os.OpenFile(filepath.Join(dir, "backup.dump"), os.O_WRONLY, 0)
					if e != nil {
						return e
					}
					defer f.Close()
					_, e = f.WriteAt([]byte("X"), 10)
					return e
				case kind == "backup-truncated" && stage == "backup-published":
					return os.Truncate(filepath.Join(dir, "backup.dump"), 8)
				case kind == "nonempty-restore" && stage == "backup-published":
					_, e := d.sql(context.Background(), p.Inventory.Restore.ID, "CREATE TABLE public.unexpected(id int);")
					return e
				case kind == "schema-missing" && stage == "restored":
					_, e := d.sql(context.Background(), p.Inventory.Restore.ID, "ALTER TABLE themis_app.transactions DROP CONSTRAINT transactions_payload_check;")
					return e
				case kind == "table-missing" && stage == "restored":
					_, e := d.sql(context.Background(), p.Inventory.Restore.ID, "DROP TABLE themis_app.transactions;")
					return e
				case kind == "corrupt-payload" && stage == "restored":
					_, e := d.sql(context.Background(), p.Inventory.Restore.ID, "UPDATE themis_app.transactions SET payload=repeat('0',64) WHERE id=4;")
					return e
				case kind == "duplicate-rows" && stage == "restored":
					if _, e := d.sql(context.Background(), p.Inventory.Restore.ID, "INSERT INTO themis_app.transactions SELECT * FROM themis_app.transactions WHERE id=4;"); e == nil {
						return errors.New("real primary key failed to reject duplicate")
					}
					_, e := d.sql(context.Background(), p.Inventory.Restore.ID, "ALTER TABLE themis_app.transactions DROP CONSTRAINT transactions_pkey; INSERT INTO themis_app.transactions SELECT * FROM themis_app.transactions WHERE id=4;")
					return e
				case kind == "forged-receipt" && stage == "restored":
					var r Receipt
					path := filepath.Join(dir, "receipt-04.json")
					if e := localstate.Read(path, &r); e != nil {
						return e
					}
					r.Payload = payload(99)
					b, _ := json.Marshal(r)
					return os.WriteFile(path, b, 0600)
				case kind == "storage-exhausted" && stage == "before-backup":
					_, e := d.output(context.Background(), nil, "exec", "--user", "999:999", p.Inventory.Source.ID, "dd", "if=/dev/zero", "of=/var/lib/postgresql/budget-test", "bs=1048576", "count=129")
					if e == nil {
						return errors.New("expected enforced tmpfs exhaustion")
					}
					t.Log("actual bounded tmpfs write rejected")
					return errors.New("storage budget exhausted; no backup attempted")
				}
				return nil
			}}
			if kind == "lost-ack" {
				opts.acknowledgement = func(id int, v string, e error) (string, error) {
					if id == 8 && e == nil {
						actual, err := d.sql(context.Background(), p.Inventory.Source.ID, "SELECT count(*) FROM themis_app.transactions WHERE id=8;")
						if err != nil || actual != "1" {
							t.Error("lost-ack test lacked actual committed transaction")
						}
						return "", errors.New("actual COMMIT acknowledgement deliberately withheld")
					}
					return v, e
				}
			}
			r, e := run(context.Background(), dir, opts)
			if e != nil {
				t.Fatal(e)
			}
			exportLive(t, dir, r)
			want := result.Inconclusive
			if kind == "schema-missing" || kind == "table-missing" || kind == "corrupt-payload" || kind == "duplicate-rows" {
				want = result.Fail
			}
			if r.Verdict != want || !r.Cleanup.Complete {
				t.Fatalf("expected %s and cleanup, got %s: %s / %s", want, r.Verdict, r.Problem, r.Cleanup.Reason)
			}
			if (kind == "backup-digest" || kind == "backup-truncated" || kind == "nonempty-restore") && r.Measurements.RestoreExit != nil {
				t.Fatal("invalid restore was attempted")
			}
		})
	}
}

type pacedReader struct {
	ctx context.Context
	r   io.Reader
}

func (p pacedReader) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	select {
	case <-p.ctx.Done():
		return 0, p.ctx.Err()
	case <-time.After(50 * time.Millisecond):
	}
	return p.r.Read(b[:1])
}

func holdBackupLock(ctx context.Context, d Docker, p Plan) error {
	go func() {
		_, _ = d.sql(ctx, p.Inventory.Source.ID, "SET statement_timeout='10s'; BEGIN; LOCK TABLE themis_app.transactions IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(8); COMMIT;")
	}()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		v, e := d.sql(ctx, p.Inventory.Source.ID, `SELECT count(*) FROM pg_locks WHERE relation='themis_app.transactions'::regclass AND mode='AccessExclusiveLock' AND granted;`)
		if e == nil && v == "1" {
			return nil
		}
		time.Sleep(30 * time.Millisecond)
	}
	return errors.New("real backup lock not observed")
}
func waitTool(ctx context.Context, d Docker, id, tool string) error {
	for {
		b, e := d.output(ctx, nil, "top", id, "-eo", "pid,args")
		// Version probes use the same executable. Only the actual authenticated
		// operation starts with -w; observing --version proves no recovery work.
		if e == nil && strings.Contains(string(b), tool+" -w ") {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("actual PostgreSQL tool process was not observed")
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func TestRealPostgresInterruptedTools(t *testing.T) {
	for _, phase := range []string{"backup", "restore"} {
		t.Run(phase, func(t *testing.T) {
			dir, p := liveSetup(t, "healthy")
			d := Docker{p.Inventory.Endpoint, p.Inventory.Engine}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			opts := runOptions{restoreInput: func(r io.Reader) io.Reader {
				if phase == "restore" {
					return pacedReader{ctx, r}
				}
				return r
			}}
			opts.after = func(stage string, p Plan) error {
				if phase == "backup" && stage == "before-backup" {
					return holdBackupLock(ctx, d, p)
				}
				if (phase == "backup" && stage == "before-backup") || (phase == "restore" && stage == "before-restore") {
					return nil
				}
				return nil
			}
			tool, id := "pg_dump", p.Inventory.Source.ID
			if phase == "restore" {
				tool, id = "pg_restore", p.Inventory.Restore.ID
			}
			observed := make(chan error, 1)
			go func() {
				deadline, c := context.WithTimeout(context.Background(), 25*time.Second)
				defer c()
				e := waitTool(deadline, d, id, tool)
				observed <- e
				if e == nil {
					cancel()
				}
			}()
			r, e := run(ctx, dir, opts)
			if e != nil {
				t.Fatal(e)
			}
			if e = <-observed; e != nil {
				t.Fatal(e)
			}
			exportLive(t, dir, r)
			if r.Verdict != result.Inconclusive || r.Execution != result.Cancelled || !r.Cleanup.Complete {
				t.Fatalf("interrupted actual tool produced %s/%s: %s", r.Verdict, r.Execution, r.Problem)
			}
			if phase == "backup" && (r.Measurements.DumpExit == nil || *r.Measurements.DumpExit == 0) {
				t.Fatal("actual backup tool interruption not recorded")
			}
			if phase == "restore" && (r.Measurements.RestoreExit == nil || *r.Measurements.RestoreExit == 0 || r.Measurements.DumpExit == nil || *r.Measurements.DumpExit != 0) {
				t.Fatal("actual restore tool interruption not recorded after successful backup")
			}
		})
	}
}

// This helper runs in an actual separate OS process. It is not a CLI feature.
func TestPostgresDeathHelper(t *testing.T) {
	dir := os.Getenv("THEMIS_POSTGRES_DEATH_DIR")
	if dir == "" {
		t.Skip("subprocess helper")
	}
	i, e := loadInventory(dir)
	if e != nil {
		t.Fatal(e)
	}
	d := Docker{i.Endpoint, i.Engine}
	ctx := context.Background()
	phase := os.Getenv("THEMIS_POSTGRES_DEATH_PHASE")
	opts := runOptions{after: func(stage string, p Plan) error {
		if phase == "backup" && stage == "before-backup" {
			return holdBackupLock(ctx, d, p)
		}
		return nil
	}, restoreInput: func(r io.Reader) io.Reader {
		if phase == "restore" {
			return pacedReader{ctx, r}
		}
		return r
	}}
	_, e = run(ctx, dir, opts)
	if e != nil {
		t.Fatal(e)
	}
	t.Fatal("parent failed to kill helper during actual operation")
}

func TestRealPostgresRunnerDeath(t *testing.T) {
	for _, phase := range []string{"backup", "restore"} {
		t.Run(phase, func(t *testing.T) {
			dir, p := liveSetup(t, "healthy")
			d := Docker{p.Inventory.Endpoint, p.Inventory.Engine}
			exe, e := os.Executable()
			if e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command(exe, "-test.run=^TestPostgresDeathHelper$", "-test.v")
			cmd.Env = append(os.Environ(), "THEMIS_POSTGRES_DEATH_DIR="+dir, "THEMIS_POSTGRES_DEATH_PHASE="+phase)
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			defer func() {
				if cmd.ProcessState == nil {
					cmd.Process.Kill()
					cmd.Wait()
				}
			}()
			tool, id := "pg_dump", p.Inventory.Source.ID
			if phase == "restore" {
				tool, id = "pg_restore", p.Inventory.Restore.ID
			}
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			if e = waitTool(ctx, d, id, tool); e != nil {
				t.Fatal(e)
			}
			if _, e = Reconcile(context.Background(), dir); e == nil {
				t.Fatal("live runner lock bypassed")
			}
			if e = cmd.Process.Kill(); e != nil {
				t.Fatal(e)
			}
			e = cmd.Wait()
			t.Logf("actual helper killed during %s, process exit=%v", tool, e)
			if _, e = os.Stat(filepath.Join(dir, "report.json")); !os.IsNotExist(e) {
				t.Fatal("death invented completed report")
			}
			before, _ := os.ReadFile(filepath.Join(dir, "journal.jsonl"))
			if e = VerifyJournal(before, p.Digest); e != nil {
				t.Fatal(e)
			}
			for n := 0; n < 2; n++ {
				r, e := Reconcile(context.Background(), dir)
				if e != nil || !r.Complete {
					t.Fatalf("death reconciliation failed: %v %s", e, r.Reason)
				}
			}
			after, _ := os.ReadFile(filepath.Join(dir, "journal.jsonl"))
			if string(before) != string(after) {
				t.Fatal("death recovery rewrote history")
			}
			if _, e = Run(context.Background(), dir); e == nil {
				t.Fatal("ambiguous operation resumed")
			}
			t.Log("exact-ID cleanup after real runner death complete; no operation resumed; historical journal unchanged")
		})
	}
}

func TestRealPostgresAdmission(t *testing.T) {
	dir, p := liveSetup(t, "healthy")
	i := p.Inventory
	d := Docker{i.Endpoint, i.Engine}
	ctx := context.Background()
	for _, tc := range []string{"wrong-engine", "wrong-id", "wrong-label", "replaced-source", "wrong-database", "unowned-restore", "outside-cleanup"} {
		t.Run(tc, func(t *testing.T) {
			b, _ := json.Marshal(i)
			var candidate Inventory
			json.Unmarshal(b, &candidate)
			var e error
			switch tc {
			case "wrong-engine":
				e = (Docker{i.Endpoint, "wrong-engine-000000"}).target(ctx, candidate, candidate.Source)
			case "wrong-id":
				candidate.Source.ID = strings.Repeat("f", 64)
				e = d.target(ctx, candidate, candidate.Source)
			case "wrong-label":
				candidate.Run = strings.Repeat("0", 64)
				e = d.target(ctx, candidate, candidate.Source)
			case "replaced-source":
				candidate.Source.DB.Boot = "replacement-boot"
				e = d.target(ctx, candidate, candidate.Source)
			case "wrong-database":
				candidate.Source.DB.Database = "other_database"
				e = d.target(ctx, candidate, candidate.Source)
			case "unowned-restore":
				candidate.Restore.ID = candidate.Source.ID
				e = d.target(ctx, candidate, candidate.Restore)
			case "outside-cleanup":
				candidate.Source.ID = candidate.Restore.ID
				receipt := cleanup(ctx, candidate, false)
				if receipt.Complete || len(receipt.Actions) != 0 {
					t.Fatal("out-of-scope cleanup acted")
				}
				e = errors.New(receipt.Reason)
			}
			if e == nil {
				t.Fatal("mismatched database authority admitted")
			}
			t.Log("real denial:", tc, e)
		})
	}
	path := filepath.Join(dir, "authorization.json")
	if e := os.Rename(path, path+".withheld"); e != nil {
		t.Fatal(e)
	}
	if _, e := Run(ctx, dir); e == nil {
		t.Fatal("missing authority admitted")
	}
	if e := os.Rename(path+".withheld", path); e != nil {
		t.Fatal(e)
	}
	for _, r := range []Resource{i.Source, i.Restore} {
		v, e := d.sql(ctx, r.ID, emptySQL)
		if e != nil || v != "0" {
			t.Fatal("denied operations changed owned database")
		}
	}
	// A corrupt execution journal is not cleanup authority and must not prevent
	// safe exact-ID reconciliation of the original protected setup inventory.
	if e := localstate.WriteNew(filepath.Join(dir, "journal.jsonl"), map[string]string{"corrupt": "not an execution journal"}); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "journal.jsonl"))
	clean, e := Reconcile(ctx, dir)
	if e != nil || !clean.Complete {
		t.Fatalf("cleanup with corrupt journal failed: %v", e)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "journal.jsonl"))
	if string(before) != string(after) {
		t.Fatal("corrupt history repaired or rewritten")
	}
}

func TestRealPostgresToolTimeout(t *testing.T) {
	dir, p := liveSetup(t, "healthy")
	d := Docker{p.Inventory.Endpoint, p.Inventory.Engine}
	r, e := run(context.Background(), dir, runOptions{after: func(stage string, p Plan) error {
		if stage == "before-backup" {
			return holdBackupLock(context.Background(), d, p)
		}
		return nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	exportLive(t, dir, r)
	if r.Verdict != result.Inconclusive || r.Measurements.DumpExit == nil || *r.Measurements.DumpExit == 0 || !r.Cleanup.Complete {
		t.Fatalf("actual pg_dump lock timeout mishandled: %s %s", r.Verdict, r.Problem)
	}
	t.Log("actual pg_dump lock-wait-timeout caused nonzero exit; not a measured correctness FAIL")
}
