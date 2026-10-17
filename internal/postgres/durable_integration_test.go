package postgres

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

func durableLiveSetup(t *testing.T, scenario string) (string, DurablePlan) {
	return durableLiveSetupContract(t, DurableExample(scenario))
}
func durableLiveSetupContract(t *testing.T, contract DurableContract) (string, DurablePlan) {
	t.Helper()
	if os.Getenv("THEMIS_POSTGRES_DOCKER") != "1" {
		t.Skip("real owned PostgreSQL Docker opt-in not enabled")
	}
	endpoint, engine, root := os.Getenv("THEMIS_POSTGRES_ENDPOINT"), os.Getenv("THEMIS_POSTGRES_ENGINE"), os.Getenv("THEMIS_POSTGRES_TEST_STATE")
	if endpoint == "" || engine == "" || root == "" {
		t.Fatal("explicit original local Docker and private test-state root required")
	}
	dir := filepath.Join(root, localstate.RandomID())
	i, e := SetupDurable(context.Background(), dir, endpoint, engine)
	if e != nil {
		t.Fatalf("durable setup %s: %v", dir, e)
	}
	t.Cleanup(func() {
		r, e := ReconcileDurable(context.Background(), dir)
		if e != nil || !r.Complete {
			t.Errorf("durable cleanup pending %s: %v %s", dir, e, r.Reason)
		}
	})
	p, e := PlanDurableFile(dir, contract)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ApprovePreparation(dir, p.Digest); e != nil {
		t.Fatal(e)
	}
	t.Logf("real persistent source=%s restore=%s plan=%s sourceSystem=%s restoreSystem=%s", i.Source.ID, i.Restore.ID, p.Digest, i.Source.DB.System, i.Restore.DB.System)
	return dir, p
}
func durableLivePrepare(t *testing.T, scenario string) (string, DurablePlan) {
	t.Helper()
	dir, p := durableLiveSetup(t, scenario)
	s, e := PrepareDurable(context.Background(), dir)
	if e != nil {
		t.Fatalf("prepare %s: %v", dir, e)
	}
	if _, e = ApproveFailure(dir, p.Digest, s.BackupSHA256); e != nil {
		t.Fatal(e)
	}
	return dir, p
}
func exportDurable(t *testing.T, dir string, r DurableReport) {
	t.Helper()
	b, _ := json.Marshal(r)
	t.Log(string(b))
	root := os.Getenv("THEMIS_POSTGRES_EVIDENCE")
	if root == "" {
		return
	}
	out := filepath.Join(root, strings.ReplaceAll(t.Name(), "/", "-"))
	if e := os.MkdirAll(out, 0700); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"durable-report.json", "durable-journal.jsonl", "durable-prepare.jsonl", "durable-backup-receipt.json", "durable-prepared.json"} {
		data, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(out, name), data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	var p DurablePlan
	if e := localstate.Read(filepath.Join(dir, "durable-plan.json"), &p); e != nil {
		t.Fatal(e)
	}
	i := p.Inventory
	identity := map[string]any{"version": DurableVersion, "plan": p.Digest, "run": i.Run, "engine": i.Engine, "endpoint": i.Endpoint, "image": Image, "source": i.Source.ID, "restore": i.Restore.ID, "sourceSystem": i.Source.DB.System, "restoreSystem": i.Restore.DB.System, "sourceVolume": i.Source.Volume, "restoreVolume": i.Restore.Volume, "ledgerPublicKey": i.LedgerKey}
	b, _ = json.MarshalIndent(identity, "", "  ")
	if e := os.WriteFile(filepath.Join(out, "identity.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
}
func TestRealDurableScenarios(t *testing.T) {
	for _, tc := range []struct {
		scenario string
		verdict  result.Verdict
		code     int
	}{{"healthy", result.Pass, 0}, {"ack-loss", result.Fail, 3}, {"missing-receipt", result.Inconclusive, 4}, {"cleanup-denied", result.Inconclusive, 7}, {"inflight-crash", result.Inconclusive, 4}} {
		t.Run(tc.scenario, func(t *testing.T) {
			dir, p := durableLivePrepare(t, tc.scenario)
			r, e := RunDurable(context.Background(), dir)
			if e != nil {
				t.Fatal(e)
			}
			exportDurable(t, dir, r)
			if r.Verdict != tc.verdict || DurableExitCode(r) != tc.code {
				t.Fatalf("expected %s/%d got %s/%d problem=%s", tc.verdict, tc.code, r.Verdict, DurableExitCode(r), r.Problem)
			}
			m := r.Measurements
			if !m.FailureObserved || !m.SourceVolumePersisted || !m.BackupVerified || !m.ReadWriteReady || m.RestoreExit == nil || *m.RestoreExit != 0 || !validTimeline(m.Timeline) {
				t.Fatal("missing actual durable failure/recovery measurements")
			}
			if tc.scenario == "ack-loss" && (!m.DataLossExact || len(m.Missing) != 3 || m.Missing[0] != 17 || m.RecoveryPoint != 16) {
				t.Fatal("incorrect acknowledged loss")
			}
			if tc.scenario == "inflight-crash" {
				if len(m.Uncertain) != 1 || m.Uncertain[0] != 17 {
					t.Fatal("in-flight outcome not uncertain")
				}
				if _, e = os.Stat(filepath.Join(dir, "durable-receipt-17.json")); !os.IsNotExist(e) {
					t.Fatal("fabricated in-flight receipt")
				}
			}
			before, _ := os.ReadFile(filepath.Join(dir, "durable-report.json"))
			jb, _ := os.ReadFile(filepath.Join(dir, "durable-journal.jsonl"))
			if e = VerifyDurableJournal(jb, p.Digest); e != nil {
				t.Fatal(e)
			}
			for n := 0; n < 2; n++ {
				c, e := ReconcileDurable(context.Background(), dir)
				if e != nil || !c.Complete {
					t.Fatalf("reconcile %v %s", e, c.Reason)
				}
			}
			after, _ := os.ReadFile(filepath.Join(dir, "durable-report.json"))
			ja, _ := os.ReadFile(filepath.Join(dir, "durable-journal.jsonl"))
			if string(before) != string(after) || string(jb) != string(ja) {
				t.Fatal("cleanup rewrote history")
			}
			f, b, e := openDurableBackup(p)
			if e != nil {
				t.Fatalf("host backup unavailable after original container/volumes removed: %v", e)
			}
			f.Close()
			if b.SHA256 != m.Backup.SHA256 {
				t.Fatal("published backup changed")
			}
			replay, e := ReplayDurable(dir)
			if e != nil || replay.Live || replay.Verdict == result.Pass {
				t.Fatalf("unsafe replay %v", e)
			}
			if _, e = RunDurable(context.Background(), dir); e == nil {
				t.Fatal("failure invocation repeated")
			}
		})
	}
}
