package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

func replicationLiveSetup(t *testing.T, scenario string) (string, ReplicationPlan) {
	t.Helper()
	if os.Getenv("THEMIS_POSTGRES_DOCKER") != "1" {
		t.Skip("real owned PostgreSQL Docker opt-in not enabled")
	}
	endpoint, engine, root := os.Getenv("THEMIS_POSTGRES_ENDPOINT"), os.Getenv("THEMIS_POSTGRES_ENGINE"), os.Getenv("THEMIS_POSTGRES_TEST_STATE")
	if endpoint == "" || engine == "" || root == "" {
		t.Fatal("explicit local endpoint, original engine and private test root required")
	}
	dir := filepath.Join(root, localstate.RandomID())
	i, err := SetupReplication(context.Background(), dir, endpoint, engine)
	if err != nil {
		t.Fatalf("replication setup %s: %v; partial acknowledged inventory retained for review", dir, err)
	}
	t.Cleanup(func() {
		r, e := ReconcileReplication(context.Background(), dir)
		if e != nil || !r.Complete {
			t.Errorf("cleanup %s: %v %s", dir, e, r.Reason)
		}
	})
	p, err := PlanReplicationFile(dir, ReplicationExample(scenario))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ApproveReplication(dir, p.Digest, "prepare"); err != nil {
		t.Fatal(err)
	}
	t.Logf("original primary=%s standby=%s system=%s primaryBoot=%s standbyBoot=%s state=%s", i.Primary.ID, i.Standby.ID, i.Primary.DB.System, i.Primary.DB.Boot, i.Standby.DB.Boot, dir)
	return dir, p
}
func replicationLivePrepared(t *testing.T, scenario string) (string, ReplicationPlan, ReplicationPrepared) {
	t.Helper()
	dir, p := replicationLiveSetup(t, scenario)
	s, err := PrepareReplication(context.Background(), dir)
	if err != nil {
		t.Fatalf("replication prepare: %v", err)
	}
	for _, scope := range []string{"terminate-and-fence", "promote-fenced-standby"} {
		if _, err = ApproveReplication(dir, s.Digest, scope); err != nil {
			t.Fatal(err)
		}
	}
	return dir, p, s
}
func exportReplication(t *testing.T, dir string, p ReplicationPlan, r ReplicationReport) {
	t.Helper()
	b, _ := json.Marshal(r)
	t.Log(string(b))
	root := os.Getenv("THEMIS_POSTGRES_EVIDENCE")
	if root == "" {
		return
	}
	out := filepath.Join(root, strings.ReplaceAll(t.Name(), "/", "-"))
	if err := os.MkdirAll(out, 0700); err != nil {
		t.Fatal(err)
	}
	names := []string{"replication-prepared.json", "replication-report.json", "replication-prepare.jsonl", "replication-journal.jsonl", "replication-cleanup-initial.json", "replication-tool-versions-primary.json", "replication-tool-versions-standby.json", "replication-primary.postgres.log", "replication-standby.postgres.log"}
	for id := 1; id <= replicationCommits; id++ {
		names = append(names, fmt.Sprintf("replication-receipt-%02d.json", id))
	}
	for _, name := range names {
		b, e := os.ReadFile(filepath.Join(dir, name))
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(out, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	i := p.Inventory
	identity := map[string]any{"version": ReplicationVersion, "plan": p.Digest, "run": i.Run, "engine": i.Engine, "image": i.Image, "primary": i.Primary.ID, "standby": i.Standby.ID, "primarySystem": i.Primary.DB.System, "standbySystem": i.Standby.DB.System, "primaryBoot": i.Primary.DB.Boot, "standbyBoot": i.Standby.DB.Boot, "ledgerPublicKey": i.LedgerKey}
	b, _ = json.MarshalIndent(identity, "", "  ")
	if err := os.WriteFile(filepath.Join(out, "identity.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestRealReplicationScenarios(t *testing.T) {
	for _, tc := range []struct {
		scenario string
		verdict  result.Verdict
		code     int
	}{{"healthy", result.Pass, 0}, {"time-violation", result.Fail, 3}, {"missing-receipt", result.Inconclusive, 4}, {"cleanup-denied", result.Inconclusive, 7}} {
		t.Run(tc.scenario, func(t *testing.T) {
			dir, p, _ := replicationLivePrepared(t, tc.scenario)
			r, err := RunReplication(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			exportReplication(t, dir, p, r)
			if r.Verdict != tc.verdict || ReplicationExitCode(r) != tc.code {
				t.Fatalf("verdict=%s exit=%d problem=%s", r.Verdict, ReplicationExitCode(r), r.Problem)
			}
			m := r.Measurements
			if !m.FailureObserved || !m.Fenced {
				t.Fatal("real independently observed termination/fencing required")
			}
			if tc.scenario != "missing-receipt" && (!m.PromotionObserved || !m.ReadWriteReady || !m.PrimaryAbsentAfterReady || !m.ReceiptCoverage || m.RecoveryPoint != 20 || len(m.Missing) != 0) {
				t.Fatal("real promotion, write readiness and exact loss observations required")
			}
			if tc.scenario == "missing-receipt" && m.PromotionObserved {
				t.Fatal("promotion occurred despite missing independent COMMIT coverage")
			}
			before, err := os.ReadFile(filepath.Join(dir, "replication-report.json"))
			if err != nil {
				t.Fatal(err)
			}
			for n := 0; n < 2; n++ {
				c, e := ReconcileReplication(context.Background(), dir)
				if e != nil || !c.Complete {
					t.Fatalf("reconcile: %v %s", e, c.Reason)
				}
			}
			after, _ := os.ReadFile(filepath.Join(dir, "replication-report.json"))
			if string(before) != string(after) {
				t.Fatal("reconciliation changed historical outcome")
			}
			replay, err := ReplayReplication(dir)
			if err != nil || replay.Live || replay.Verdict != result.Inconclusive {
				t.Fatal("offline report gained execution trust")
			}
			if _, err = RunReplication(context.Background(), dir); err == nil {
				t.Fatal("duplicate failover invocation accepted")
			}
		})
	}
}
