package postgres

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

func pitrLiveSetup(t *testing.T, scenario string) (string, PITRPlan) {
	t.Helper()
	if os.Getenv("THEMIS_POSTGRES_DOCKER") != "1" {
		t.Skip("real owned PostgreSQL Docker opt-in not enabled")
	}
	endpoint, engine, root := os.Getenv("THEMIS_POSTGRES_ENDPOINT"), os.Getenv("THEMIS_POSTGRES_ENGINE"), os.Getenv("THEMIS_POSTGRES_TEST_STATE")
	if endpoint == "" || engine == "" || root == "" {
		t.Fatal("explicit engine, endpoint and private state root required")
	}
	dir := filepath.Join(root, localstate.RandomID())
	i, err := SetupPITR(context.Background(), dir, endpoint, engine)
	if err != nil {
		t.Fatalf("setup %s: %v", dir, err)
	}
	t.Cleanup(func() {
		pitrExportLogs(t, i)
		r, err := ReconcilePITR(context.Background(), dir)
		if err != nil || !r.Complete {
			t.Errorf("PITR cleanup %s: %v %s", dir, err, r.Reason)
		}
	})
	p, err := PlanPITRFile(dir, PITRExample(scenario))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ApprovePITR(dir, p.Digest, "prepare"); err != nil {
		t.Fatal(err)
	}
	t.Logf("owned source=%s restore=%s archive=%s state=%s", i.Source.ID, i.Restore.ID, i.Archive.ID, dir)
	return dir, p
}
func pitrExportLogs(t *testing.T, i PITRInventory) {
	t.Helper()
	root := os.Getenv("THEMIS_POSTGRES_EVIDENCE")
	if root == "" {
		return
	}
	out := filepath.Join(root, strings.ReplaceAll(t.Name(), "/", "-"))
	if err := os.MkdirAll(out, 0700); err != nil {
		t.Fatal(err)
	}
	k, err := pitrLoadKeys(i)
	if err != nil {
		t.Error(err)
		return
	}
	d := Docker{i.Endpoint, i.Engine}
	for _, r := range []Resource{i.Source, i.Restore} {
		var b bytes.Buffer
		if err := d.command(context.Background(), nil, &b, 128<<10, "cp", r.ID+":/var/lib/postgresql/themis-logs/server.log", "-"); err != nil {
			continue
		}
		tr := tar.NewReader(&b)
		h, err := tr.Next()
		if err != nil || h.Name != "server.log" || h.Typeflag != tar.TypeReg || h.Size > 65536 {
			t.Error("bounded PostgreSQL log unavailable")
			continue
		}
		log, err := io.ReadAll(tr)
		if err != nil {
			t.Error(err)
			continue
		}
		log = []byte(strings.ReplaceAll(string(log), k.Password, "[REDACTED]"))
		if err = os.WriteFile(filepath.Join(out, r.Role+".postgres.log"), log, 0600); err != nil {
			t.Error(err)
		}
	}
}
func TestRealPITRPreparation(t *testing.T) {
	dir, p := pitrLiveSetup(t, "healthy")
	s, err := PreparePITR(context.Background(), dir)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err = verifyPITRCapsule(p, s); err != nil {
		t.Fatal(err)
	}
	t.Logf("base=%s bytes=%d backupEnd=%s target=%s targetLSN=%s WAL=%d executionPlan=%s", s.Base.SHA256, s.Base.Bytes, s.EndLSN, s.TargetName, s.TargetLSN, len(s.WAL), s.Digest)
}
func exportPITR(t *testing.T, dir string, p PITRPlan, r PITRReport) {
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
	names := []string{"pitr-prepared.json", "pitr-report.json", "pitr-prepare.jsonl", "pitr-journal.jsonl", "pitr-cleanup-initial.json", "pitr-source.postgres.log", "pitr-restore.postgres.log", "pitr-tool-versions-source.json", "pitr-tool-versions-restore.json", "pitr-tool-versions-archive.json"}
	for id := 1; id <= r.Measurements.Prepared.Receipts; id++ {
		names = append(names, fmt.Sprintf("pitr-receipt-%02d.json", id))
	}
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(out, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(pitrCapsule(p.Inventory, "backup_manifest"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(out, "backup_manifest"), data, 0600); err != nil {
		t.Fatal(err)
	}
	i := p.Inventory
	identity := map[string]any{"version": PITRVersion, "plan": p.Digest, "executionPlan": r.ExecutionPlan, "run": i.Run, "engine": i.Engine, "endpoint": i.Endpoint, "image": Image, "source": i.Source.ID, "restore": i.Restore.ID, "archive": i.Archive.ID, "sourceSystem": i.Source.DB.System, "destinationSystem": r.Measurements.Destination.System, "ledgerPublicKey": i.LedgerKey, "volumes": []Volume{i.Source.Volume, i.Restore.Volume, i.Archive.Volume}}
	data, _ = json.MarshalIndent(identity, "", "  ")
	if err = os.WriteFile(filepath.Join(out, "identity.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestRealPITRScenarios(t *testing.T) {
	for _, tc := range []struct {
		scenario string
		verdict  result.Verdict
		clean    bool
	}{{"healthy", result.Pass, true}, {"ack-loss", result.Fail, true}, {"missing-wal", result.Inconclusive, true}, {"cleanup-denied", result.Inconclusive, false}, {"inflight-crash", result.Inconclusive, true}} {
		t.Run(tc.scenario, func(t *testing.T) {
			dir, p := pitrLiveSetup(t, tc.scenario)
			s, err := PreparePITR(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = ApprovePITR(dir, s.Digest, "sigkill-physical-target-once"); err != nil {
				t.Fatal(err)
			}
			r, err := RunPITR(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			exportPITR(t, dir, p, r)
			if r.Verdict != tc.verdict || r.Cleanup.Complete != tc.clean {
				t.Fatalf("verdict=%s clean=%t problem=%s", r.Verdict, r.Cleanup.Complete, r.Problem)
			}
			if tc.scenario != "missing-wal" && (!r.Measurements.TargetObserved || !r.Measurements.TargetFidelity || !r.Measurements.Promoted || !r.Measurements.ReadWriteReady) {
				t.Fatalf("physical recovery not independently verified: %s", r.Problem)
			}
			if tc.scenario == "ack-loss" && !slices.Equal(r.Measurements.Missing, []int{21, 22, 23}) {
				t.Fatal("post-target acknowledged loss not reported exactly")
			}
			if tc.scenario == "inflight-crash" && (!slices.Equal(r.Measurements.Uncertain, []int{21}) || len(r.Measurements.Receipts) != 20) {
				t.Fatal("inflight uncertainty or receipt coverage incorrect")
			}
			before, err := os.ReadFile(filepath.Join(dir, "pitr-report.json"))
			if err != nil {
				t.Fatal(err)
			}
			journal, err := os.ReadFile(filepath.Join(dir, "pitr-journal.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			clean, err := ReconcilePITR(context.Background(), dir)
			if err != nil || !clean.Complete {
				t.Fatalf("independent reconcile %v %s", err, clean.Reason)
			}
			after, _ := os.ReadFile(filepath.Join(dir, "pitr-report.json"))
			afterJournal, _ := os.ReadFile(filepath.Join(dir, "pitr-journal.jsonl"))
			if !bytes.Equal(before, after) || !bytes.Equal(journal, afterJournal) {
				t.Fatal("reconcile rewrote history")
			}
			if root := os.Getenv("THEMIS_POSTGRES_EVIDENCE"); root != "" {
				b, _ := json.MarshalIndent(clean, "", "  ")
				if err = os.WriteFile(filepath.Join(root, strings.ReplaceAll(t.Name(), "/", "-"), "later-cleanup.json"), b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			offline, err := ReplayPITR(dir)
			if err != nil || offline.Live || offline.Verdict != result.Inconclusive {
				t.Fatal("offline replay gained execution trust")
			}
			if _, err = RunPITR(context.Background(), dir); err == nil {
				t.Fatal("duplicate execution allowed")
			}
		})
	}
}
