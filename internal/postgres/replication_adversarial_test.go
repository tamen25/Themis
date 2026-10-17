package postgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

func TestReplicationProcessHelper(t *testing.T) {
	dir, stage := os.Getenv("THEMIS_REPLICATION_HELPER_STATE"), os.Getenv("THEMIS_REPLICATION_HELPER_STAGE")
	if dir == "" {
		t.Skip("child helper only")
	}
	_, err := runReplication(context.Background(), dir, replicationOptions{after: func(s string, p ReplicationPlan) error {
		if s == stage {
			if err := localstate.WriteNew(filepath.Join(dir, "replication-helper-reached.json"), map[string]string{"stage": s}); err != nil {
				return err
			}
			select {}
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRealReplicationUnavailableAndPausedStandby(t *testing.T) {
	for _, mode := range []string{"disconnected", "replay-paused"} {
		t.Run(mode, func(t *testing.T) {
			dir, p, _ := replicationLivePrepared(t, "healthy")
			i := p.Inventory
			d := Docker{i.Endpoint, i.Engine}
			ctx := context.Background()
			if mode == "disconnected" {
				if _, err := d.output(ctx, nil, "container", "stop", "--time", "2", i.Standby.ID); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := d.sql(ctx, i.Standby.ID, "SELECT pg_wal_replay_pause();"); err != nil {
					t.Fatal(err)
				}
				for {
					v, e := d.sql(ctx, i.Standby.ID, "SELECT pg_get_wal_replay_pause_state();")
					if e == nil && v == "paused" {
						break
					}
					if e = replicationWait(ctx); e != nil {
						t.Fatal(e)
					}
				}
			}
			r, err := RunReplication(ctx, dir)
			if err != nil {
				t.Fatal(err)
			}
			exportReplication(t, dir, p, r)
			if r.Verdict != result.Inconclusive || r.Measurements.FailureObserved || r.Measurements.PromotionAcknowledged || !r.Cleanup.Complete {
				t.Fatalf("unavailable/paused standby failed to block destructive admission: %s", r.Problem)
			}
			t.Log("actual standby disconnection or replay pause; primary termination and promotion withheld")
		})
	}
}

func TestRealReplicationCleanupAuthorityNegatives(t *testing.T) {
	dir, p := replicationLiveSetup(t, "healthy")
	i := p.Inventory
	ctx := context.Background()
	d := Docker{i.Endpoint, i.Engine}
	ownership := filepath.Join(dir, "replication-ownership.json")
	withheld := ownership + ".withheld"
	if err := os.Rename(ownership, withheld); err != nil {
		t.Fatal(err)
	}
	_, denied := ReconcileReplication(ctx, dir)
	if err := os.Rename(withheld, ownership); err != nil {
		t.Fatal(err)
	}
	if denied == nil {
		t.Fatal("missing cleanup inventory accepted")
	}
	capability := filepath.Join(dir, "replication-cleanup-capability.json")
	original, err := os.ReadFile(capability)
	if err != nil {
		t.Fatal(err)
	}
	var g replicationCleanupGrant
	if err = localstate.Unmarshal(original, &g); err != nil {
		t.Fatal(err)
	}
	k, err := loadReplicationKeys(i)
	if err != nil {
		t.Fatal(err)
	}
	g.NotAfter = time.Now().Add(-time.Minute)
	g.Signature = ed25519.Sign(k.Cleanup, replicationCleanupMessage(g))
	modified, _ := json.Marshal(g)
	if err = os.WriteFile(capability, modified, 0600); err != nil {
		t.Fatal(err)
	}
	r := replicationCleanup(ctx, i, false)
	if err = os.WriteFile(capability, original, 0600); err != nil {
		t.Fatal(err)
	}
	if r.Complete || len(r.Actions) != 0 {
		t.Fatal("expired/altered cleanup capability permitted deletion")
	}
	_, otherPlan := replicationLiveSetup(t, "healthy")
	unrelated := i
	unrelated.Primary = otherPlan.Inventory.Primary
	refused := replicationCleanup(ctx, unrelated, false)
	if refused.Complete || len(refused.Actions) != 0 {
		t.Fatal("changed original inventory adopted unrelated role/container")
	}
	for _, resource := range i.resources() {
		if err = d.replicationTarget(ctx, i, resource); err != nil {
			t.Fatal("cleanup negative deleted or altered a live original resource")
		}
	}
	otherDocker := Docker{otherPlan.Inventory.Endpoint, otherPlan.Inventory.Engine}
	for _, resource := range otherPlan.Inventory.resources() {
		if err = otherDocker.replicationTarget(ctx, otherPlan.Inventory, resource); err != nil {
			t.Fatal("cleanup negative modified an unrelated independently owned pair")
		}
	}
	t.Log("actual Docker originals preserved; missing original inventory and signed expired/altered capability are controlled private-state negatives; changed container authority denied before deletion")
}
func TestRealReplicationRunnerDeath(t *testing.T) {
	for _, stage := range []string{"PRIMARY_STOPPED", "PROMOTED"} {
		t.Run(stage, func(t *testing.T) {
			dir, p, _ := replicationLivePrepared(t, "healthy")
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(exe, "-test.run=^TestReplicationProcessHelper$", "-test.v")
			cmd.Env = append(os.Environ(), "THEMIS_REPLICATION_HELPER_STATE="+dir, "THEMIS_REPLICATION_HELPER_STAGE="+stage)
			var output bytes.Buffer
			cmd.Stdout = &output
			cmd.Stderr = &output
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if cmd.ProcessState == nil {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			})
			deadline := time.Now().Add(90 * time.Second)
			for {
				if _, err = os.Stat(filepath.Join(dir, "replication-helper-reached.json")); err == nil {
					break
				}
				if time.Now().After(deadline) {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
					t.Fatalf("actual stage not reached: %s", output.String())
				}
				time.Sleep(100 * time.Millisecond)
			}
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err = cmd.Wait(); err == nil {
				t.Fatal("actual runner process death not observed")
			}
			journalPath := filepath.Join(dir, "replication-journal.jsonl")
			before, err := os.ReadFile(journalPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = os.Stat(filepath.Join(dir, "replication-report.json")); !os.IsNotExist(err) {
				t.Fatal("dead runner published completed report")
			}
			d := Docker{p.Inventory.Endpoint, p.Inventory.Engine}
			v, err := d.sql(context.Background(), p.Inventory.Standby.ID, "SELECT pg_is_in_recovery();")
			if err != nil || (stage == "PRIMARY_STOPPED" && v != "t") || (stage == "PROMOTED" && v != "f") {
				t.Fatal("independent standby state after actual runner death differs")
			}
			if stage == "PROMOTED" {
				present, e := d.exists(context.Background(), "container", p.Inventory.Primary.ID)
				if e != nil || present {
					t.Fatal("promoted standby without primary absence")
				}
			}
			if _, err = RunReplication(context.Background(), dir); err == nil {
				t.Fatal("dead invocation resumed")
			}
			for n := 0; n < 2; n++ {
				c, e := ReconcileReplication(context.Background(), dir)
				if e != nil || !c.Complete {
					t.Fatalf("post-death cleanup: %v %s", e, c.Reason)
				}
			}
			after, _ := os.ReadFile(journalPath)
			if !bytes.Equal(before, after) {
				t.Fatal("post-death cleanup rewrote history")
			}
			exportReplication(t, dir, p, ReplicationReport{Version: ReplicationVersion, Run: p.Inventory.Run, Plan: p.Digest, Verdict: result.Inconclusive, Problem: "actual OS runner termination; no completed historical report"})
			t.Logf("actual runner killed at %s; child exit=%d; independent standby recovery=%s; original journal retained; repeated exact inventory cleanup completed", stage, cmd.ProcessState.ExitCode(), v)
		})
	}
}

func TestRealReplicationReadOnlyIdentityNegatives(t *testing.T) {
	dir, p := replicationLiveSetup(t, "healthy")
	i := p.Inventory
	ctx := context.Background()
	d := Docker{i.Endpoint, i.Engine}
	if _, err := d.replicationSQL(ctx, i.Primary.ID, "BEGIN; SELECT 1; COMMIT; DO $$ BEGIN RAISE WARNING 'synthetic acknowledgement warning'; END $$;"); err == nil {
		t.Fatal("SQL COMMIT with PostgreSQL warning accepted as clean acknowledgement")
	}
	for _, tc := range []struct {
		name  string
		alter func(*ReplicationInventory)
	}{{"wrong-primary-ID", func(i *ReplicationInventory) { i.Primary.ID = i.Standby.ID }}, {"wrong-standby-ID", func(i *ReplicationInventory) { i.Standby.ID = i.Primary.ID }}, {"wrong-system-ID", func(i *ReplicationInventory) { i.Standby.DB.System = "1" }}, {"changed-postmaster", func(i *ReplicationInventory) { i.Standby.DB.Boot = "other" }}, {"wrong-ownership", func(i *ReplicationInventory) { i.Run = strings.Repeat("f", 64) }}} {
		t.Run(tc.name, func(t *testing.T) {
			changed := i
			tc.alter(&changed)
			primaryError := d.replicationTarget(ctx, changed, changed.Primary)
			if err := d.replicationTarget(ctx, changed, changed.Standby); err == nil && primaryError == nil {
				t.Fatal("read-only live admission accepted changed identity")
			}
			if err := d.replicationTarget(ctx, i, i.Primary); err != nil {
				t.Fatal("negative test changed original primary")
			}
		})
	}
	_ = dir
}

func TestRealReplicationUncertainSynchronousCommit(t *testing.T) {
	dir, p := replicationLiveSetup(t, "healthy")
	if _, err := PrepareReplication(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	i := p.Inventory
	d := Docker{i.Endpoint, i.Engine}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := d.replicationSQL(ctx, i.Standby.ID, "SELECT pg_wal_replay_pause();"); err != nil {
		t.Fatal(err)
	}
	for {
		v, e := d.replicationSQL(ctx, i.Standby.ID, "SELECT pg_get_wal_replay_pause_state();")
		if e == nil && v == "paused" {
			break
		}
		if e = replicationWait(ctx); e != nil {
			t.Fatal(e)
		}
	}
	f, err := localstate.OpenNew(filepath.Join(dir, "replication-uncertain.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	j := journal{w: f, start: time.Now(), plan: p.Digest, version: ReplicationVersion}
	k, err := loadReplicationKeys(i)
	if err != nil {
		t.Fatal(err)
	}
	_, err = replicationCommit(ctx, d, p, k.Ledger, &j, localstate.RandomID(), "", 21, replicationOptions{})
	if err == nil {
		t.Fatal("paused remote_apply COMMIT unexpectedly produced trusted acknowledgement")
	}
	if _, err = os.Stat(filepath.Join(dir, "replication-receipt-21.json")); !os.IsNotExist(err) {
		t.Fatal("ambiguous real synchronous COMMIT published a receipt")
	}
	t.Log("actual WAL replay pause and bounded synchronous COMMIT interruption; no receipt for transaction 21, no termination or promotion attempted")
}
func TestRealReplicationAdversarialLifecycle(t *testing.T) {
	for _, mode := range []string{"ambiguous-termination", "primary-restarted", "standby-unavailable", "promotion-ack-lost", "journal-corrupt", "cancel-before-promotion", "cancel-during-cleanup", "ineffective-sync"} {
		t.Run(mode, func(t *testing.T) {
			dir, p, _ := replicationLivePrepared(t, "healthy")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			o := replicationOptions{}
			if mode == "ambiguous-termination" {
				o.termination = func(ctx context.Context, d Docker, id string) ([]byte, error) {
					_, err := d.output(ctx, nil, "container", "kill", "--signal", "KILL", id)
					if err != nil {
						return nil, err
					}
					return nil, errors.New("controlled loss of real Docker kill acknowledgement")
				}
			}
			if mode == "promotion-ack-lost" {
				o.promotion = func(ctx context.Context, d Docker, id string) (string, error) {
					_, err := d.sql(ctx, id, "SELECT pg_promote(true,10);")
					if err != nil {
						return "", err
					}
					return "", errors.New("controlled loss of real PostgreSQL promotion acknowledgement")
				}
			}
			o.after = func(stage string, p ReplicationPlan) error {
				d := Docker{p.Inventory.Endpoint, p.Inventory.Engine}
				i := p.Inventory
				if mode == "primary-restarted" && stage == "PRIMARY_STOPPED" {
					_, err := d.output(ctx, nil, "start", i.Primary.ID)
					return err
				}
				if mode == "standby-unavailable" && stage == "PRIMARY_FENCED" {
					_, err := d.output(ctx, nil, "container", "stop", "--time", "2", i.Standby.ID)
					return err
				}
				if mode == "journal-corrupt" && stage == "PRIMARY_FENCED" {
					f, err := os.OpenFile(filepath.Join(dir, "replication-journal.jsonl"), os.O_APPEND|os.O_WRONLY, 0600)
					if err != nil {
						return err
					}
					defer f.Close()
					if _, err = f.WriteString("torn"); err != nil {
						return err
					}
					return f.Sync()
				}
				if (mode == "cancel-before-promotion" && stage == "PRIMARY_FENCED") || (mode == "cancel-during-cleanup" && stage == "CLEANUP_STARTING") {
					cancel()
				}
				if mode == "ineffective-sync" && stage == "FAILURE_INTENT" {
					_, err := d.sql(ctx, i.Primary.ID, "ALTER SYSTEM SET synchronous_standby_names=''; SELECT pg_reload_conf();")
					if err != nil {
						return err
					}
					for {
						value, e := d.sql(ctx, i.Primary.ID, "SELECT current_setting('synchronous_standby_names')='';")
						if e == nil && value == "t" {
							return nil
						}
						if e = replicationWait(ctx); e != nil {
							return e
						}
					}
				}
				return nil
			}
			r, err := runReplication(ctx, dir, o)
			if err != nil {
				t.Fatal(err)
			}
			exportReplication(t, dir, p, r)
			if r.Verdict == result.Pass || !r.Cleanup.Complete {
				t.Fatalf("unsafe result: verdict=%s cleanup=%v problem=%s", r.Verdict, r.Cleanup.Complete, r.Problem)
			}
			if mode != "cancel-during-cleanup" && r.Measurements.PromotionObserved {
				t.Fatal("unsafe/ambiguous path accepted verified promotion")
			}
			if mode == "ineffective-sync" && r.Measurements.FailureObserved {
				t.Fatal("primary killed despite ineffective synchronous mode")
			}
			t.Logf("mode=%s real Docker/PostgreSQL operations; loss of API acknowledgements and journal corruption explicitly controlled; problem=%s", mode, r.Problem)
		})
	}
}
