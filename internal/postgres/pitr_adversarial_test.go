package postgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
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

func TestPITRExactTargetProof(t *testing.T) {
	p, _ := testPITRPlan(t)
	s := PITRPrepared{TargetLSN: "0/1001488"}
	good := "t|paused|0/1001488|" + p.TargetName + "|1|pause"
	if !validPITRTarget(p, s, good) {
		t.Fatal("exact observation rejected")
	}
	for _, v := range []string{"database ready", strings.Replace(good, "t|", "f|", 1), strings.Replace(good, "paused", "not paused", 1), strings.Replace(good, "1001488", "1001480", 1), strings.Replace(good, "1001488", "1001490", 1), strings.Replace(good, p.TargetName, "wrong", 1), strings.Replace(good, "|1|", "|2|", 1), strings.Replace(good, "pause", "promote", 1)} {
		if validPITRTarget(p, s, v) {
			t.Fatal("startup, wrong target, wrong timeline or replay drift accepted")
		}
	}
}
func TestRealPITRAdmissionAndArtifacts(t *testing.T) {
	dir, p := pitrLiveSetup(t, "healthy")
	s, err := PreparePITR(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	d := Docker{p.Inventory.Endpoint, p.Inventory.Engine}
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		alter func(*PITRInventory)
	}{
		{"wrong-engine", func(i *PITRInventory) { i.Engine = "wrong-original-engine" }},
		{"wrong-container", func(i *PITRInventory) { i.Source.ID = i.Restore.ID }},
		{"wrong-volume", func(i *PITRInventory) { i.Source.Volume = i.Restore.Volume }},
		{"wrong-boot", func(i *PITRInventory) { i.Starts["source"] = "wrong-boot" }},
		{"wrong-system", func(i *PITRInventory) { i.Source.DB.System = "other" }},
		{"wrong-owner", func(i *PITRInventory) { i.Run = strings.Repeat("b", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := json.Marshal(p.Inventory)
			var i PITRInventory
			json.Unmarshal(b, &i)
			tc.alter(&i)
			client := Docker{i.Endpoint, i.Engine}
			if client.pitrSource(ctx, i) == nil {
				t.Fatal("wrong live identity admitted")
			}
		})
	}
	t.Run("archive-lag", func(t *testing.T) {
		if pitrWaitArchive(ctx, d, p.Inventory, []string{"000000010000000000000FFF"}) == nil {
			t.Fatal("unavailable required WAL declared archived")
		}
	})
	t.Run("partial-archive-publication", func(t *testing.T) {
		if err := pitrDeliver(ctx, d, p.Inventory.Archive.ID, "/var/lib/postgresql/wal", map[string]string{".partial-test": "partial"}); err != nil {
			t.Fatal(err)
		}
		if pitrWaitArchive(ctx, d, p.Inventory, []string{strings.TrimPrefix(s.WAL[0].Name, "wal/")}) == nil {
			t.Fatal("partial WAL publication admitted")
		}
		if _, err := pitrExec(ctx, d, p.Inventory.Archive.ID, "rm", "--", "/var/lib/postgresql/wal/.partial-test"); err != nil {
			t.Fatal(err)
		}
	})
	// Each mutation affects retained bytes, not a fake Docker client's response.
	for _, name := range []string{"base.tar", "backup_manifest", s.WAL[0].Name} {
		t.Run("corrupt-"+strings.ReplaceAll(name, "/", "-"), func(t *testing.T) {
			pathname := pitrCapsule(p.Inventory, name)
			f, err := os.OpenFile(pathname, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			var old [1]byte
			if _, err = f.ReadAt(old[:], 0); err != nil {
				t.Fatal(err)
			}
			if _, err = f.WriteAt([]byte{old[0] ^ 1}, 0); err != nil {
				t.Fatal(err)
			}
			f.Sync()
			f.Close()
			if verifyPITRCapsule(p, s) == nil {
				t.Fatal("corrupt artifact admitted")
			}
			f, err = os.OpenFile(pathname, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			f.WriteAt(old[:], 0)
			f.Sync()
			f.Close()
			if err = verifyPITRCapsule(p, s); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, name := range []string{"backup_manifest", "base.tar"} {
		t.Run("missing-"+name, func(t *testing.T) {
			pathname := pitrCapsule(p.Inventory, name)
			if err := os.Rename(pathname, pathname+".missing"); err != nil {
				t.Fatal(err)
			}
			if verifyPITRCapsule(p, s) == nil {
				t.Fatal("missing physical evidence admitted")
			}
			if err := os.Rename(pathname+".missing", pathname); err != nil {
				t.Fatal(err)
			}
		})
	}
	basePath := pitrCapsule(p.Inventory, "base.tar")
	f, err := os.OpenFile(basePath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	var tail [1]byte
	if _, err = f.ReadAt(tail[:], info.Size()-1); err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(info.Size() - 1); err != nil {
		t.Fatal(err)
	}
	f.Sync()
	f.Close()
	if verifyPITRCapsule(p, s) == nil {
		t.Fatal("truncated base backup admitted")
	}
	f, err = os.OpenFile(basePath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteAt(tail[:], info.Size()-1); err != nil {
		t.Fatal(err)
	}
	f.Sync()
	f.Close()
	for _, name := range []string{"pitr-receipt-01.json", "pitr-prepare.jsonl"} {
		t.Run("corrupt-"+name, func(t *testing.T) {
			pathname := filepath.Join(dir, name)
			original, err := os.ReadFile(pathname)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(pathname, append(original, []byte("corrupt")...), 0600); err != nil {
				t.Fatal(err)
			}
			if verifyPITRCapsule(p, s) == nil {
				t.Fatal("damaged independent receipt/history admitted")
			}
			if err = os.WriteFile(pathname, original, 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
	pathname := pitrCapsule(p.Inventory, s.WAL[len(s.WAL)-1].Name)
	if err = os.Rename(pathname, pathname+".missing"); err != nil {
		t.Fatal(err)
	}
	if verifyPITRCapsule(p, s) == nil {
		t.Fatal("missing WAL admitted")
	}
	if err = os.Rename(pathname+".missing", pathname); err != nil {
		t.Fatal(err)
	}
	// A replacement inode with identical bytes must still be rejected.
	base := pitrCapsule(p.Inventory, "base.tar")
	if err = os.Rename(base, base+".original"); err != nil {
		t.Fatal(err)
	}
	old, err := os.Open(base + ".original")
	if err != nil {
		t.Fatal(err)
	}
	if err = pitrPublish(base, old, PITRBackupBytes); err != nil {
		t.Fatal(err)
	}
	old.Close()
	if verifyPITRCapsule(p, s) == nil {
		t.Fatal("identical-byte substituted base backup admitted")
	}
	if err = os.Remove(base); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(base+".original", base); err != nil {
		t.Fatal(err)
	}
	// Incorrect signed metadata remains invalid even under a trusted test signer.
	k, err := pitrLoadKeys(p.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	preparedPath := filepath.Join(dir, "pitr-prepared.json")
	original, err := os.ReadFile(preparedPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		alter func(*PITRPrepared)
	}{{"target-before-backup", func(s *PITRPrepared) { s.TargetLSN = s.StartLSN }}, {"wrong-target", func(s *PITRPrepared) { s.TargetName = "wrong" }}, {"wrong-timeline", func(s *PITRPrepared) { s.Timeline = 2 }}, {"system-mismatch", func(s *PITRPrepared) { s.System = "other" }}, {"WAL-reordered", func(s *PITRPrepared) { s.WAL[0], s.WAL[1] = s.WAL[1], s.WAL[0] }}} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := json.Marshal(s)
			var v PITRPrepared
			json.Unmarshal(b, &v)
			tc.alter(&v)
			v.Digest = pitrPreparedHash(v)
			v.Signature = ed25519.Sign(k.Ledger, []byte(v.Digest))
			b, _ = json.Marshal(v)
			if err := os.WriteFile(preparedPath, b, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadPITRPrepared(p); err == nil {
				t.Fatal("unsafe prepared plan admitted")
			}
			if err := os.WriteFile(preparedPath, original, 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
	if _, err = d.pitrContainer(ctx, p.Inventory, p.Inventory.Source, true, true); err != nil {
		t.Fatal("negative admissions mutated source")
	}
	for _, name := range []string{"pitr-ownership.json", "pitr-cleanup-capability.json"} {
		t.Run("missing-"+name, func(t *testing.T) {
			src := filepath.Join(dir, name)
			if err := os.Rename(src, src+".withheld"); err != nil {
				t.Fatal(err)
			}
			r, e := ReconcilePITR(ctx, dir)
			if e == nil && r.Complete {
				t.Fatal("cleanup adopted missing authority")
			}
			if err := os.Rename(src+".withheld", src); err != nil {
				t.Fatal(err)
			}
			if err := d.pitrSource(ctx, p.Inventory); err != nil {
				t.Fatal("denied cleanup changed source")
			}
		})
	}
	// Exercise the real kernel per-file bound in the owned tools container.
	_, err = pitrExec(ctx, d, p.Inventory.Archive.ID, "dd", "if=/dev/zero", "of=/var/lib/postgresql/budget-probe", "bs=1048576", "count=9")
	if err == nil {
		t.Fatal("hard per-file budget not enforced")
	}
	b, err := pitrExec(ctx, d, p.Inventory.Archive.ID, "stat", "-c", "%s", "/var/lib/postgresql/budget-probe")
	if err != nil || strings.TrimSpace(string(b)) != "8388608" {
		t.Fatal("actual fsize budget boundary unproven")
	}
	t.Log("actual negative live identity checks, artifact corruption/substitution, signed invalid metadata and kernel fsize limit executed; no source fault")
}

type pitrFailWriter struct {
	w         io.Writer
	remaining int
}

func (w *pitrFailWriter) Write(b []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, io.ErrUnexpectedEOF
	}
	if len(b) > w.remaining {
		b = b[:w.remaining]
	}
	n, err := w.w.Write(b)
	w.remaining -= n
	if err == nil && w.remaining == 0 {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}
func TestRealPITRInterruptedBackup(t *testing.T) {
	dir, _ := pitrLiveSetup(t, "healthy")
	_, err := preparePITR(context.Background(), dir, pitrOptions{backupOutput: func(w io.Writer) io.Writer { return &pitrFailWriter{w, 32768} }})
	if err == nil {
		t.Fatal("interrupted physical backup reported complete")
	}
	if _, err = os.Stat(filepath.Join(dir, "pitr-prepared.json")); !os.IsNotExist(err) {
		t.Fatal("incomplete backup eligible for failure approval")
	}
	if _, err = ApprovePITR(dir, strings.Repeat("a", 64), "sigkill-physical-target-once"); err == nil {
		t.Fatal("partial physical backup authorized SIGKILL")
	}
	info, err := os.Stat(filepath.Join(dir, "capsule", "base.tar.partial"))
	if err != nil || info.Size() != 32768 {
		t.Fatal("actual partial backup output not retained")
	}
	t.Logf("actual pg_basebackup interrupted after %d bytes; no prepared seal, grant or source kill", info.Size())
}

func TestPITRProcessHelper(t *testing.T) {
	dir, stage := os.Getenv("THEMIS_PITR_HELPER_STATE"), os.Getenv("THEMIS_PITR_HELPER_STAGE")
	if dir == "" {
		t.Skip("subprocess helper")
	}
	if stage == "WAL_COPY" {
		_, err := preparePITR(context.Background(), dir, pitrOptions{walCopyInput: func(r io.Reader) io.Reader { return &pitrPausedWALCopy{r: r, dir: dir} }})
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	_, err := runPITR(context.Background(), dir, pitrOptions{after: func(s string, p PITRPlan) error {
		if s == stage {
			if err := localstate.WriteNew(filepath.Join(dir, "pitr-helper-reached.json"), map[string]string{"stage": s}); err != nil {
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

type pitrPausedWALCopy struct {
	r      io.Reader
	dir    string
	copied int
}

func (r *pitrPausedWALCopy) Read(b []byte) (int, error) {
	if r.copied == 8192 {
		if err := localstate.WriteNew(filepath.Join(r.dir, "pitr-helper-reached.json"), map[string]string{"stage": "WAL_COPY"}); err != nil {
			return 0, err
		}
		select {}
	}
	if len(b) > 8192-r.copied {
		b = b[:8192-r.copied]
	}
	n, err := r.r.Read(b)
	r.copied += n
	return n, err
}
func TestRealPITRWALCopyProcessDeath(t *testing.T) {
	dir, p := pitrLiveSetup(t, "healthy")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestPITRProcessHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "THEMIS_PITR_HELPER_STATE="+dir, "THEMIS_PITR_HELPER_STAGE=WAL_COPY")
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	deadline := time.Now().Add(80 * time.Second)
	for {
		if _, err = os.Stat(filepath.Join(dir, "pitr-helper-reached.json")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatalf("actual WAL copy not reached: %s", output.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err = cmd.Wait(); err == nil {
		t.Fatal("runner death not observed")
	}
	files, err := filepath.Glob(filepath.Join(dir, "capsule", "wal", "*.partial"))
	if err != nil || len(files) != 1 {
		t.Fatal("partial real WAL publication not retained")
	}
	info, err := os.Stat(files[0])
	if err != nil || info.Size() != 8192 {
		t.Fatal("actual interrupted WAL bytes not observed")
	}
	if _, err = os.Stat(filepath.Join(dir, "pitr-prepared.json")); !os.IsNotExist(err) {
		t.Fatal("interrupted WAL publication became eligible")
	}
	if _, err = ApprovePITR(dir, strings.Repeat("a", 64), "sigkill-physical-target-once"); err == nil {
		t.Fatal("partial WAL authorized source failure")
	}
	if err = (Docker{p.Inventory.Endpoint, p.Inventory.Engine}).pitrSource(context.Background(), p.Inventory); err != nil {
		t.Fatal("WAL publication interruption changed source")
	}
	t.Log("actual OS runner killed during host publication after 8192 bytes of a real archived WAL segment; no prepared seal or SIGKILL authority; source remains original and available")
}
func TestRealPITRRunnerDeath(t *testing.T) {
	for _, stage := range []string{"SOURCE_STOPPED", "RECOVERY_STARTED"} {
		t.Run(stage, func(t *testing.T) {
			dir, p := pitrLiveSetup(t, "healthy")
			s, err := PreparePITR(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = ApprovePITR(dir, s.Digest, "sigkill-physical-target-once"); err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(executable, "-test.run=^TestPITRProcessHelper$", "-test.v")
			cmd.Env = append(os.Environ(), "THEMIS_PITR_HELPER_STATE="+dir, "THEMIS_PITR_HELPER_STAGE="+stage)
			var output bytes.Buffer
			cmd.Stdout = &output
			cmd.Stderr = &output
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if cmd.ProcessState == nil {
					cmd.Process.Kill()
					cmd.Wait()
				}
			})
			deadline := time.Now().Add(80 * time.Second)
			for {
				if _, err = os.Stat(filepath.Join(dir, "pitr-helper-reached.json")); err == nil {
					break
				}
				if time.Now().After(deadline) {
					cmd.Process.Kill()
					cmd.Wait()
					t.Fatalf("helper stage not reached: %s", output.String())
				}
				time.Sleep(100 * time.Millisecond)
			}
			if _, err = ReconcilePITR(context.Background(), dir); err == nil {
				t.Fatal("cleanup raced live runner")
			}
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err = cmd.Wait(); err == nil {
				t.Fatal("runner termination not observed")
			}
			if _, err = os.Stat(filepath.Join(dir, "pitr-report.json")); !os.IsNotExist(err) {
				t.Fatal("dead runner published completed result")
			}
			journal, err := os.ReadFile(filepath.Join(dir, "pitr-journal.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = RunPITR(context.Background(), dir); err == nil {
				t.Fatal("dead invocation resumed")
			}
			// Recovery reconciliation survives deliberately corrupt execution history.
			if stage == "SOURCE_STOPPED" {
				journal = append(journal, []byte("torn")...)
				if err = os.WriteFile(filepath.Join(dir, "pitr-journal.jsonl"), journal, 0600); err != nil {
					t.Fatal(err)
				}
			}
			clean, err := ReconcilePITR(context.Background(), dir)
			if err != nil || !clean.Complete {
				t.Fatalf("cleanup after actual runner death: %v %s", err, clean.Reason)
			}
			after, _ := os.ReadFile(filepath.Join(dir, "pitr-journal.jsonl"))
			if !bytes.Equal(journal, after) {
				t.Fatal("reconcile changed interrupted journal")
			}
			if err = verifyPITRCapsule(p, s); err != nil {
				t.Fatal("host base backup/WAL not independently readable after all Docker resources removed")
			}
			t.Logf("actual OS runner termination at %s; original source already SIGKILLed; no resume, historical bytes retained, all resources independently reconciled", stage)
		})
	}
}

func TestRealPITRIncorrectTarget(t *testing.T) {
	dir, p := pitrLiveSetup(t, "healthy")
	s, err := PreparePITR(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ApprovePITR(dir, s.Digest, "sigkill-physical-target-once"); err != nil {
		t.Fatal(err)
	}
	r, err := runPITR(context.Background(), dir, pitrOptions{after: func(stage string, p PITRPlan) error {
		if stage == "BEFORE_RECOVERY_START" {
			// A controlled installer test changes only this newly owned destination.
			// No operator-supplied SQL/configuration surface exists in the CLI.
			d := Docker{p.Inventory.Endpoint, p.Inventory.Engine}
			_, err := d.output(context.Background(), strings.NewReader("include = '/var/lib/postgresql/18/docker/postgresql.conf'\nrecovery_target_name = 'themis_absent_target'\n"), "exec", "-i", "--user", "999:999", p.Inventory.Restore.ID, "tee", "/var/lib/postgresql/themis-recovery/postgresql.conf")
			return err
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	exportPITR(t, dir, p, r)
	if r.Verdict != result.Inconclusive || r.Measurements.TargetObserved || r.Measurements.Promoted || r.Measurements.ReadWriteReady {
		t.Fatal("actual recovery before missing named point manufactured PASS")
	}
	if !r.Measurements.FailureObserved || !r.Cleanup.Complete {
		t.Fatal("actual fault or cleanup not observed")
	}
}

func TestRealPITRRecoveryHardening(t *testing.T) {
	for _, mode := range []string{"cancel-paused", "cancel-finalizing", "cancel-cleanup", "missing-capsule-directory", "corrupt-promoted-data", "interrupt-recovery-process"} {
		t.Run(mode, func(t *testing.T) {
			dir, p := pitrLiveSetup(t, "healthy")
			s, err := PreparePITR(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = ApprovePITR(dir, s.Digest, "sigkill-physical-target-once"); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			moved := false
			r, err := runPITR(ctx, dir, pitrOptions{after: func(stage string, p PITRPlan) error {
				d := Docker{p.Inventory.Endpoint, p.Inventory.Engine}
				if mode == "cancel-paused" && stage == "TARGET_PAUSED" {
					cancel()
					return nil
				}
				if mode == "cancel-finalizing" && stage == "RECOVERY_READY" {
					cancel()
					return nil
				}
				if mode == "cancel-cleanup" && stage == "CLEANUP_STARTING" {
					cancel()
					return nil
				}
				if mode == "missing-capsule-directory" && stage == "SOURCE_STOPPED" {
					from, to := filepath.Join(dir, "capsule"), filepath.Join(dir, "capsule.withheld")
					if !filepath.IsAbs(from) || !filepath.IsAbs(to) || filepath.Dir(from) != dir || filepath.Dir(to) != dir {
						return io.ErrUnexpectedEOF
					}
					if err := os.Rename(from, to); err != nil {
						return err
					}
					moved = true
				}
				if mode == "corrupt-promoted-data" && stage == "PROMOTED" {
					_, err := d.sql(ctx, p.Inventory.Restore.ID, "UPDATE themis_app.accounts SET balance=balance+1 WHERE id=1;")
					return err
				}
				if mode == "interrupt-recovery-process" && stage == "RECOVERY_STARTED" {
					deadline := time.Now().Add(10 * time.Second)
					for {
						v, e := d.sql(ctx, p.Inventory.Restore.ID, "SELECT pg_is_in_recovery();")
						if e == nil && v == "t" {
							break
						}
						if time.Now().After(deadline) {
							return io.ErrUnexpectedEOF
						}
						time.Sleep(100 * time.Millisecond)
					}
					if _, err := d.pitrContainer(ctx, p.Inventory, p.Inventory.Restore, true, true); err != nil {
						return err
					}
					if _, err := d.output(ctx, nil, "container", "kill", "--signal", "KILL", p.Inventory.Restore.ID); err != nil {
						return err
					}
					stopped, err := d.pitrContainer(ctx, p.Inventory, p.Inventory.Restore, false, true)
					if err != nil {
						return err
					}
					if stopped.State.Running || stopped.State.Pid != 0 || stopped.State.ExitCode != 137 {
						return io.ErrUnexpectedEOF
					}
					t.Log("actual owned PostgreSQL recovery process killed after independently observing pg_is_in_recovery=true")
					return io.ErrUnexpectedEOF
				}
				return nil
			}})
			if moved {
				from, to := filepath.Join(dir, "capsule.withheld"), filepath.Join(dir, "capsule")
				if filepath.Dir(from) != dir || filepath.Dir(to) != dir {
					t.Fatal("private archive path scope changed")
				}
				if e := os.Rename(from, to); e != nil {
					t.Fatal(e)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			exportPITR(t, dir, p, r)
			want := result.Inconclusive
			if mode == "corrupt-promoted-data" {
				want = result.Fail
			}
			if r.Verdict != want || !r.Cleanup.Complete || r.Measurements.ReadWriteReady != (mode == "cancel-finalizing" || mode == "cancel-cleanup") {
				t.Fatalf("hardening %s: verdict=%s cleanup=%t problem=%s", mode, r.Verdict, r.Cleanup.Complete, r.Problem)
			}
		})
	}
}
func TestRealPITRArchiveBudget(t *testing.T) {
	dir, p := pitrLiveSetup(t, "healthy")
	d := Docker{p.Inventory.Endpoint, p.Inventory.Engine}
	ctx := context.Background()
	for _, name := range []string{"budget-1", "budget-2", "budget-3", "budget-4"} {
		if _, err := pitrExec(ctx, d, p.Inventory.Archive.ID, "dd", "if=/dev/zero", "of=/var/lib/postgresql/wal/"+name, "bs=1048576", "count=8"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := PreparePITR(ctx, dir); err == nil {
		t.Fatal("exhausted owned WAL archive budget admitted")
	}
	if _, err := os.Stat(filepath.Join(dir, "pitr-prepared.json")); !os.IsNotExist(err) {
		t.Fatal("full archive published eligible preparation")
	}
	if err := d.pitrSource(ctx, p.Inventory); err != nil {
		t.Fatal("archive capacity rejection changed source")
	}
	t.Log("actual fixed owned archive filled to 32 MiB; archiving/preparation failed closed without source SIGKILL")
}
func TestRealPITRSourceRestartAndUnrelatedCleanup(t *testing.T) {
	dir, p := pitrLiveSetup(t, "healthy")
	_, other := pitrLiveSetup(t, "healthy")
	d := Docker{p.Inventory.Endpoint, p.Inventory.Engine}
	ctx := context.Background()
	forged := p.Inventory
	forged.Source = other.Inventory.Source
	if c := pitrCleanup(ctx, forged, false); c.Complete || len(c.Actions) != 0 {
		t.Fatal("unrelated inventory authorized deletion")
	}
	if err := d.pitrSource(ctx, other.Inventory); err != nil {
		t.Fatal("denied cleanup changed unrelated owned source")
	}
	s, err := PreparePITR(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ApprovePITR(dir, s.Digest, "sigkill-physical-target-once"); err != nil {
		t.Fatal(err)
	}
	if _, err = d.output(ctx, nil, "container", "restart", "--time", "1", p.Inventory.Source.ID); err != nil {
		t.Fatal(err)
	}
	if err = d.pitrSource(ctx, p.Inventory); err == nil {
		t.Fatal("restarted source admitted under original boot")
	}
	r, err := RunPITR(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	exportPITR(t, dir, p, r)
	if r.Verdict != result.Inconclusive || r.Measurements.FailureObserved || !r.Cleanup.Complete {
		t.Fatal("stale boot executed source fault or prevented independent cleanup")
	}
	if err = d.pitrSource(ctx, other.Inventory); err != nil {
		t.Fatal("reconcile changed unrelated source")
	}
}
