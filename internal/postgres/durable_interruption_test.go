package postgres

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

type durablePartialReader struct {
	ctx   context.Context
	r     io.Reader
	bytes atomic.Int64
}

func (r *durablePartialReader) Read(b []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	case <-time.After(20 * time.Millisecond):
	}
	if len(b) > 16 {
		b = b[:16]
	}
	n, e := r.r.Read(b)
	r.bytes.Add(int64(n))
	return n, e
}
func TestRealDurableRestoreInterruption(t *testing.T) {
	dir, p := durableLivePrepare(t, "healthy")
	d := Docker{p.Inventory.Endpoint, p.Inventory.Engine}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var partial *durablePartialReader
	observed := make(chan error, 1)
	opts := durableOptions{restoreInput: func(r io.Reader) io.Reader {
		partial = &durablePartialReader{ctx: ctx, r: r}
		go func() {
			watch, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			e := waitTool(watch, d, p.Inventory.Restore.ID, "pg_restore")
			if e == nil {
				for partial.bytes.Load() == 0 {
					select {
					case <-watch.Done():
						observed <- watch.Err()
						return
					case <-time.After(20 * time.Millisecond):
					}
				}
				cancel()
			}
			observed <- e
		}()
		return partial
	}}
	r, e := runDurable(ctx, dir, opts)
	if e != nil {
		t.Fatal(e)
	}
	if e = <-observed; e != nil {
		t.Fatal(e)
	}
	exportDurable(t, dir, r)
	if partial.bytes.Load() <= 0 || partial.bytes.Load() >= r.Measurements.Backup.Bytes {
		t.Fatal("did not interrupt actual partial archive input")
	}
	if r.Verdict != result.Inconclusive || r.Execution != result.Cancelled || !r.Cleanup.Complete || r.Measurements.RestoreExit == nil || *r.Measurements.RestoreExit == 0 || !r.Measurements.FailureObserved {
		t.Fatalf("unsafe interrupted restore %s/%s: %s", r.Verdict, r.Execution, r.Problem)
	}
	t.Logf("actual pg_restore observed, %d/%d archive bytes delivered before cancellation, child exit=%d", partial.bytes.Load(), r.Measurements.Backup.Bytes, *r.Measurements.RestoreExit)
}
func TestDurableDeathHelper(t *testing.T) {
	dir := os.Getenv("THEMIS_DURABLE_DEATH_DIR")
	if dir == "" {
		t.Skip("actual OS subprocess helper")
	}
	opts := durableOptions{after: func(stage string, p DurablePlan) error {
		if stage == "source-observed" {
			if e := localstate.WriteNew(filepath.Join(dir, "durable-death-ready.json"), map[string]string{"source": p.Inventory.Source.ID}); e != nil {
				return e
			}
			select {}
		}
		return nil
	}}
	if _, e := runDurable(context.Background(), dir, opts); e != nil {
		t.Fatal(e)
	}
	t.Fatal("parent did not kill helper")
}
func TestRealDurableRunnerDeath(t *testing.T) {
	dir, p := durableLivePrepare(t, "healthy")
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(exe, "-test.run=^TestDurableDeathHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "THEMIS_DURABLE_DEATH_DIR="+dir)
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
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, e = os.Stat(filepath.Join(dir, "durable-death-ready.json")); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("runner did not independently observe actual source termination")
		}
		time.Sleep(50 * time.Millisecond)
	}
	d := Docker{p.Inventory.Endpoint, p.Inventory.Engine}
	c, e := d.durableContainer(context.Background(), p.Inventory, p.Inventory.Source, false)
	if e != nil || c.State.Running || c.State.ExitCode != 137 {
		t.Fatal("source not actually uncleanly terminated")
	}
	if _, e = ReconcileDurable(context.Background(), dir); e == nil {
		t.Fatal("live process lock bypassed")
	}
	if e = cmd.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	e = cmd.Wait()
	if e == nil {
		t.Fatal("helper unexpectedly completed")
	}
	t.Logf("actual runner killed after exact source SIGKILL, child exit=%d error=%v", cmd.ProcessState.ExitCode(), e)
	if _, e = os.Stat(filepath.Join(dir, "durable-report.json")); !os.IsNotExist(e) {
		t.Fatal("dead runner invented a report")
	}
	before, e := os.ReadFile(filepath.Join(dir, "durable-journal.jsonl"))
	if e != nil || VerifyDurableJournal(before, p.Digest) != nil {
		t.Fatal("journal before death invalid")
	}
	for n := 0; n < 2; n++ {
		r, e := ReconcileDurable(context.Background(), dir)
		if e != nil || !r.Complete {
			t.Fatalf("independent cleanup failed: %v %s", e, r.Reason)
		}
	}
	after, _ := os.ReadFile(filepath.Join(dir, "durable-journal.jsonl"))
	if !bytes.Equal(before, after) {
		t.Fatal("recovery altered historical journal")
	}
	f, _, e := openDurableBackup(p)
	if e != nil {
		t.Fatal("backup lost after runner death and resource removal")
	}
	f.Close()
	if _, e = RunDurable(context.Background(), dir); e == nil {
		t.Fatal("dead invocation resumed")
	}
	t.Log("exact-ID independent cleanup complete twice; historical journal unchanged; backup retained; termination never retried")
}
func TestRealDurableSourceDiesBeforePublication(t *testing.T) {
	dir, p := durableLiveSetup(t, "healthy")
	opts := durableOptions{after: func(stage string, p DurablePlan) error {
		if stage == "backup-validated" {
			d := Docker{p.Inventory.Endpoint, p.Inventory.Engine}
			if e := d.durableTarget(context.Background(), p.Inventory, p.Inventory.Source); e != nil {
				return e
			}
			_, e := d.output(context.Background(), nil, "container", "kill", "--signal", "KILL", p.Inventory.Source.ID)
			return e
		}
		return nil
	}}
	if _, e := prepareDurable(context.Background(), dir, opts); e == nil {
		t.Fatal("source died before publication but preparation succeeded")
	}
	if _, e := os.Stat(filepath.Join(dir, "durable-prepared.json")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("early source death produced prepared seal")
	}
	if _, e := ApproveFailure(dir, p.Digest, "untrusted"); e == nil {
		t.Fatal("source died early yet failure authorized")
	}
	t.Log("controlled test-only early SIGKILL of exact fresh owned source; production preparation never has fault authority; incomplete artifact denied")
}
