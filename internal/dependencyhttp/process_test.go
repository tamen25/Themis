package dependencyhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

type crashMarker struct {
	Config                                Config
	PodUID, Boot, StateDirectory, Journal string
}

func TestNativeControlTornWriteChild(t *testing.T) {
	if os.Getenv("THEMIS_NATIVE_TORN_CHILD") != "1" {
		t.Skip("actual child helper")
	}
	f := newFixture(t)
	_ = f.authorize(t)
	// A real incomplete final append is synced, then the parent terminates this
	// actual process. No finalized record or resumed mutation is invented.
	tail := []byte(`{"kind":"apply-INTENT","partial":`)
	if _, e := f.proxy.journal.Write(tail); e != nil {
		t.Fatal(e)
	}
	if e := f.proxy.journal.Sync(); e != nil {
		t.Fatal(e)
	}
	marker := crashMarker{f.proxy.config, f.proxy.Identity.PodUID, f.proxy.Identity.Boot, filepath.Dir(filepath.Dir(f.proxy.journal.Name())), f.proxy.journal.Name()}
	b, e := json.Marshal(marker)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(os.Getenv("THEMIS_NATIVE_TORN_READY"), b, 0600); e != nil {
		t.Fatal(e)
	}
	time.Sleep(8 * time.Second)
	os.Exit(11)
}
func TestActualNativeProxyProcessDeathRetainsTornJournalWithoutResumption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ready.json")
	cmd := exec.Command(os.Args[0], "-test.run=^TestNativeControlTornWriteChild$")
	cmd.Env = append(os.Environ(), "THEMIS_NATIVE_TORN_CHILD=1", "THEMIS_NATIVE_TORN_READY="+path)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	var marker crashMarker
	ready := false
	for start := time.Now(); time.Since(start) < 6*time.Second; {
		b, e := os.ReadFile(path)
		if e == nil && json.Unmarshal(b, &marker) == nil {
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("real child did not reach partial append", output.String())
	}
	if e := cmd.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	if e := cmd.Wait(); e == nil {
		t.Fatal("actual child was not terminated")
	}
	before, e := os.ReadFile(marker.Journal)
	if e != nil || len(before) == 0 || before[len(before)-1] == '\n' {
		t.Fatal("actual torn tail absent")
	}
	restarted, e := NewServer(marker.Config, "proxy", marker.PodUID, marker.StateDirectory)
	if e != nil {
		t.Fatal(e)
	}
	defer restarted.Close()
	if restarted.Identity.Boot == marker.Boot || restarted.binding != nil || restarted.active != nil || len(restarted.epochs) != 0 {
		t.Fatal("restart resumed torn history or fault authority")
	}
	after, e := os.ReadFile(marker.Journal)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("restart repaired or rewrote original history")
	}
}
func TestMissingCleanupIdentityExpiredAuthorityAndCancelledApplyDenied(t *testing.T) {
	f := newFixture(t)
	a := f.authorize(t)
	a.Grant.CleanupBefore = time.Now().Add(-time.Second)
	if a.Grant.Valid(time.Now(), false) {
		t.Fatal("expired/conflicting cleanup accepted")
	}
	a = f.authorize(t)
	a.Grant.CleanupKey = ""
	if a.Grant.Valid(time.Now(), false) {
		t.Fatal("missing cleanup identity accepted")
	}
	a = f.authorize(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := f.proxy.mutate(ctx, NewCommand("apply", a, time.Now())); e == nil || f.proxy.snapshot(a.Grant.Invocation).Applied {
		t.Fatal("cancelled Apply mutated dependency path")
	}
}
