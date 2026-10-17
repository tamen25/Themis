package evidence

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestPublicationCrashChild(t *testing.T) {
	dir := os.Getenv("THEMIS_EVIDENCE_CRASH_TEST")
	if dir == "" {
		return
	}
	m, f, k, _ := fixture(t)
	data, e := Sign(m, f, k)
	if e != nil {
		t.Fatal(e)
	}
	_ = publishBytes(filepath.Join(dir, "bundle.zip"), data, func(phase string) error {
		if phase == "synced" {
			if e := os.WriteFile(filepath.Join(dir, "ready"), []byte("synced-before-link"), 0600); e != nil {
				return e
			}
			select {}
		}
		return nil
	})
	t.Fatal("crash child unexpectedly returned")
}

func TestActualPublisherDeathBeforeFinalLink(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestPublicationCrashChild$")
	cmd.Env = append(os.Environ(), "THEMIS_EVIDENCE_CRASH_TEST="+dir)
	var diagnostic bytes.Buffer
	cmd.Stdout = &diagnostic
	cmd.Stderr = &diagnostic
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, e := os.Stat(filepath.Join(dir, "ready")); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("publication checkpoint unavailable", diagnostic.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e := cmd.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	_ = cmd.Wait()
	if _, e := os.Stat(filepath.Join(dir, "bundle.zip")); !os.IsNotExist(e) {
		t.Fatal("interrupted publisher exposed a final path")
	}
	// A subsequent explicit publication can succeed. Abandoned private temporary
	// filenames are not evidence discovery and are retained for operator review.
	m, f, k, _ := fixture(t)
	data, e := Sign(m, f, k)
	if e != nil {
		t.Fatal(e)
	}
	if e = PublishBytes(filepath.Join(dir, "bundle.zip"), data); e != nil {
		t.Fatal(e)
	}
}

func TestFailedSyncCheckpointLeavesNoPublication(t *testing.T) {
	out := filepath.Join(t.TempDir(), "bundle.zip")
	if e := publishBytes(out, []byte("incomplete"), func(string) error { return errors.New("controlled publication interruption") }); e == nil {
		t.Fatal("interrupted publication succeeded")
	}
	if _, e := os.Stat(out); !os.IsNotExist(e) {
		t.Fatal("partial final publication")
	}
}

func TestSourceSymlinkAndSubstitutedIdentity(t *testing.T) {
	m, f, _, _ := fixture(t)
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "artifacts"), 0700)
	p := filepath.Join(dir, "artifacts", "report.json")
	os.WriteFile(p, f["artifacts/report.json"], 0600)
	if _, e := snapshot(dir, m.Artifacts, func() {
		old := p + ".original"
		if e := os.Rename(p, old); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(p, f["artifacts/report.json"], 0600); e != nil {
			t.Fatal(e)
		}
	}); e == nil {
		t.Fatal("identical-byte file substitution accepted")
	}
	link := filepath.Join(t.TempDir(), "linked")
	if e := os.Symlink(dir, link); e != nil {
		t.Log("source-root symlink creation unavailable on this platform:", e)
		return
	}
	if _, e := Snapshot(link, m.Artifacts); e == nil {
		t.Fatal("symlink source root accepted")
	}
}
