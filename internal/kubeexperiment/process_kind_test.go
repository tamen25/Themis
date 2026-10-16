package kubeexperiment

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/localstate"
)

type tornAppliedWrite struct{ journalFile }

func (f tornAppliedWrite) Write(data []byte) (int, error) {
	if bytes.Contains(data, []byte(`"type":"APPLIED"`)) {
		n, err := f.journalFile.Write(data[:len(data)/2])
		if err != nil {
			return n, err
		}
		if err = f.journalFile.Sync(); err != nil {
			return n, err
		}
		fmt.Println("THEMIS_ACTUAL_JOURNAL_WRITE_STALLED")
		select {} // parent owns and kills this test child; fixture timer stays independent
	}
	return f.journalFile.Write(data)
}

func TestKindJournalWriterChild(t *testing.T) {
	if os.Getenv("THEMIS_JOURNAL_CHILD") != "1" {
		t.Skip("child helper only")
	}
	ctx := context.Background()
	c, err := Open(ctx, os.Getenv("THEMIS_KIND_EXPERIMENT_STATE"))
	if err != nil {
		t.Fatal(err)
	}
	var a kubefault.Authorization
	if err = localstate.Read(os.Getenv("THEMIS_JOURNAL_AUTH"), &a); err != nil {
		t.Fatal(err)
	}
	_, _, err = c.executeWithStorage(ctx, a.Grant.Plan, a, filepath.Dir(os.Getenv("THEMIS_JOURNAL_AUTH")), func(path string) (journalFile, error) {
		f, err := localstate.OpenNew(path)
		return tornAppliedWrite{f}, err
	})
	t.Fatal("child unexpectedly returned before journal-write termination", err)
}

func TestRealKindJournalWriterTermination(t *testing.T) {
	if os.Getenv("THEMIS_KIND_LIFECYCLE") != "1" {
		t.Skip("NOT EXECUTED: explicit owned Kind lifecycle opt-in required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := Open(ctx, os.Getenv("THEMIS_KIND_EXPERIMENT_STATE"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Plan(ctx, "latency-request", "healthy")
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.Approve(ctx, p, p.Digest())
	if err != nil {
		t.Fatal(err)
	}
	root, err := localstate.CreateDirectory(filepath.Join(c.StateDirectory, "case-journal-write-"+kubefault.RandomID()[:12]))
	if err != nil {
		t.Fatal(err)
	}
	authPath := filepath.Join(root, "authorization.json")
	if err = localstate.WriteNew(authPath, a); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestKindJournalWriterChild$", "-test.v")
	cmd.Env = append(os.Environ(), "THEMIS_JOURNAL_CHILD=1", "THEMIS_JOURNAL_AUTH="+authPath)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	stalled := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "THEMIS_ACTUAL_JOURNAL_WRITE_STALLED") {
				stalled <- true
				return
			}
		}
		stalled <- false
	}()
	select {
	case ready := <-stalled:
		if !ready {
			t.Fatal("actual child did not stall in journal Write")
		}
	case <-ctx.Done():
		t.Fatal("child write-stall timeout")
	}
	s, err := c.Connect(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	known, err := s.Client.Control(ctx, a, "status")
	s.Close()
	if err != nil || !known.Applied || !known.Active {
		t.Fatal("fault application not known while journal writing stalled", err)
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	waitErr := cmd.Wait()
	waited = true
	exit := -99
	var processExit *exec.ExitError
	if errors.As(waitErr, &processExit) {
		exit = processExit.ExitCode()
	}
	if waitErr == nil {
		t.Fatal("terminated child succeeded")
	}
	dir := filepath.Join(root, "run-"+a.Grant.InvocationID)
	before, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ReadJournal(filepath.Join(dir, "events.jsonl")); err == nil {
		t.Fatal("actual partial journal accepted")
	}
	if wait := time.Until(known.ExpiresAt) + 70*time.Millisecond; wait > 0 {
		time.Sleep(wait)
	}
	s, err = c.Connect(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	expired, err := s.Client.Control(ctx, a, "status")
	s.Close()
	if err != nil || expired.Active || expired.Reason != "expired" {
		t.Fatal("runner journal death extended fault", err)
	}
	receipt, err := c.Cancel(ctx, dir)
	if err != nil || receipt.OperationalState != "CLEANUP_COMPLETE" || !receipt.RecoveryVerified {
		t.Fatal("torn-journal cleanup/recovery failed", err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if !bytes.Equal(before, after) {
		t.Fatal("cleanup changed torn historical bytes")
	}
	if evidence := os.Getenv("THEMIS_KIND_EXPERIMENT_EVIDENCE"); evidence != "" {
		if err = os.MkdirAll(evidence, 0700); err != nil {
			t.Fatal(err)
		}
		data, _ := json.MarshalIndent(map[string]any{"boundary": "REAL_KIND_ACTUAL_CHILD_TERMINATED_DURING_PARTIAL_JOURNAL_WRITE", "childExitCode": exit, "stderr": stderr.String(), "knownApplied": known, "independentExpiry": expired, "cleanup": receipt, "historicalBytesUnchanged": true, "historicalComplete": false}, "", "  ")
		if err = os.WriteFile(filepath.Join(evidence, "actual-journal-writer-death.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(evidence, "actual-torn-journal.jsonl"), before, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Log("REAL KIND runner child killed during actual partial journal Write; known active fault independently expired; application recovery verified; corrupt history preserved")
}
