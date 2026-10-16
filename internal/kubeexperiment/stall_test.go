package kubeexperiment

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/localstate"
)

type stalledSync struct {
	journalFile
	block            bool
	entered, release chan struct{}
	once             sync.Once
}

func (f *stalledSync) Sync() error {
	if f.block {
		f.once.Do(func() { close(f.entered) })
		<-f.release
	}
	return f.journalFile.Sync()
}

func TestIndependentExpiryWhileActualJournalSyncIsStalled(t *testing.T) {
	p, c, a := localSession(t, "healthy")
	dir, err := localstate.CreateDirectory(filepath.Join(t.TempDir(), "private"))
	if err != nil {
		t.Fatal(err)
	}
	file, err := localstate.OpenNew(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	f := &stalledSync{journalFile: file, entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(f.release) })
	j := &journal{file: f, epoch: time.Now()}
	summary := publicAuthorization(a.Grant)
	if err = j.append(Event{Type: "START", Plan: &p, Authorization: &summary}); err != nil {
		t.Fatal(err)
	}
	if err = j.append(Event{Type: "INTENT"}); err != nil {
		t.Fatal(err)
	}
	status, err := c.Control(context.Background(), a, "apply")
	if err != nil {
		t.Fatal(err)
	}
	f.block = true
	done := make(chan error, 1)
	go func() { done <- j.append(Event{Type: "APPLIED", Status: &status}) }()
	select {
	case <-f.entered:
	case <-time.After(time.Second):
		t.Fatal("actual file boundary did not stall")
	}
	time.Sleep(time.Until(status.ExpiresAt) + 30*time.Millisecond)
	observed, err := c.Control(context.Background(), a, "status")
	if err != nil || observed.Active || observed.Reason != "expired" {
		t.Fatal("journal stall extended intervention", err)
	}
	release.Do(func() { close(f.release) })
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}
