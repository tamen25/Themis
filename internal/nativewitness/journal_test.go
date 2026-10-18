package nativewitness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	wire "github.com/tamen25/themis/internal/dependencyhttp"
	"github.com/tamen25/themis/internal/localstate"
	obs "github.com/tamen25/themis/pkg/nativeobservation"
)

type failingJournal struct {
	writes, syncs        int
	partial, syncFailure bool
}

func TestWitnessKeyCannotResumeCopiedSessionOrGrowWithoutBound(t *testing.T) {
	keyDir, e := localstate.CreateDirectory(filepath.Join(t.TempDir(), "key"))
	if e != nil {
		t.Fatal(e)
	}
	session := wire.ID()
	if e = claimSession(context.Background(), keyDir, session); e != nil {
		t.Fatal(e)
	}
	if claimSession(context.Background(), keyDir, session) == nil {
		t.Fatal("same session accepted again under signing key")
	}
	for range 63 {
		if e = claimSession(context.Background(), keyDir, wire.ID()); e != nil {
			t.Fatal(e)
		}
	}
	if claimSession(context.Background(), keyDir, wire.ID()) == nil {
		t.Fatal("unbounded witness key session growth")
	}
}

func (f *failingJournal) Write(b []byte) (int, error) {
	f.writes++
	if f.partial {
		return len(b) - 1, nil
	}
	return len(b), nil
}
func (f *failingJournal) Sync() error {
	f.syncs++
	if f.syncFailure {
		return errors.New("controlled sync failure")
	}
	return nil
}
func (f *failingJournal) Close() error { return nil }
func TestNativeWitnessFailedPersistencePoisonsWriter(t *testing.T) {
	for _, kind := range []string{"short-write", "sync"} {
		t.Run(kind, func(t *testing.T) {
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			file := &failingJournal{partial: kind == "short-write", syncFailure: kind == "sync"}
			j := journal{file: file, reg: obs.Registration{}, key: key, epoch: time.Now()}
			if _, e := j.append("START", "CONFIRMED", 0, nil); e == nil {
				t.Fatal("failed append accepted")
			}
			if _, e := j.append("END", "CONFIRMED", 0, nil); e == nil || file.writes != 1 || len(j.records) != 0 || len(j.raw) != 0 {
				t.Fatal("writer continued after ambiguous persistence")
			}
		})
	}
}
