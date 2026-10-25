package nativewitness

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/localstate"
	obs "github.com/tamen25/themis/pkg/nativeobservation"
)

type actualJournalFailure struct {
	*os.File
	mode string
}

func (f actualJournalFailure) Write(b []byte) (int, error) {
	if f.mode == "short" {
		return f.File.Write(b[:len(b)/2])
	}
	n, err := f.File.Write(b)
	if err == nil && f.mode == "sync-on-closed-file" {
		err = f.File.Close()
	}
	return n, err
}

func TestNativeWitnessActualFileFailuresCannotResume(t *testing.T) {
	for _, mode := range []string{"short", "sync-on-closed-file"} {
		t.Run(mode, func(t *testing.T) {
			dir, err := localstate.CreateDirectory(filepath.Join(t.TempDir(), "witness"))
			if err != nil {
				t.Fatal(err)
			}
			file, err := localstate.OpenNew(filepath.Join(dir, "observations.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			j := journal{file: actualJournalFailure{file, mode}, key: key, epoch: time.Now()}
			if _, err := j.append("START", "CONFIRMED", 0, nil); err == nil || !j.poisoned {
				t.Fatal("actual file error did not poison witness")
			}
			if _, err := j.append("END", "CONFIRMED", 0, nil); err == nil || len(j.records) != 0 || len(j.raw) != 0 {
				t.Fatal("ambiguous persistence was promoted to a recorded terminal")
			}
			t.Logf("ACTUAL FILE fault=%s retained bytes are a prefix, no fabricated terminal or successful resume", mode)
		})
	}
}

func TestNativeWitnessActualRecordAndByteCapacity(t *testing.T) {
	for _, mode := range []string{"record-cap", "byte-cap"} {
		t.Run(mode, func(t *testing.T) {
			dir, err := localstate.CreateDirectory(filepath.Join(t.TempDir(), "bounded"))
			if err != nil {
				t.Fatal(err)
			}
			file, err := localstate.OpenNew(filepath.Join(dir, "observations.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			j := journal{file: file, key: key, epoch: time.Now()}
			if mode == "record-cap" {
				for range obs.MaxRecords {
					if _, err := j.append("SAMPLE", "UNKNOWN", 0, nil); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				// Controlled in-memory near-cap state exercises the real writer's
				// bound without consuming a host filesystem or fabricating proof.
				j.raw = make([]byte, obs.MaxJournal-1)
			}
			before, _ := file.Stat()
			if _, err := j.append("SAMPLE", "UNKNOWN", 0, nil); err == nil {
				t.Fatal("native witness capacity exceeded")
			}
			after, _ := file.Stat()
			if before.Size() != after.Size() || after.Size() > obs.MaxJournal {
				t.Fatal("failed bounded append wrote or grew a final record")
			}
			t.Logf("BOUNDED CONTROLLED writer capacity=%s retainedRecords=%d fileBytes=%d", mode, len(j.records), after.Size())
		})
	}
}
