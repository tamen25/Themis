package experiment

import (
	"bytes"
	"testing"

	"github.com/tamen25/themis/internal/result"
)

func FuzzReplayExperiment(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("{}\n"))
	f.Add([]byte("{\"version\":\"themis.experiment-journal/v1alpha1\"}\n"))
	f.Add([]byte("{\"version\":\"themis.experiment-journal/v1alpha2\"}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := Replay(bytes.NewReader(data))
		if err == nil && r.Verdict == result.Pass {
			if r.FaultAttempted == nil || !*r.FaultAttempted || !r.BaselineSatisfied || !r.InterventionConfirmed || !r.RecoveryObserved || !r.CleanupCompleted || !r.SufficientObservations || r.Execution.Status != result.Succeeded {
				t.Fatal("PASS without complete execution prerequisites")
			}
			if r.Version == Version && (r.Provenance == nil || r.Provenance.Source != UnsignedReplay || r.Provenance.ExecutionAttestation != "UNVERIFIED") {
				t.Fatal("replay silently upgraded unsigned evidence")
			}
		}
	})
}
