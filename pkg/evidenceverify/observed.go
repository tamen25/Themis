package evidenceverify

import (
	"github.com/tamen25/themis/internal/evidencesource"
	"github.com/tamen25/themis/pkg/evidence"
	obs "github.com/tamen25/themis/pkg/liveobservation"
	"io"
	"time"
)

// ObservedResult is an additive result format. T4.0 result bytes stay unchanged.
type ObservedResult struct {
	Version                  string          `json:"version"`
	Evidence                 evidence.Result `json:"evidence"`
	ObservationCorroboration obs.Finding     `json:"observationCorroboration"`
}

func VerifyObserved(r io.ReaderAt, size int64, publisherPolicy *evidence.Policy, witnessPolicy *obs.Policy, now time.Time) (ObservedResult, error) {
	o, e := Verify(r, size, publisherPolicy, now)
	f := obs.NewFinding()
	if e == nil {
		f = evidencesource.Corroborate(o, witnessPolicy, now)
	}
	return ObservedResult{"themis.witness-bundle-verification/v1alpha1", o.Result, f}, e
}
