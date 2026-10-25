package evidenceverify

import (
	"io"
	"time"

	"github.com/tamen25/themis/internal/evidencesource"
	"github.com/tamen25/themis/pkg/evidence"
	obs "github.com/tamen25/themis/pkg/nativeobservation"
)

// NativeObservedResult is additive: existing T4.0/T4.1 output bytes do not change.
type NativeObservedResult struct {
	Version                        string          `json:"version"`
	Evidence                       evidence.Result `json:"evidence"`
	NativeObservationCorroboration obs.Finding     `json:"nativeObservationCorroboration"`
}

func VerifyNative(r io.ReaderAt, size int64, publisherPolicy *evidence.Policy, witnessPolicy *obs.Policy, now time.Time) (NativeObservedResult, error) {
	o, e := Verify(r, size, publisherPolicy, now)
	f := obs.NewFinding()
	if e == nil {
		f = evidencesource.CorroborateNative(o, witnessPolicy, now)
	}
	return NativeObservedResult{"themis.native-witness-bundle-verification/v1alpha1", o.Result, f}, e
}
