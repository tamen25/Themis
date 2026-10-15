package experiment

import (
	"errors"

	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

// DecodeReport validates the declared artifact format. A report without its
// journal remains a recorded claim; parsing does not authenticate its contents.
func DecodeReport(data []byte) (Report, error) {
	var r Report
	if err := localstate.Unmarshal(data, &r); err != nil {
		return r, err
	}
	return r, validateReportFormat(r)
}

func validateReportFormat(r Report) error {
	if r.Version == LegacyVersion {
		if r.Provenance != nil || r.Deadlines != nil || r.Failure != nil {
			return errors.New("T1.2 fields in a T1.1 report")
		}
	} else if r.Version == Version {
		if r.Provenance == nil || r.Deadlines == nil {
			return errors.New("T1.2 provenance/deadlines required")
		}
		switch r.Provenance.Source {
		case LocallyCollected, UnsignedReplay, ImportedEvidence:
		default:
			return errors.New("unsupported evidence provenance")
		}
		if r.Provenance.ClientTiming != "MISSING" && r.Provenance.ClientTiming != "UNAUTHENTICATED_CLIENT_TIMING" {
			return errors.New("unsupported timing provenance")
		}
		switch r.Provenance.FixtureResponses {
		case "MISSING", "UNVERIFIED_OR_MISSING", "PARTIALLY_VERIFIED_FIXTURE_RESPONSES", "SIGNED_FIXTURE_RESPONSES_VERIFIED":
		default:
			return errors.New("unsupported fixture-response provenance")
		}
		if r.Provenance.JournalAuthentication != "UNSIGNED" || r.Provenance.ExecutionAttestation != "UNVERIFIED" {
			return errors.New("unsupported authentication claim")
		}
	} else {
		return errors.New("unsupported experiment report version")
	}
	switch r.Verdict {
	case result.Pass, result.Fail, result.Inconclusive, result.NotRun:
	default:
		return errors.New("unsupported report verdict")
	}
	switch r.Execution.Status {
	case result.Succeeded, result.Failed, result.Cancelled, result.TimedOut, result.Error, result.CleanupPending:
	default:
		return errors.New("unsupported execution status")
	}
	return nil
}
