package evidencesource

import (
	"encoding/hex"
	"errors"
	"reflect"
	"sort"
	"time"

	"github.com/tamen25/themis/internal/kubeexperiment"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/pkg/evidence"
	obs "github.com/tamen25/themis/pkg/liveobservation"
)

func describeWitness(files map[string][]byte) (s evidence.Source, c evidence.SourceChecks, err error) {
	s, c, err = Describe(Kubernetes, files)
	if err != nil {
		return
	}
	s.Engine = obs.Engine
	s.Mapping = obs.Engine + "/v1"
	s.Versions = append(s.Versions, obs.Version, obs.RegistrationVersion)
	sort.Strings(s.Versions)
	for _, path := range []string{"artifacts/witness-registration.json", "artifacts/witness-journal.json"} {
		if _, ok := files[path]; !ok {
			s.Missing = append(s.Missing, path)
		}
	}
	sort.Strings(s.Missing)
	if len(s.Missing) > 0 {
		c.Complete = false
		c.Status = "INCOMPLETE"
		return
	}
	var reg obs.Registration
	if obs.Decode(files["artifacts/witness-registration.json"], &reg) != nil || reg.Validate() != nil {
		return s, c, errors.New("invalid witness registration")
	}
	var proposal kubeexperiment.CoordinationProposal
	if localstate.Unmarshal(files["artifacts/kubernetes-proposal.json"], &proposal) != nil || !reflect.DeepEqual(reg.Plan, proposal.Plan) || reg.ProposalDigest != proposal.Digest() || reg.Plan.RunUID != s.RunID || reg.InvocationID != s.InvocationID {
		return s, c, errors.New("witness plan, proposal or invocation differs from runner")
	}
	approver, _ := hex.DecodeString(proposal.ApproverKey)
	found := false
	for _, key := range reg.AuthorityKeyIDs {
		if key == evidence.Hash(approver) {
			found = true
		}
	}
	if !found {
		return s, c, errors.New("witness approval authority commitment differs")
	}
	raw, e := obs.DecodeJournalArtifact(files["artifacts/witness-journal.json"])
	if e != nil {
		return s, c, e
	}
	f, _ := obs.Analyze(reg, raw, nil, time.Time{})
	if f.SignatureChain != "VALID" || f.Status == "OBSERVATIONS_CONTRADICTORY" || f.Status == "UNSUPPORTED_SOURCE" {
		return s, c, errors.New("invalid witness chain or observation bindings")
	}
	c.Checks = append(c.Checks, "witness-registration-and-individual-signatures", "witness-session-nonce-phase-and-monotonic-bindings", "witness-coverage-independent-of-publisher-and-execution-trust")
	c.Complete = c.Complete && f.Complete
	if !c.Complete {
		c.Status = "INCOMPLETE"
	}
	return
}

// Corroborate separately applies external witness trust and correlates original
// runner evidence. It cannot mutate a source verdict or execution classification.
func Corroborate(o evidence.Opened, policy *obs.Policy, now time.Time) obs.Finding {
	f := obs.NewFinding()
	f.RunnerCorrelation = "NOT_CHECKED"
	if o.Manifest.Source.Engine != obs.Engine {
		f.Status = "UNSUPPORTED_SOURCE"
		f.Problems = append(f.Problems, "NO_LIVE_WITNESS_SOURCE_MAPPING")
		return f
	}
	var reg obs.Registration
	if obs.Decode(o.Artifacts["artifacts/witness-registration.json"], &reg) != nil {
		f.Problems = append(f.Problems, "MISSING_OR_INVALID_WITNESS_REGISTRATION")
		return f
	}
	raw, e := obs.DecodeJournalArtifact(o.Artifacts["artifacts/witness-journal.json"])
	if e != nil {
		f.Problems = append(f.Problems, "MISSING_OR_INVALID_WITNESS_JOURNAL")
		return f
	}
	var records []obs.Record
	f, records = obs.Analyze(reg, raw, policy, now)
	f.RunnerCorrelation = "NOT_CHECKED"
	if reg.KeyID == o.Manifest.Publisher.KeyID {
		f.Status = "WITNESS_IDENTITY_UNTRUSTED"
		f.WitnessTrust = "UNTRUSTED"
		f.Problems = append(f.Problems, "PUBLISHER_KEY_REUSED_AS_WITNESS")
		return f
	}
	if f.Status == "WITNESS_SIGNATURE_INVALID" || f.Status == "WITNESS_IDENTITY_UNTRUSTED" || f.Status == "UNSUPPORTED_SOURCE" {
		return f
	}
	if o.Result.SourceChecks.Status == "FAILED" {
		f.Status = "OBSERVATIONS_CONTRADICTORY"
		f.RunnerCorrelation = "INVALID"
		f.Problems = append(f.Problems, "RUNNER_OR_SOURCE_BINDINGS_INCONSISTENT")
		return f
	}
	if o.Result.SourceChecks.Status != "PASSED" {
		f.Status = "OBSERVATIONS_INCOMPLETE"
		f.RunnerCorrelation = "INCOMPLETE"
		f.Problems = append(f.Problems, "RUNNER_OR_SOURCE_EVIDENCE_INCOMPLETE")
		return f
	}
	var report kubeexperiment.Report
	if localstate.Unmarshal(o.Artifacts["artifacts/kubernetes-report.json"], &report) != nil {
		f.Status = "OBSERVATIONS_INCOMPLETE"
		f.RunnerCorrelation = "INCOMPLETE"
		return f
	}
	runnerNonces := map[string]bool{}
	for _, sample := range report.Observations {
		runnerNonces[sample.RequestID] = true
	}
	for _, record := range records {
		if record.Type == "SAMPLE" && runnerNonces[record.Nonce] {
			f.Status = "OBSERVATIONS_CONTRADICTORY"
			f.RunnerCorrelation = "INVALID"
			f.Problems = append(f.Problems, "RUNNER_RESPONSE_REUSED_AS_INDEPENDENT_WITNESS_REQUEST")
			return f
		}
	}
	if report.InterventionConfirmed != (f.EffectSamples >= 3) || report.Verdict == "PASS" && f.ApplicationFailures > 0 {
		f.Status = "OBSERVATIONS_CONTRADICTORY"
		f.RunnerCorrelation = "INVALID"
		f.Problems = append(f.Problems, "RUNNER_WITNESS_EFFECT_OR_APPLICATION_DISAGREEMENT")
		return f
	}
	f.RunnerCorrelation = "VALID"
	if report.Execution != "SUCCEEDED" && report.Execution != "FAILED" || report.Cleanup != "COMPLETE" {
		f.Status = "OBSERVATIONS_INCOMPLETE"
		f.Problems = append(f.Problems, "ORIGINAL_EXECUTION_OR_CLEANUP_UNCERTAINTY_PRESERVED")
	}
	return f
}
