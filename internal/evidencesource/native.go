package evidencesource

import (
	"bytes"
	"errors"
	"reflect"
	"sort"
	"strings"
	"time"

	adapter "github.com/tamen25/themis/internal/dependencyexperiment"
	wire "github.com/tamen25/themis/internal/dependencyhttp"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/pkg/evidence"
	obs "github.com/tamen25/themis/pkg/nativeobservation"
)

const NativeResultVersion = "themis.native-public-result/v1alpha1"
const NativeReconciliationVersion = "themis.native-public-reconciliation/v1alpha1"

type NativeResult struct {
	Version string          `json:"version"`
	Report  *adapter.Report `json:"report,omitempty"`
}
type NativeReconciliation struct {
	Version  string            `json:"version"`
	Receipts []adapter.Receipt `json:"receipts"`
}
type NativeRunnerStatements struct {
	Version string               `json:"version"`
	Intent  obs.RunnerStatement  `json:"intent"`
	Final   *obs.RunnerStatement `json:"final,omitempty"`
}

func nativeInventory() []evidence.Artifact {
	files := []evidence.Artifact{
		{Path: "artifacts/native-plan.json", Role: "source-plan", Version: wire.PlanVersion},
		{Path: "artifacts/native-approval-reference.json", Role: "public-approval-commitment", Version: obs.ApprovalVersion},
		{Path: "artifacts/native-runner-journal.json", Role: "original-runner-journal", Version: obs.Version},
		{Path: "artifacts/native-result.json", Role: "original-source-result", Version: NativeResultVersion},
		{Path: "artifacts/native-witness-admission.json", Role: "readiness-apply-correlation", Version: obs.AdmissionVersion},
		{Path: "artifacts/native-reconciliation.json", Role: "subsequent-cleanup-receipts", Version: NativeReconciliationVersion},
		{Path: "artifacts/native-witness-registration.json", Role: "native-witness-registration", Version: obs.RegistrationVersion},
		{Path: "artifacts/native-witness-journal.json", Role: "native-witness-observations", Version: obs.Version},
		{Path: "artifacts/native-runner-statements.json", Role: "original-runner-assertion-signatures", Version: obs.RunnerStatementVersion},
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files
}

type nativeSource struct {
	plan                                 wire.Plan
	approval                             obs.ApprovalReference
	registration                         obs.Registration
	admission                            obs.Admission
	result                               NativeResult
	statements                           NativeRunnerStatements
	events                               []adapter.Event
	rawWitness                           []byte
	complete, applied, cleaned, identity bool
	signatures                           int
}

func readNative(files map[string][]byte) (v nativeSource, err error) {
	decode := func(path string, out any) error {
		if b, ok := files[path]; !ok {
			return errors.New("missing native mapping artifact")
		} else {
			if path == "artifacts/native-plan.json" || path == "artifacts/native-approval-reference.json" || path == "artifacts/native-witness-registration.json" || path == "artifacts/native-witness-admission.json" {
				return obs.Decode(b, out)
			}
			return localstate.Unmarshal(b, out)
		}
	}
	if decode("artifacts/native-plan.json", &v.plan) != nil || !v.plan.Valid() || decode("artifacts/native-approval-reference.json", &v.approval) != nil || v.approval.Validate() != nil || !reflect.DeepEqual(v.plan, v.approval.Plan) || decode("artifacts/native-witness-registration.json", &v.registration) != nil || v.registration.Validate() != nil || !reflect.DeepEqual(v.approval, v.registration.Approval) || decode("artifacts/native-witness-admission.json", &v.admission) != nil || v.admission.Version != obs.AdmissionVersion || v.admission.RegistrationDigest != obs.RegistrationDigest(v.registration) || v.admission.ApprovalDigest != v.approval.ApprovalDigest {
		return v, errors.New("native plan/approval/registration/admission mismatch")
	}
	if decode("artifacts/native-runner-statements.json", &v.statements) != nil || v.statements.Version != obs.RunnerStatementVersion || v.statements.Intent.Kind != "INTENT" || v.statements.Intent.Validate(v.approval) != nil || v.admission.IntentDigest != wire.Hash(v.statements.Intent) {
		return v, errors.New("invalid original runner intent signature or binding")
	}
	raw, e := obs.DecodeJournal(files["artifacts/native-runner-journal.json"])
	if e != nil {
		return v, e
	}
	// Original runner records are strictly ordered. A prefix is retained without
	// synthesizing a result or interpreting a later reconciliation as history.
	lines := bytes.Split(raw, []byte{'\n'})
	torn := raw[len(raw)-1] != '\n'
	lines = lines[:len(lines)-1]
	if len(lines) == 0 || len(lines) > 64 {
		return v, errors.New("native runner journal bound")
	}
	previous := ""
	for i, line := range lines {
		var event adapter.Event
		if wire.Decode(line, &event) != nil {
			return v, errors.New("invalid native runner record")
		}
		h := event.Hash
		event.Hash = ""
		if event.Version != "themis.native-http-report/v1alpha1" || event.Sequence != i || event.Previous != previous || event.PlanDigest != v.plan.Digest() || event.Invocation != v.approval.Invocation || wire.Hash(event) != h {
			return v, errors.New("native runner chain or invocation mismatch")
		}
		event.Hash = h
		valid := false
		switch i {
		case 0:
			valid = event.Kind == "CLAIMED" && event.Reply == nil
		case 1:
			valid = event.Kind == "APPLY_INTENT" && event.Reply == nil
		case 2:
			valid = event.Kind == "APPLIED" || event.Kind == "APPLY_UNCERTAIN"
		case 3:
			valid = event.Kind == "CLEANUP_CONFIRMED" || event.Kind == "CLEANUP_PENDING"
		case 4:
			valid = (event.Kind == "IDENTITY_CONFIRMED" || event.Kind == "IDENTITY_UNCERTAIN") && event.Reply == nil
			v.identity = event.Kind == "IDENTITY_CONFIRMED"
		case 5:
			valid = event.Kind == "FINAL" && event.Reply == nil
		}
		if !valid {
			return v, errors.New("forged native source phase order")
		}
		if event.Reply != nil && event.Reply.Version != "" {
			r := event.Reply
			if !r.Verified(v.plan.Binding.Target.Proxy.Process, r.Nonce, "control") || r.PlanDigest != v.plan.Digest() || r.State.ApplyCount > 1 {
				if event.Kind == "APPLY_UNCERTAIN" || event.Kind == "CLEANUP_PENDING" {
					// An unexpected replacement's response is preserved as unsigned
					// runner diagnostics. It proves neither Apply nor cleanup.
					previous = h
					v.events = append(v.events, event)
					continue
				}
				return v, errors.New("invalid signed native control response")
			}
			v.signatures++
			if i == 2 && (r.Action != "apply" || r.Nonce != v.admission.ApplyNonce) {
				return v, errors.New("Apply receipt does not commit to witness readiness")
			}
			if i == 3 && r.Action != "remove" {
				return v, errors.New("invalid native cleanup action")
			}
			if r.Code == 200 && r.State.Invocation != v.approval.Invocation {
				return v, errors.New("native control invocation mismatch")
			}
			if event.Kind == "APPLIED" {
				if r.Code != 200 || !r.State.Applied || !r.State.Active || r.State.Fenced || r.State.ApplyCount != 1 || r.State.StartedNS < 0 || r.State.DeadlineNS <= r.State.StartedNS || r.State.DeadlineNS-r.State.StartedNS > int64(v.plan.LifetimeMS)*int64(time.Millisecond) {
					return v, errors.New("unsupported applied native receipt")
				}
				v.applied = true
			}
			if event.Kind == "CLEANUP_CONFIRMED" {
				if r.Code != 200 || r.State.Active || !r.State.Fenced {
					return v, errors.New("fabricated native cleanup")
				}
				v.cleaned = true
			}
		} else if event.Kind == "APPLIED" || event.Kind == "CLEANUP_CONFIRMED" {
			return v, errors.New("missing signed native control receipt")
		}
		previous = h
		v.events = append(v.events, event)
	}
	v.complete = !torn && len(v.events) == 6 && v.events[5].Kind == "FINAL"
	if decode("artifacts/native-result.json", &v.result) != nil || v.result.Version != NativeResultVersion {
		return v, errors.New("invalid original native result wrapper")
	}
	if v.result.Report == nil {
		if v.complete {
			return v, errors.New("completed native result missing")
		}
	} else {
		r := v.result.Report
		if r.Version != "themis.native-http-report/v1alpha1" || !reflect.DeepEqual(r.Plan, v.plan) || r.PlanDigest != v.plan.Digest() || r.Invocation != v.approval.Invocation || r.ApprovalDigest != v.approval.ApprovalDigest || !reflect.DeepEqual(r.Events, v.events) || r.ExecutionAttestation != "NOT_INDEPENDENTLY_ATTESTED" || r.TrustedExecutionVerdict != "INCONCLUSIVE" {
			return v, errors.New("native result/identity/history mismatch")
		}
		if v.complete {
			if _, e = adapter.Replay(*r); e != nil {
				return v, e
			}
		} else if r.Execution != "CANCELLED" || r.Verdict != "INCONCLUSIVE" || v.applied || v.cleaned {
			return v, errors.New("historical native success invented from a prefix")
		}
	}
	if v.statements.Final != nil {
		s := v.statements.Final
		if v.result.Report == nil || s.Kind != "FINAL" || s.Validate(v.approval) != nil || s.Key != v.statements.Intent.Key || s.ReadyCommitment != v.statements.Intent.ReadyCommitment || s.IntentDigest != wire.Hash(v.statements.Intent) || s.JournalDigest != evidence.Hash(raw) || s.ReportDigest != evidence.Hash(wire.JSON(v.result.Report)) || s.Execution != v.result.Report.Execution || s.Candidate != v.result.Report.Verdict || s.Cleanup != v.result.Report.Cleanup {
			return v, errors.New("original runner final assertion signature or result commitment mismatch")
		}
	}
	v.rawWitness, e = obs.DecodeJournal(files["artifacts/native-witness-journal.json"])
	if e != nil {
		return v, e
	}
	f, records := obs.Analyze(v.registration, v.rawWitness, nil, evidence.Publisher{}, time.Time{})
	if f.SignatureChain != "VALID" || f.Status == "OBSERVATIONS_CONTRADICTORY" {
		return v, errors.New("invalid signed native witness evidence")
	}
	readyFound := false
	for _, record := range records {
		if record.Type == "READY" && v.statements.Intent.ReadyCommitment == obs.ApplyNonce(v.registration, record) && reflect.DeepEqual(v.admission, obs.BindIntent(obs.NewAdmission(v.registration, record), v.statements.Intent)) {
			readyFound = true
		}
	}
	if !readyFound {
		return v, errors.New("missing authenticated pre-Apply witness readiness")
	}
	var reconciliation NativeReconciliation
	if decode("artifacts/native-reconciliation.json", &reconciliation) != nil || reconciliation.Version != NativeReconciliationVersion || reconciliation.Receipts == nil || len(reconciliation.Receipts) > 8 {
		return v, errors.New("invalid native reconciliation wrapper")
	}
	for _, r := range reconciliation.Receipts {
		if r.Version != "themis.native-http-reconciliation/v1alpha1" || r.PlanDigest != v.plan.Digest() || r.Invocation != v.approval.Invocation || !r.HistoricalBytesUnchanged {
			return v, errors.New("reconciliation target/history mismatch")
		}
		if r.Cleanup == "COMPLETE" && (r.Reply == nil || !r.Reply.Verified(v.plan.Binding.Target.Proxy.Process, r.Reply.Nonce, "control") || r.Reply.Code != 200 || r.Reply.Action != "remove" || r.Reply.PlanDigest != v.plan.Digest() || r.Reply.State.Invocation != v.approval.Invocation || r.Reply.State.Active || !r.Reply.State.Fenced) {
			return v, errors.New("invalid subsequent original-actuator cleanup")
		}
	}
	return v, nil
}
func describeNative(files map[string][]byte) (s evidence.Source, c evidence.SourceChecks, err error) {
	s = evidence.Source{Engine: obs.Engine, Mapping: obs.Engine + "/v1", Experiment: "native-http-dependency-latency", Provenance: "RETROSPECTIVE_PUBLICATION", Missing: []string{}, Unsupported: []string{"trusted-global-clock", "whole-execution-attestation"}}
	c = evidence.SourceChecks{Status: "FAILED", RecomputedCandidate: "INCONCLUSIVE", Checks: []string{}, Problems: []string{}}
	v, e := readNative(files)
	if e != nil {
		return s, c, e
	}
	p := v.plan
	s.RunID = p.Run
	s.PlanDigest = strings.TrimPrefix(p.Digest(), "sha256:")
	s.ContractDigest = evidence.Hash(wire.JSON(struct {
		Version                     string
		MaxApplicationMS, RequestMS int
	}{"themis.native-application-contract/v1alpha1", p.MaxApplicationMS, p.RequestMS}))
	s.ExecutionPlan = s.PlanDigest
	s.InvocationID = v.approval.Invocation
	s.Versions = []string{wire.Version, wire.PlanVersion, wire.BindingVersion, obs.Version, obs.RegistrationVersion, obs.ApprovalVersion, obs.AdmissionVersion, NativeResultVersion, NativeReconciliationVersion}
	s.Versions = append(s.Versions, wire.AuthorityReceiptVersion, "themis.native-http-report/v1alpha1", "themis.native-http-observations/v1alpha1")
	s.Versions = append(s.Versions, obs.RunnerStatementVersion)
	sort.Strings(s.Versions)
	s.CandidateVerdict = "INCONCLUSIVE"
	s.Execution = "INTERRUPTED"
	s.Cleanup = "UNKNOWN"
	if v.result.Report != nil {
		r := v.result.Report
		s.CandidateVerdict = r.Verdict
		s.Execution = r.Execution
		s.Cleanup = r.Cleanup
		c.RecomputedCandidate = r.Verdict
	} else {
		s.Missing = append(s.Missing, "completed-runner-result")
	}
	if !v.complete {
		s.Missing = append(s.Missing, "terminal-runner-history")
	}
	if v.statements.Final == nil {
		s.Missing = append(s.Missing, "signed-runner-final-assertion")
	}
	sort.Strings(s.Missing)
	f, _ := obs.Analyze(v.registration, v.rawWitness, nil, evidence.Publisher{}, time.Time{})
	c.Complete = v.complete && v.result.Report != nil && v.statements.Final != nil && f.Complete && f.AuthorityCorrelation == "MATCHED"
	c.Status = "PASSED"
	if !c.Complete {
		c.Status = "INCOMPLETE"
	}
	c.VerifiedObservationSignatures = v.signatures
	c.Checks = []string{"native-plan-installer-and-public-approver-signatures", "original-runner-chain-and-strict-phase-order", "proxy-Apply-signature-commits-to-signed-live-readiness-and-runner-intent", "original-runner-final-assertion-signature-where-completed", "native-run-invocation-original-target-and-boot-bindings", "original-source-predicates-recomputed", "separate-native-witness-signatures-and-nonce-clock-bounds", "actual-actuator-grant-and-authority-key-commitments", "original-cleanup-kept-separate-from-later-reconciliation"}
	return s, c, nil
}
func nativePublisherSeparated(o *evidence.Opened) bool {
	var reg obs.Registration
	if localstate.Unmarshal(o.Artifacts["artifacts/native-witness-registration.json"], &reg) != nil {
		return false
	}
	keys := append(obs.SourceKeys(reg.Approval.Plan), reg.KeyID, reg.Approval.ApplyKeyID, reg.Approval.CleanupKeyID)
	for _, key := range keys {
		if key == o.Manifest.Publisher.KeyID {
			return false
		}
	}
	return true
}

// CorroborateNative applies externally supplied exact-session witness trust.
// It preserves original source, cancellation and cleanup classifications.
func CorroborateNative(o evidence.Opened, policy *obs.Policy, now time.Time) obs.Finding {
	f := obs.NewFinding()
	if o.Manifest.Source.Engine != obs.Engine || o.Manifest.Source.Mapping != obs.Engine+"/v1" || o.Result.SourceChecks.Status == "UNSUPPORTED" {
		f.Status = "UNSUPPORTED_SOURCE"
		return f
	}
	var reg obs.Registration
	if localstate.Unmarshal(o.Artifacts["artifacts/native-witness-registration.json"], &reg) != nil {
		f.Problems = append(f.Problems, "INVALID_NATIVE_REGISTRATION")
		return f
	}
	raw, e := obs.DecodeJournal(o.Artifacts["artifacts/native-witness-journal.json"])
	if e != nil {
		f.Problems = append(f.Problems, "MISSING_NATIVE_WITNESS_JOURNAL")
		return f
	}
	var records []obs.Record
	f, records = obs.Analyze(reg, raw, policy, o.Manifest.Publisher, now)
	f.OriginalCandidate = o.Manifest.Source.CandidateVerdict
	f.OriginalCleanup = o.Manifest.Source.Cleanup
	if f.Status == "WITNESS_SIGNATURE_INVALID" || f.WitnessTrust != "TRUSTED" || f.Status == "OBSERVATIONS_CONTRADICTORY" {
		return f
	}
	if !nativePublisherSeparated(&o) {
		f.Status = "WITNESS_IDENTITY_UNTRUSTED"
		f.Problems = append(f.Problems, "PUBLISHER_REUSES_NATIVE_AUTHORITY")
		return f
	}
	v, e := readNative(o.Artifacts)
	if e != nil || o.Result.SourceChecks.Status == "FAILED" {
		f.Status = "OBSERVATIONS_CONTRADICTORY"
		f.RunnerCorrelation = "INVALID"
		f.Problems = append(f.Problems, "ORIGINAL_SOURCE_BINDINGS_OR_CLAIMS_CONTRADICT_WITNESS")
		return f
	}
	// Independent source and witness requests must never reuse response nonces.
	runnerNonces := map[string]bool{}
	if v.result.Report != nil {
		for _, record := range v.result.Report.Observations.Records {
			for _, probe := range record.Probes {
				runnerNonces[probe.Nonce] = true
			}
		}
	}
	for _, record := range records {
		for _, probe := range record.Probes {
			if runnerNonces[probe.Nonce] {
				f.Status = "OBSERVATIONS_CONTRADICTORY"
				f.RunnerCorrelation = "INVALID"
				f.Problems = append(f.Problems, "SOURCE_RESPONSE_REUSED_AS_WITNESS")
				return f
			}
			if v.applied {
				original := v.events[2].Reply.State
				var state *wire.State
				if probe.Authority != nil && probe.Authority.Code == 200 && probe.Authority.State.Applied {
					state = &probe.Authority.State
				}
				if probe.Kind == "proxy" && probe.Response != nil && probe.Response.State.Active {
					state = &probe.Response.State
				}
				if state != nil && (state.StartedNS != original.StartedNS || state.DeadlineNS != original.DeadlineNS || state.ApplyCount != original.ApplyCount) {
					f.Status = "OBSERVATIONS_CONTRADICTORY"
					f.RunnerCorrelation = "INVALID"
					f.Problems = append(f.Problems, "ACTUATOR_RECEIPT_AND_WITNESS_EPOCH_DIFFER")
					return f
				}
			}
		}
	}
	f.RunnerCorrelation = "MATCHED"
	if v.result.Report != nil && f.Complete {
		r := v.result.Report
		if (r.Evaluation.Effects >= 3) != (f.Effects >= 3) || r.Verdict == "PASS" && f.ApplicationVerdict == "FAIL" || r.Verdict == "FAIL" && f.ApplicationVerdict == "PASS" {
			f.Status = "OBSERVATIONS_CONTRADICTORY"
			f.RunnerCorrelation = "INVALID"
			f.Problems = append(f.Problems, "SOURCE_WITNESS_EFFECT_OR_APPLICATION_DISAGREEMENT")
			return f
		}
	}
	if o.Result.SourceChecks.Status != "PASSED" || !v.complete || v.result.Report == nil || v.statements.Final == nil || !v.applied || !v.cleaned || !v.identity || o.Manifest.Source.Execution != "SUCCEEDED" || o.Manifest.Source.Cleanup != "COMPLETE" || o.Manifest.Source.CandidateVerdict == "INCONCLUSIVE" || !f.Complete || f.AuthorityCorrelation != "MATCHED" {
		f.Status = "OBSERVATIONS_INCOMPLETE"
		f.Problems = append(f.Problems, "ORIGINAL_INTERRUPTION_IDENTITY_OR_CLEANUP_UNCERTAINTY_PRESERVED")
	}
	return f
}
