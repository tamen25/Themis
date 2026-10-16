package kubeexperiment

import (
	"encoding/hex"
	"strconv"
	"time"

	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/result"
)

const VerificationVersion = "themis.kubernetes-evidence-verification/v1alpha1"

type EvidenceVerification struct {
	Version                  string         `json:"version"`
	JournalVersion           string         `json:"journalVersion"`
	PlanDigest               string         `json:"planDigest"`
	InvocationID             string         `json:"invocationID"`
	JournalIntegrity         string         `json:"journalIntegrity"`
	JournalComplete          bool           `json:"journalComplete"`
	BindingsValid            bool           `json:"bindingsValid"`
	ExpectedDigestMatched    *bool          `json:"expectedDigestMatched,omitempty"`
	VerifiedDataSignatures   int            `json:"verifiedDataSignatures"`
	InvalidDataSignatures    int            `json:"invalidDataSignatures"`
	VerifiedStatusSignatures int            `json:"verifiedStatusSignatures"`
	MissingMeasurements      int            `json:"missingMeasurements"`
	CandidateVerdict         result.Verdict `json:"candidateVerdict"`
	TrustedExecutionVerdict  result.Verdict `json:"trustedExecutionVerdict"`
	CredibleSignedFailure    bool           `json:"credibleSignedFailure"`
	Provenance               Provenance     `json:"provenance"`
	Report                   Report         `json:"assessment"`
	Problems                 []string       `json:"problems"`
	Limitations              []string       `json:"limitations"`
}

// VerifyEvidence reuses the live pure evaluator. It verifies signatures against
// the frozen embedded fixture key, not an independent trust store or attestation.
func VerifyEvidence(path, expectedDigest string) (EvidenceVerification, error) {
	r := EvidenceVerification{Version: VerificationVersion, JournalIntegrity: "INVALID", TrustedExecutionVerdict: result.Inconclusive, CandidateVerdict: result.Inconclusive,
		Problems: []string{}, Limitations: []string{"Journal, authorization summary, phase assignment and client timing are unsigned claims.", "Fixture signatures are checked against the embedded plan key; that key and execution authorization are not independently attested.", "Individual signed fixture responses do not authenticate the historical evidence bundle or establish a trusted execution PASS."}}
	events, err := ReadJournal(path)
	if err != nil {
		return r, err
	}
	r.JournalIntegrity, r.JournalVersion = "VALID_UNSIGNED_HASH_CHAIN", events[0].Version
	r.PlanDigest, r.InvocationID = events[0].Plan.Digest(), events[0].Authorization.InvocationID
	r.JournalComplete = events[len(events)-1].Type == "FINAL"
	r.Problems = evidenceProblems(events)
	if expectedDigest != "" {
		matched := expectedDigest == r.PlanDigest
		r.ExpectedDigestMatched = &matched
		if !matched {
			r.Problems = append(r.Problems, "external expected plan digest does not match")
		}
	}
	r.BindingsValid = len(r.Problems) == 0
	if !r.JournalComplete {
		r.Problems = append(r.Problems, "historical execution has no final record")
	}
	for _, e := range events {
		if e.Status != nil && kubefault.VerifyStatus(*e.Status, events[0].Plan.Target.Fixture) {
			r.VerifiedStatusSignatures++
		}
		if e.Observation != nil {
			for _, p := range e.Observation.Probes {
				if p.Response != nil {
					if kubefault.VerifyData(*p.Response, events[0].Plan.Target.Fixture, e.Observation.RequestID, p.Kind, p.HTTPCode) {
						r.VerifiedDataSignatures++
					} else {
						r.InvalidDataSignatures++
					}
				}
			}
		}
	}
	r.Report = assess(events, false)
	r.MissingMeasurements = 9*r.Report.Plan.Contract.Samples - r.VerifiedDataSignatures - r.InvalidDataSignatures
	if r.MissingMeasurements < 0 {
		r.MissingMeasurements = 0
	}
	if r.MissingMeasurements != 0 {
		r.Problems = append(r.Problems, "missing trustworthy observations; consult coverage and assertion results")
	}
	r.CandidateVerdict = r.Report.CandidateVerdict
	if !r.BindingsValid && r.CandidateVerdict != result.Fail {
		r.CandidateVerdict = result.Inconclusive
	}
	// A credible scoped signed failure remains useful; a PASS needs authenticated
	// execution provenance unavailable in this unsigned format.
	r.CredibleSignedFailure = r.Report.Verdict == result.Fail
	r.Provenance = r.Report.Provenance
	return r, nil
}

func validID(id string) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == id
}

// These checks supplement corruption detection. Missing observations remain an
// assessment/coverage issue, while contradictory bindings or transitions fail
// structural verification. No second assertion evaluator is introduced.
func evidenceProblems(events []Event) []string {
	problems := []string{}
	if len(events) == 0 || events[0].Plan == nil || events[0].Authorization == nil {
		return []string{"missing start bindings"}
	}
	p, a := *events[0].Plan, *events[0].Authorization
	if p.Validate() != nil || a.Version != kubefault.GrantVersion || a.PlanDigest != p.Digest() || a.Actor != p.Operator || !validID(a.InvocationID) || a.IssuedAt.IsZero() || a.ApplyBefore.Sub(a.IssuedAt) != 20*time.Second || a.CleanupBefore.Sub(a.IssuedAt) != 90*time.Second {
		problems = append(problems, "invalid plan or authorization summary binding")
	}
	phase := ""
	intent, applied, removed, aborted, cancelled, final := false, false, false, false, false, false
	requests, nonces := map[string]bool{}, map[string]bool{}
	indices := map[string]map[int]bool{}
	for i, e := range events {
		bad := final || i > 0 && e.AtNS < events[i-1].AtNS
		if e.Type != "START" && (e.Plan != nil || e.Authorization != nil) {
			bad = true
		}
		if e.Type != "OBSERVATION" && e.Observation != nil || e.Type != "APPLIED" && e.Type != "REMOVED" && e.Status != nil || e.Type != "ABORT" && e.Attempted != nil || e.Type != "FINAL" && e.Execution != "" || e.Type != "CANCEL_ACCEPTED" && e.ActionID != "" {
			bad = true
		}
		switch e.Type {
		case "START":
			bad = bad || i != 0
		case "BASELINE":
			bad = bad || phase != ""
			phase = "baseline"
		case "INTENT":
			bad = bad || intent || phase != "baseline" || aborted
			intent = true
			phase = "intent"
		case "APPLIED":
			bad = bad || !intent || applied || phase != "intent" || aborted
			applied, phase = true, "applied"
		case "INTERVENTION":
			bad = bad || !applied || phase != "applied" || aborted
			phase = "intervention"
		case "REMOVED":
			bad = bad || removed || phase == "recovery"
			removed, phase = true, "removed"
		case "RECOVERY":
			bad = bad || !removed || phase != "removed" || aborted
			phase = "recovery"
		case "OBSERVATION":
			o := e.Observation
			if o == nil {
				bad = true
				break
			}
			if indices[phase] == nil {
				indices[phase] = map[int]bool{}
			}
			bad = bad || (phase != "baseline" && phase != "intervention" && phase != "recovery") || o.Phase != phase || o.Index < 0 || o.Index >= p.Contract.Samples || indices[phase][o.Index] || !validID(o.RequestID) || requests[o.RequestID] || len(o.Probes) != 3
			indices[phase][o.Index], requests[o.RequestID] = true, true
			for k, q := range o.Probes {
				if k >= 3 {
					bad = true
					break
				}
				kind := []string{"direct", "proxy", "application"}[k]
				if q.Kind != kind || q.StartedNS < 0 || q.CompletedNS < q.StartedNS || q.CompletedNS > e.AtNS || q.CompletedNS-q.StartedNS > int64(1500*time.Millisecond) {
					bad = true
				}
				if q.Response == nil {
					continue
				} // Missing measurement is not a signature.
				if !kubefault.VerifyData(*q.Response, p.Target.Fixture, o.RequestID, kind, q.HTTPCode) || q.Response.ProxyDelayNS < 0 {
					bad = true
				}
				invocation := ""
				if phase == "intervention" && kind != "direct" {
					invocation = a.InvocationID
				}
				if q.Response.InvocationID != invocation {
					bad = true
				}
			}
		case "ABORT":
			aborted, phase = true, "aborted"
		case "CANCEL_ACCEPTED":
			bad = bad || cancelled || !validID(e.ActionID) || e.Version != LifecycleJournalVersion
			cancelled = true
		case "FINAL":
			final = true
			switch result.ExecutionStatus(e.Execution) {
			case result.Succeeded:
				bad = bad || phase != "recovery" || aborted || cancelled
			case result.Error, result.Cancelled, result.TimedOut, result.CleanupPending:
			default:
				bad = true
			}
		default:
			bad = true
		}
		if e.Status != nil {
			s := e.Status
			if !kubefault.VerifyStatus(*s, p.Target.Fixture) || s.InvocationID != a.InvocationID || s.ApplyCount < 0 || s.ApplyCount > 1 || s.Applied != (s.ApplyCount == 1) || s.Active && !s.Applied {
				bad = true
			}
			if s.Proof != nil {
				if !validID(s.Proof.Nonce) || nonces[s.Proof.Nonce] {
					bad = true
				}
				nonces[s.Proof.Nonce] = true
			}
			if e.Type == "APPLIED" && (!s.Applied || !s.Active) || e.Type == "REMOVED" && s.Active {
				bad = true
			}
			if s.Applied && (s.AppliedAt.Before(a.IssuedAt) || !s.AppliedAt.Before(a.ApplyBefore) || !s.ExpiresAt.After(s.AppliedAt) || s.ExpiresAt.Sub(s.AppliedAt) > time.Duration(p.Fault.DurationMS)*time.Millisecond || s.ExpiresAt.After(a.ApplyBefore)) {
				bad = true
			}
		} else if e.Type == "APPLIED" || e.Type == "REMOVED" {
			bad = true
		}
		if bad {
			problems = append(problems, "invalid event fields, lifecycle, identity, signature or request correlation at "+strconv.Itoa(i))
		}
	}
	return problems
}
