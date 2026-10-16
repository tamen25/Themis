package kubeexperiment

import (
	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/result"
)

const ReportVersion = "themis.kubernetes-experiment-report/v1alpha1"

type Report struct {
	Version               string                   `json:"version"`
	Plan                  kubefault.Plan           `json:"plan"`
	PlanDigest            string                   `json:"planDigest"`
	Authorization         AuthorizationSummary     `json:"authorization"`
	Execution             result.ExecutionStatus   `json:"execution"`
	Verdict               result.Verdict           `json:"verdict"`
	CandidateVerdict      result.Verdict           `json:"candidateVerdict"`
	Authorized            bool                     `json:"authorizedExecution"`
	FaultAttempted        *bool                    `json:"faultAttempted"`
	InterventionConfirmed bool                     `json:"interventionConfirmed"`
	RecoveryVerified      bool                     `json:"recoveryVerified"`
	Cleanup               string                   `json:"cleanup"`
	Observations          []Observation            `json:"observations"`
	Assertions            []result.AssertionResult `json:"assertions"`
	Provenance            Provenance               `json:"provenance"`
	Unknowns              []string                 `json:"unknowns"`
}
type Provenance struct {
	Source               string `json:"source"`
	FixtureResponses     string `json:"fixtureResponses"`
	ClientTiming         string `json:"clientTiming"`
	Journal              string `json:"journal"`
	ExecutionAttestation string `json:"executionAttestation"`
}

func complete(p kubefault.Plan, invocation, phase string, observations []Observation) (bool, bool, int) {
	if len(observations) != p.Contract.Samples {
		return false, false, 0
	}
	good, confirmed, failed := true, 0, 0
	seen := map[string]bool{}
	for index, o := range observations {
		if o.Index != index || o.Phase != phase || o.RequestID == "" || seen[o.RequestID] || len(o.Probes) != 3 {
			return false, false, 0
		}
		seen[o.RequestID] = true
		valid := true
		for i, kind := range []string{"direct", "proxy", "application"} {
			probe := o.Probes[i]
			if probe.Kind != kind || probe.StartedNS < 0 || probe.CompletedNS < probe.StartedNS || probe.CompletedNS-probe.StartedNS > int64(1500000000) || probe.Response == nil || !kubefault.VerifyData(*probe.Response, p.Target.Fixture, o.RequestID, kind, probe.HTTPCode) {
				valid = false
				continue
			}
			if kind == "application" && phase == "intervention" && probe.Response.InvocationID != invocation {
				valid = false
				continue
			}
			if kind == "application" && probe.HTTPCode != 200 {
				failed++
			}
			if probe.HTTPCode != 200 {
				good = false
			}
			if phase != "intervention" && kind == "application" && probe.Response.Degraded {
				good = false
			}
		}
		if !valid {
			return false, false, failed
		}
		direct := o.Probes[0].CompletedNS - o.Probes[0].StartedNS
		proxy := o.Probes[1].CompletedNS - o.Probes[1].StartedNS
		delay := int64(p.Fault.DelayMS) * 1000000
		if phase == "intervention" {
			if proxy-direct >= delay*7/10 && direct < delay/2 && o.Probes[1].Response.InvocationID == invocation && o.Probes[2].Response.InvocationID == invocation {
				confirmed++
			}
		} else if proxy-direct > delay/4 || direct >= delay/2 || o.Probes[1].Response.InvocationID != "" || o.Probes[2].Response.InvocationID != "" {
			good = false
		}
	}
	return true, good && (phase != "intervention" || confirmed >= p.Contract.MinConfirmed), failed
}

func assess(events []Event, locallyAuthorized bool) Report {
	r := Report{Version: ReportVersion, Execution: result.CleanupPending, Verdict: result.Inconclusive, CandidateVerdict: result.Inconclusive, Cleanup: "UNKNOWN", Provenance: Provenance{Source: "UNSIGNED_REPLAY", FixtureResponses: "INDIVIDUALLY_VERIFIED_WHERE_PRESENT", ClientTiming: "UNAUTHENTICATED_MONOTONIC_CLIENT_TIMING", Journal: "UNSIGNED_HASH_CHAIN", ExecutionAttestation: "UNVERIFIED"}}
	if len(events) == 0 || events[0].Plan == nil || events[0].Authorization == nil {
		return r
	}
	r.Plan = *events[0].Plan
	r.PlanDigest = r.Plan.Digest()
	r.Authorization = *events[0].Authorization
	notAttempted := false
	r.FaultAttempted = &notAttempted
	r.Authorized = locallyAuthorized
	if locallyAuthorized {
		r.Provenance.Source = "LOCALLY_COLLECTED_OPERATOR_SESSION"
	}
	phases := map[string][]Observation{}
	intent, ack, removed, final, aborted := false, false, false, false, false
	phase := ""
	valid := r.Plan.Validate() == nil
	requestIDs := map[string]bool{}
	lastTime := int64(-1)
	for _, e := range events {
		if e.AtNS < lastTime {
			valid = false
		}
		lastTime = e.AtNS
		switch e.Type {
		case "START":
		case "BASELINE":
			if phase != "" {
				valid = false
			}
			phase = "baseline"
		case "INTENT":
			if phase != "baseline" || intent {
				valid = false
			}
			intent = true
			r.FaultAttempted = nil
			phase = "intent"
		case "APPLIED":
			if !intent || ack || e.Status == nil || !e.Status.Applied || !kubefault.VerifyStatus(*e.Status, r.Plan.Target.Fixture) || e.Status.InvocationID != r.Authorization.InvocationID {
				valid = false
			} else {
				ack = true
				v := true
				r.FaultAttempted = &v
			}
			phase = "applied"
		case "INTERVENTION":
			if !ack || phase != "applied" {
				valid = false
			}
			phase = "intervention"
		case "REMOVED":
			if e.Status == nil || e.Status.Active || !kubefault.VerifyStatus(*e.Status, r.Plan.Target.Fixture) || e.Status.InvocationID != r.Authorization.InvocationID {
				valid = false
			} else {
				removed = true
			}
			phase = "removed"
		case "RECOVERY":
			if !removed || phase != "removed" {
				valid = false
			}
			phase = "recovery"
		case "OBSERVATION":
			if e.Observation == nil || e.Observation.Phase != phase {
				valid = false
				continue
			}
			for _, p := range e.Observation.Probes {
				if p.CompletedNS > e.AtNS {
					valid = false
				}
			}
			if requestIDs[e.Observation.RequestID] {
				valid = false
			}
			requestIDs[e.Observation.RequestID] = true
			phases[phase] = append(phases[phase], *e.Observation)
			r.Observations = append(r.Observations, *e.Observation)
		case "ABORT":
			aborted = true
			if e.Attempted != nil {
				r.FaultAttempted = e.Attempted
			}
			phase = "aborted"
		case "FINAL":
			if final {
				valid = false
			}
			final = true
			r.Execution = result.ExecutionStatus(e.Execution)
		default:
			valid = false
		}
	}
	baseComplete, baseGood, _ := complete(r.Plan, r.Authorization.InvocationID, "baseline", phases["baseline"])
	interventionComplete, interventionGood, _ := complete(r.Plan, r.Authorization.InvocationID, "intervention", phases["intervention"])
	recoveryComplete, recoveryGood, _ := complete(r.Plan, r.Authorization.InvocationID, "recovery", phases["recovery"])
	failures := signedApplicationFailures(r.Plan, r.Authorization.InvocationID, "intervention", phases["intervention"])
	recoveryFailures := signedApplicationFailures(r.Plan, "", "recovery", phases["recovery"])
	// Application failures must not prevent independent confirmation of latency.
	r.InterventionConfirmed = interventionComplete && confirmedLatency(r.Plan, r.Authorization.InvocationID, phases["intervention"])
	r.RecoveryVerified = removed && recoveryComplete && recoveryGood
	cleanupComplete := removed && final && r.Execution != result.CleanupPending
	if cleanupComplete {
		r.Cleanup = "COMPLETE"
	} else {
		r.Cleanup = "PENDING"
		r.Execution = result.CleanupPending
	}
	add := func(id string, pass bool, fail bool) {
		a := result.AssertionResult{ID: id, Verdict: result.Inconclusive, Evidence: result.Insufficient}
		if pass {
			a.Verdict = result.Pass
			a.Evidence = result.Sufficient
		}
		if fail {
			a.Verdict = result.Fail
			a.Evidence = result.Sufficient
		}
		r.Assertions = append(r.Assertions, a)
	}
	add("baseline", baseComplete && baseGood, false)
	add("intervention", r.InterventionConfirmed, false)
	add("application", interventionComplete && interventionGood, failures > 0)
	add("recovery", r.RecoveryVerified, removed && recoveryFailures > 0)
	add("coverage", baseComplete && interventionComplete && recoveryComplete, false)
	add("cleanup", cleanupComplete, false)
	r.CandidateVerdict = result.Aggregate([]string{"baseline", "intervention", "application", "recovery", "coverage", "cleanup"}, r.Assertions, result.RunEvidence{PreconditionsMet: baseComplete && baseGood && valid && !aborted, InterventionRequired: true, InterventionObserved: r.InterventionConfirmed})
	r.Verdict = r.CandidateVerdict
	if !valid {
		r.Verdict = result.Inconclusive
		r.Unknowns = append(r.Unknowns, "invalid lifecycle or observation ordering")
	}
	if r.Verdict == result.Pass && (!locallyAuthorized || r.Execution != result.Succeeded) {
		r.Verdict = result.Inconclusive
		r.Unknowns = append(r.Unknowns, "unsigned replay cannot establish authorized execution or a trusted PASS")
	}
	if intent && !ack && r.FaultAttempted == nil {
		r.Unknowns = append(r.Unknowns, "Apply intent exists without a trusted acknowledgement; application is uncertain")
	}
	if !cleanupComplete {
		r.Unknowns = append(r.Unknowns, "cleanup is unresolved; independent in-fixture expiry still bounds the fault")
	}
	return r
}

func confirmedLatency(p kubefault.Plan, invocation string, observations []Observation) bool {
	copy := append([]Observation{}, observations...)
	// complete also evaluates application codes. Confirmation needs valid signed
	// probes and paired timings, independently of application success.
	if len(copy) != p.Contract.Samples {
		return false
	}
	confirmed := 0
	for index, o := range copy {
		if o.Index != index || len(o.Probes) != 3 {
			return false
		}
		for i, kind := range []string{"direct", "proxy", "application"} {
			q := o.Probes[i]
			if q.Response == nil || q.Kind != kind || !kubefault.VerifyData(*q.Response, p.Target.Fixture, o.RequestID, kind, q.HTTPCode) || q.CompletedNS < q.StartedNS {
				return false
			}
		}
		direct := o.Probes[0].CompletedNS - o.Probes[0].StartedNS
		proxy := o.Probes[1].CompletedNS - o.Probes[1].StartedNS
		delay := int64(p.Fault.DelayMS) * 1000000
		if o.Probes[0].HTTPCode == 200 && o.Probes[1].HTTPCode == 200 && o.Probes[1].Response.ProxyDelayNS >= delay*7/10 && proxy-direct >= delay*7/10 && direct < delay/2 && o.Probes[1].Response.InvocationID == invocation && o.Probes[2].Response.InvocationID == invocation {
			confirmed++
		}
	}
	return confirmed >= p.Contract.MinConfirmed
}

// The v1 contract's exact maximum error fraction is zero. One scoped signed
// application failure is already a strict lower bound above zero, even if other
// requests or slots are missing. Coverage cannot hide a trustworthy failure.
func signedApplicationFailures(p kubefault.Plan, invocation, phase string, observations []Observation) int {
	failed := 0
	seen := map[int]bool{}
	for _, o := range observations {
		if o.Phase != phase || o.Index < 0 || o.Index >= p.Contract.Samples || seen[o.Index] || o.RequestID == "" {
			continue
		}
		seen[o.Index] = true
		for _, q := range o.Probes {
			if q.Kind == "application" && q.StartedNS >= 0 && q.CompletedNS >= q.StartedNS && q.CompletedNS-q.StartedNS <= 1500000000 && q.Response != nil && q.Response.InvocationID == invocation && q.HTTPCode != 200 && kubefault.VerifyData(*q.Response, p.Target.Fixture, o.RequestID, "application", q.HTTPCode) {
				failed++
				break
			}
		}
	}
	return failed
}

func Replay(path string) (Report, error) {
	events, err := ReadJournal(path)
	if err != nil {
		return Report{}, err
	}
	return assess(events, false), nil
}
