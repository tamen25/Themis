package nativeobservation

import (
	"bytes"
	"time"

	wire "github.com/tamen25/themis/internal/dependencyhttp"
	"github.com/tamen25/themis/pkg/evidence"
)

type Finding struct {
	Version                 string   `json:"version"`
	Status                  string   `json:"status"`
	SignatureChain          string   `json:"signatureChain"`
	WitnessTrust            string   `json:"witnessTrust"`
	IdentityCorrelation     string   `json:"identityCorrelation"`
	RunnerCorrelation       string   `json:"runnerCorrelation"`
	EffectCorroboration     string   `json:"effectCorroboration"`
	RecoveryCorroboration   string   `json:"recoveryCorroboration"`
	ActuatorState           string   `json:"actuatorState"`
	AuthorityCorrelation    string   `json:"authorityCorrelation"`
	ControlReceipts         int      `json:"signedControlReceipts"`
	ExpiryReceipts          int      `json:"expiryReceipts"`
	Complete                bool     `json:"complete"`
	Baseline                int      `json:"baselineSamples"`
	Active                  int      `json:"activeSamples"`
	Effects                 int      `json:"effectSamples"`
	Recovery                int      `json:"recoverySamples"`
	Violations              int      `json:"violations"`
	MaxApplicationMS        float64  `json:"maxApplicationMS"`
	ApplicationVerdict      string   `json:"candidateApplicationVerdict"`
	OriginalCandidate       string   `json:"originalCandidateVerdict"`
	OriginalCleanup         string   `json:"originalCleanup"`
	ExecutionAttestation    string   `json:"executionAttestation"`
	TrustedExecutionVerdict string   `json:"trustedExecutionVerdict"`
	Problems                []string `json:"problems"`
	Limitations             []string `json:"limitations"`
}

func NewFinding() Finding {
	return Finding{
		Version: Version, Status: "OBSERVATIONS_INCOMPLETE", SignatureChain: "NOT_CHECKED", WitnessTrust: "UNTRUSTED",
		IdentityCorrelation: "NOT_CHECKED", RunnerCorrelation: "NOT_CHECKED", AuthorityCorrelation: "NOT_CHECKED",
		EffectCorroboration: "NOT_CORROBORATED", RecoveryCorroboration: "NOT_CORROBORATED", ActuatorState: "UNKNOWN",
		ApplicationVerdict: "INCONCLUSIVE", OriginalCandidate: "INCONCLUSIVE", OriginalCleanup: "UNKNOWN",
		ExecutionAttestation: "NOT_INDEPENDENTLY_ATTESTED", TrustedExecutionVerdict: "INCONCLUSIVE", Problems: []string{},
		Limitations: []string{
			"Witness signatures authenticate that signer's own measured claims, not honest infrastructure or noncollusion.",
			"Monotonic offsets are local to each witness/proxy process; UTC assertions do not provide a trusted global clock.",
			"Installer images, Downward API, local routing and shared administrator remain trusted; no hardware or independently administered machine attestation.",
			"Publication is retrospective; contemporaneous witness records cannot upgrade cancellation, original cleanup or whole-execution trust.",
		},
	}
}

type sample struct {
	valid, transition, healthy, inactive bool
	phase                                string
	appNS, proxyNS, directNS, holdNS     int64
	appCode                              int
}

func activeState(s wire.State, p wire.Plan, inv string) bool {
	return s.Invocation == inv && s.Applied && s.Active && !s.Fenced && s.ApplyCount == 1 && s.StartedNS >= 0 && s.DeadlineNS > s.StartedNS && s.DeadlineNS-s.StartedNS <= int64(p.LifetimeMS)*int64(time.Millisecond)
}
func signedValue(r *wire.Reply, identity wire.Process, nonce string) bool {
	return r != nil && r.Verified(identity, nonce, "value")
}
func classify(reg Registration, probes []Probe) sample {
	f := sample{}
	if len(probes) != 4 {
		return f
	}
	p := reg.Approval.Plan
	t := p.Binding.Target
	inv := reg.Approval.Invocation
	d, x, a, state := probes[0].Response, probes[1].Response, probes[2].Response, probes[3].Authority
	if !signedValue(d, t.Dependency.Process, probes[0].Nonce) || !signedValue(x, t.Proxy.Process, probes[1].Nonce) || !signedValue(a, t.Application.Process, probes[2].Nonce) {
		return f
	}
	if d.Code != 200 || d.Value != "synthetic-dependency-v1" || d.State.Invocation != "" || d.HoldNS != 0 || x.Dependency == nil || !signedValue(x.Dependency, t.Dependency.Process, probes[1].Nonce) || x.Dependency.Code != 200 || x.Dependency.Value != d.Value {
		return f
	}
	if a.Code == 200 && (!signedValue(a.Proxy, t.Proxy.Process, probes[2].Nonce) || a.Proxy.Code != 200 || a.Value != d.Value || !signedValue(a.Proxy.Dependency, t.Dependency.Process, probes[2].Nonce) || a.Proxy.Dependency.Code != 200 || a.Proxy.Dependency.Value != d.Value) {
		return f
	}
	f = sample{valid: true, phase: "baseline", appCode: a.Code, directNS: probes[0].CompletedNS - probes[0].StartedNS, proxyNS: probes[1].CompletedNS - probes[1].StartedNS, appNS: probes[2].CompletedNS - probes[2].StartedNS, holdNS: x.HoldNS}
	if f.holdNS < 0 || f.holdNS > f.proxyNS {
		return sample{}
	}
	if x.State.Invocation != "" {
		if x.PlanDigest != p.Digest() || !activeState(x.State, p, inv) {
			return sample{}
		}
		f.phase = "active"
	}
	if a.Proxy != nil {
		if a.Proxy.HoldNS < 0 || a.Proxy.HoldNS > f.appNS {
			return sample{}
		}
		if a.Proxy.State.Invocation != x.State.Invocation {
			f.valid = false
			f.transition = (a.Proxy.State.Invocation == "" || a.Proxy.State.Invocation == inv) && (x.State.Invocation == "" || x.State.Invocation == inv)
			return f
		}
		if a.Proxy.State.Invocation != "" && (a.Proxy.PlanDigest != p.Digest() || !activeState(a.Proxy.State, p, inv) || a.Proxy.State.StartedNS != x.State.StartedNS || a.Proxy.State.DeadlineNS != x.State.DeadlineNS) {
			return sample{}
		}
	}
	f.healthy = a.Code == 200 && x.Code == 200
	f.inactive = state != nil && state.Code == 200 && state.Verified(t.Proxy.Process, probes[3].Nonce, inv) && state.PlanDigest == p.Digest() && state.GrantDigest == reg.Approval.ApprovalDigest && state.State.Applied && state.State.ApplyCount == 1 && !state.State.Active && state.State.Invocation == inv
	return f
}

// Analyze preserves a valid signed prefix and its actual measurements. Missing
// or torn tails cannot create END, recovery, complete coverage or trusted PASS.
func Analyze(reg Registration, raw []byte, policy *Policy, publisher evidence.Publisher, now time.Time) (f Finding, records []Record) {
	f = NewFinding()
	bad := func(status, problem string) {
		f.Status = status
		f.Problems = append(f.Problems, problem)
		if status == "WITNESS_SIGNATURE_INVALID" {
			f.SignatureChain = "INVALID"
		}
	}
	if reg.Validate() != nil {
		bad("WITNESS_SIGNATURE_INVALID", "INVALID_NATIVE_REGISTRATION")
		return
	}
	if Trusted(reg, policy, publisher, now) {
		f.WitnessTrust = "TRUSTED"
	}
	if publisher.KeyID == reg.KeyID {
		bad("WITNESS_IDENTITY_UNTRUSTED", "PUBLISHER_KEY_REUSED_AS_WITNESS")
		return
	}
	if len(raw) == 0 || len(raw) > MaxJournal {
		bad("OBSERVATIONS_INCOMPLETE", "MISSING_OR_OVERSIZED_JOURNAL")
		return
	}
	torn := raw[len(raw)-1] != '\n'
	lines := bytes.Split(raw, []byte{'\n'})
	lines = lines[:len(lines)-1]
	if len(lines) > MaxRecords {
		bad("WITNESS_SIGNATURE_INVALID", "RECORD_BUDGET")
		return
	}
	previous := ""
	lastEnd := int64(0)
	lastSample := int64(-1)
	pid := 0
	seen := map[string]bool{}
	ready, active, recovered, ended, closed, unknown := false, false, false, false, false, false
	baselineMax := int64(0)
	samples := 0
	inactive := 0
	var activeStart, activeDeadline int64
	for i, line := range lines {
		var r Record
		if Decode(line, &r) != nil || !VerifyRecord(r, reg.PublicKey) {
			bad("WITNESS_SIGNATURE_INVALID", "INVALID_RECORD_ENCODING_SIGNATURE_OR_HASH")
			return
		}
		utc, e := UTC(r.UTC)
		begin, _ := UTC(reg.NotBefore)
		end, _ := UTC(reg.NotAfter)
		if i == 0 {
			pid = r.PID
		}
		if r.RegistrationDigest != RegistrationDigest(reg) || r.Session != reg.Session || r.Process != reg.Process || r.PID < 1 || r.PID != pid || r.KeyID != reg.KeyID || r.PlanDigest != reg.Approval.PlanDigest || r.Invocation != reg.Approval.Invocation || r.TargetDigest != wire.Hash(reg.Approval.Plan.Binding.Target) || r.Sequence != i || r.Previous != previous || r.StartedNS < lastEnd || r.CompletedNS < r.StartedNS || r.CompletedNS > int64(Duration+time.Second) || e != nil || utc.Before(begin) || utc.After(end) || closed {
			bad("OBSERVATIONS_CONTRADICTORY", "SESSION_IDENTITY_SEQUENCE_CLOCK_OR_CHAIN_MISMATCH")
			return
		}
		records = append(records, r)
		previous = r.Hash
		lastEnd = r.CompletedNS
		if r.Identity != "CONFIRMED" && r.Identity != "UNKNOWN" {
			bad("OBSERVATIONS_CONTRADICTORY", "INVALID_IDENTITY_DISPOSITION")
			return
		}
		if r.Identity != "CONFIRMED" {
			unknown = true
			f.Problems = append(f.Problems, "KUBERNETES_IDENTITY_UNAVAILABLE")
		}
		switch r.Type {
		case "START":
			if i != 0 || len(r.Probes) != 0 {
				bad("OBSERVATIONS_CONTRADICTORY", "INVALID_START")
				return
			}
		case "READY":
			if i == 0 || ready || active || f.Baseline < 3 || len(r.Probes) != 0 || unknown {
				bad("OBSERVATIONS_CONTRADICTORY", "LATE_OR_INVALID_READINESS")
				return
			}
			ready = true
		case "SAMPLE":
			samples++
			if i == 0 || len(r.Probes) != 4 || samples > reg.MaxSamples || lastSample >= 0 && r.StartedNS-lastSample < int64(Interval) {
				bad("OBSERVATIONS_CONTRADICTORY", "INVALID_SAMPLE_RATE_OR_COUNT")
				return
			}
			lastSample = r.StartedNS
			all := true
			for j, q := range r.Probes {
				kind := []string{"direct", "proxy", "application", "state"}[j]
				if q.Kind != kind || !id.MatchString(q.Nonce) || seen[q.Nonce] || q.StartedNS < r.StartedNS || q.CompletedNS < q.StartedNS || q.CompletedNS > r.CompletedNS || q.CompletedNS-q.StartedNS > int64(time.Second) {
					bad("OBSERVATIONS_CONTRADICTORY", "NONCE_REPLAY_OR_INVALID_PROBE_CLOCK")
					return
				}
				seen[q.Nonce] = true
				if q.Outcome == "REQUEST_FAILED" && q.Response == nil && q.Authority == nil && q.HTTPCode == 0 {
					all = false
					continue
				}
				if q.Outcome == "IDENTITY_MISMATCH" {
					all = false
					continue
				}
				if j == 3 {
					a := q.Authority
					if q.Outcome != "MEASURED" || q.Response != nil || a == nil || q.HTTPCode != a.Code || !a.Verified(reg.Approval.Plan.Binding.Target.Proxy.Process, q.Nonce, reg.Approval.Invocation) {
						bad("OBSERVATIONS_CONTRADICTORY", "INVALID_ACTUATOR_AUTHORITY_RECEIPT")
						return
					}
					if a.Code == 404 {
						if active || a.PlanDigest != "" || a.GrantDigest != "" || a.ApplyKeyID != "" || a.CleanupKeyID != "" || a.State != (wire.State{}) {
							bad("OBSERVATIONS_CONTRADICTORY", "ACTUATOR_AUTHORITY_HISTORY_MISSING_OR_FORGED")
							return
						}
					} else {
						ref := reg.Approval
						if (a.Code != 200 && a.Code != 503) || a.PlanDigest != ref.PlanDigest || a.GrantDigest != ref.ApprovalDigest || a.ApplyKeyID != ref.ApplyKeyID || a.CleanupKeyID != ref.CleanupKeyID {
							bad("OBSERVATIONS_CONTRADICTORY", "APPROVED_GRANT_COMMITMENT_DIFFERS_FROM_ACTUATOR")
							return
						}
						f.ControlReceipts++
						if a.Code == 200 && a.State.Applied {
							state := a.State
							p := reg.Approval.Plan
							if state.ApplyCount != 1 || state.StartedNS < 0 || state.DeadlineNS <= state.StartedNS || state.DeadlineNS-state.StartedNS > int64(p.LifetimeMS)*int64(time.Millisecond) || active && (state.StartedNS != activeStart || state.DeadlineNS != activeDeadline) {
								bad("OBSERVATIONS_CONTRADICTORY", "RETAINED_ACTUATOR_EPOCH_CHANGED")
								return
							}
						}
						if a.Code == 503 {
							all = false
						} else if a.State.Invocation != ref.Invocation || a.State.ApplyCount > 1 || a.State.ApplyCount < 0 || a.State.Active && !activeState(a.State, ref.Plan, ref.Invocation) {
							bad("OBSERVATIONS_CONTRADICTORY", "INVALID_RETAINED_ACTUATOR_STATE")
							return
						}
						if a.Code == 200 && a.State.Applied && !a.State.Active && a.State.Reason == "expired" {
							f.ExpiryReceipts++
						}
					}
					continue
				}
				identity := []wire.Process{reg.Approval.Plan.Binding.Target.Dependency.Process, reg.Approval.Plan.Binding.Target.Proxy.Process, reg.Approval.Plan.Binding.Target.Application.Process, reg.Approval.Plan.Binding.Target.Proxy.Process}[j]
				route := "value"
				if kind == "state" {
					route = "state"
				}
				if q.Outcome != "MEASURED" || q.Authority != nil || q.Response == nil || q.HTTPCode != q.Response.Code || q.HTTPCode < 200 || q.HTTPCode > 599 || !q.Response.Verified(identity, q.Nonce, route) {
					bad("OBSERVATIONS_CONTRADICTORY", "INVALID_SIGNED_RESPONSE_IDENTITY_NONCE_STATUS_OR_BODY")
					return
				}
				if j == 3 && q.HTTPCode != 200 {
					all = false
				}
			}
			// A withheld state response is cleanup uncertainty; valid data measurements
			// remain available rather than disappearing from the signed journal.
			if !all {
				unknown = true
				f.Problems = append(f.Problems, "MISSING_TIMED_OUT_OR_IDENTITY_UNCERTAIN_PROBE")
			}
			v := classify(reg, r.Probes)
			if !v.valid {
				if !v.transition {
					unknown = true
				}
				f.Problems = append(f.Problems, "INVALID_OR_TRANSITION_DATA_SAMPLE")
				continue
			}
			if float64(v.appNS)/1e6 > f.MaxApplicationMS {
				f.MaxApplicationMS = float64(v.appNS) / 1e6
			}
			p := reg.Approval.Plan
			if v.phase == "active" {
				if !ready || recovered {
					bad("OBSERVATIONS_CONTRADICTORY", "INTERVENTION_BEFORE_READINESS_OR_AFTER_RECOVERY")
					return
				}
				state := r.Probes[1].Response.State
				if active && (state.StartedNS != activeStart || state.DeadlineNS != activeDeadline) {
					bad("OBSERVATIONS_CONTRADICTORY", "ACTUATOR_DEADLINE_CHANGED")
					return
				}
				activeStart, activeDeadline = state.StartedNS, state.DeadlineNS
				active = true
				f.Active++
				delay := int64(p.DelayMS) * int64(time.Millisecond)
				if f.Baseline >= 3 && v.healthy && v.proxyNS-v.directNS >= delay*7/10 && v.holdNS >= delay*7/10 && v.appNS-baselineMax >= delay*6/10 {
					f.Effects++
				}
				if v.appCode != 200 || v.appNS > int64(p.MaxApplicationMS)*int64(time.Millisecond) {
					f.Violations++
				}
			} else if !active {
				if v.healthy && v.appNS <= int64(p.MaxApplicationMS)*int64(time.Millisecond) {
					f.Baseline++
					if v.appNS > baselineMax {
						baselineMax = v.appNS
					}
				}
			} else {
				recovered = true
				if v.healthy && v.appNS <= int64(p.MaxApplicationMS)*int64(time.Millisecond) && v.appNS <= baselineMax+int64(40*time.Millisecond) {
					f.Recovery++
				}
				if v.inactive {
					inactive++
				}
			}
		case "END", "INTERRUPTED":
			if i == 0 || len(r.Probes) != 0 {
				bad("OBSERVATIONS_CONTRADICTORY", "INVALID_TERMINAL")
				return
			}
			closed = true
			ended = r.Type == "END"
		default:
			bad("OBSERVATIONS_CONTRADICTORY", "UNKNOWN_RECORD_KIND")
			return
		}
	}
	f.SignatureChain = "VALID"
	f.AuthorityCorrelation = "NOT_OBSERVED"
	if f.ControlReceipts > 0 {
		f.AuthorityCorrelation = "MATCHED"
	}
	f.IdentityCorrelation = "MATCHED"
	if unknown {
		f.IdentityCorrelation = "UNCERTAIN"
	}
	f.Complete = ended && ready && !torn && !unknown
	if torn {
		f.Problems = append(f.Problems, "TORN_FINAL_WRITE_PRESERVED")
	}
	if !ended {
		f.Problems = append(f.Problems, "NO_COMPLETED_WITNESS_SESSION")
	}
	if f.Effects >= 3 && f.ControlReceipts > 0 {
		f.EffectCorroboration = "CORROBORATED"
	}
	if f.Recovery >= 3 {
		f.RecoveryCorroboration = "CORROBORATED"
	}
	if inactive >= 3 {
		f.ActuatorState = "ORIGINAL_INVOCATION_INACTIVE_OBSERVED"
	}
	if f.ExpiryReceipts >= 3 {
		f.ActuatorState = "ORIGINAL_INVOCATION_EXPIRY_OBSERVED"
	}
	if f.Violations > 0 && f.Active >= 3 && f.Effects >= 3 && f.ControlReceipts > 0 {
		f.ApplicationVerdict = "FAIL"
	} else if f.Complete && f.Baseline >= 3 && f.Active >= 3 && f.Effects >= 3 && f.Recovery >= 3 && inactive >= 3 && f.ControlReceipts > 0 {
		f.ApplicationVerdict = "PASS"
	}
	if f.Complete && f.ApplicationVerdict != "INCONCLUSIVE" {
		f.Status = "OBSERVATIONS_CORROBORATED"
	}
	if f.WitnessTrust != "TRUSTED" {
		if f.Effects >= 3 {
			f.EffectCorroboration = "UNTRUSTED_OBSERVATIONS"
		}
		if f.Recovery >= 3 {
			f.RecoveryCorroboration = "UNTRUSTED_OBSERVATIONS"
		}
		f.Status = "WITNESS_IDENTITY_UNTRUSTED"
	}
	return
}
