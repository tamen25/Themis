package liveobservation

import (
	"bytes"
	"encoding/hex"
	"time"

	"github.com/tamen25/themis/internal/kubefault"
)

func NewFinding() Finding {
	return Finding{Version: Version, Status: "OBSERVATIONS_INCOMPLETE", WitnessTrust: "UNTRUSTED", SignatureChain: "NOT_CHECKED", RunnerCorrelation: "NOT_CHECKED", ApplicationVerdict: "INCONCLUSIVE", Problems: []string{}, Limitations: []string{"Trusted witness key authenticates its own observations, not honest infrastructure or absence of collusion.", "UTC is an untrusted witness clock assertion; monotonic offsets have only session-local meaning.", "Same host and administrator may control runner, fixture, witness and publisher; no physical or Byzantine independence.", "Correlated application observations never authorize trusted execution PASS or erase cleanup uncertainty."}}
}

// Phase uses authenticated response invocation identity rather than the runner's
// clock or an unauthenticated phase label. Transitions are never counted.
func Phase(p []Probe, r Registration, active bool) string {
	if len(p) != 3 || p[0].Response == nil || p[1].Response == nil || p[2].Response == nil {
		return "unknown"
	}
	proxy, app := p[1].Response.InvocationID, p[2].Response.InvocationID
	if proxy == r.InvocationID && app == r.InvocationID {
		return "intervention"
	}
	if proxy == "" && app == "" {
		if active {
			return "recovery"
		}
		return "baseline"
	}
	return "transition"
}

// Analyze verifies bounded public bytes without filesystem or infrastructure I/O.
// A torn final record preserves the valid signed prefix but never completeness.
func Analyze(reg Registration, data []byte, policy *Policy, now time.Time) (f Finding, records []Record) {
	f = NewFinding()
	bad := func(status, problem string) {
		f.Status = status
		f.Problems = append(f.Problems, problem)
		if status == "WITNESS_SIGNATURE_INVALID" {
			f.SignatureChain = "INVALID"
		}
	}
	if reg.Validate() != nil {
		bad("WITNESS_SIGNATURE_INVALID", "INVALID_REGISTRATION")
		return
	}
	if Trusted(reg, policy, now) {
		f.WitnessTrust = "TRUSTED"
	}
	fixtureKey, _ := hex.DecodeString(reg.Plan.Target.Fixture.EvidenceKey)
	if bytes.Equal(fixtureKey, reg.PublicKey) {
		bad("WITNESS_IDENTITY_UNTRUSTED", "FIXTURE_KEY_REUSED_AS_WITNESS")
		return
	}
	if len(data) == 0 || len(data) > MaxJournal {
		bad("OBSERVATIONS_INCOMPLETE", "MISSING_OR_OVERSIZED_JOURNAL")
		return
	}
	torn := data[len(data)-1] != '\n'
	lines := bytes.Split(data, []byte{'\n'})
	lines = lines[:len(lines)-1]
	if len(lines) > MaxRecords {
		bad("WITNESS_SIGNATURE_INVALID", "RECORD_BUDGET_EXCEEDED")
		return
	}
	previous := ""
	process := ""
	pid := 0
	lastEnd := int64(0)
	lastSample := int64(-1)
	seen := map[string]bool{}
	active, recovered, ready, ended, closed := false, false, false, false, false
	count := 0
	for i, line := range lines {
		var r Record
		if Decode(line, &r) != nil {
			bad("WITNESS_SIGNATURE_INVALID", "MALFORMED_WITNESS_RECORD")
			return
		}
		if r.Version != Version || r.Domain != Domain {
			bad("UNSUPPORTED_SOURCE", "UNSUPPORTED_WITNESS_VERSION_OR_DOMAIN")
			return
		}
		if !VerifyRecord(r, reg.PublicKey) {
			bad("WITNESS_SIGNATURE_INVALID", "INVALID_WITNESS_SIGNATURE_OR_HASH")
			return
		}
		records = append(records, r)
		utc, clockErr := UTC(r.UTC)
		before, _ := UTC(reg.NotBefore)
		after, _ := UTC(reg.NotAfter)
		if i == 0 {
			process = r.Process
			pid = r.PID
		}
		if r.Witness != reg.Witness || r.KeyID != reg.KeyID || r.Session != reg.Session || r.Process != process || !hexID.MatchString(r.Process) || pid < 1 || r.PID != pid || r.RegistrationDigest != RegistrationDigest(reg) || r.RunID != reg.Plan.RunUID || r.PlanDigest != reg.Plan.Digest() || r.InvocationID != reg.InvocationID || r.Target != reg.Plan.Target.Fixture || r.Sequence != i || r.Previous != previous || !hexID.MatchString(r.Nonce) || seen[r.Nonce] || r.StartedNS < lastEnd || r.CompletedNS < r.StartedNS || r.CompletedNS > int64(MaxDuration)+int64(time.Second) || clockErr != nil || utc.Before(before) || utc.After(after) || closed {
			bad("OBSERVATIONS_CONTRADICTORY", "SESSION_SEQUENCE_IDENTITY_CLOCK_OR_CHAIN_MISMATCH")
			return
		}
		previous = r.Hash
		lastEnd = r.CompletedNS
		seen[r.Nonce] = true
		switch r.Type {
		case "START":
			if i != 0 || r.Phase != "" || len(r.Probes) != 0 || r.Outcome != "LIVE_SESSION_STARTED" {
				bad("OBSERVATIONS_CONTRADICTORY", "INVALID_SESSION_START")
				return
			}
		case "READY":
			if i == 0 || ready || active || f.Baseline < 3 || r.Phase != "baseline" || len(r.Probes) != 0 || r.Outcome != "REGISTERED_BEFORE_INTERVENTION" {
				bad("OBSERVATIONS_CONTRADICTORY", "LATE_OR_INVALID_REGISTRATION_READINESS")
				return
			}
			ready = true
		case "SAMPLE":
			count++
			if i == 0 || count > reg.MaxSamples || len(r.Probes) != 3 || lastSample >= 0 && r.StartedNS-lastSample < int64(reg.IntervalMillis)*int64(time.Millisecond) {
				bad("OBSERVATIONS_CONTRADICTORY", "INVALID_SAMPLE_COUNT_RATE_OR_START")
				return
			}
			lastSample = r.StartedNS
			measured := true
			for j, p := range r.Probes {
				kind := []string{"direct", "proxy", "application"}[j]
				if p.Kind != kind || p.StartedNS < r.StartedNS || p.CompletedNS < p.StartedNS || p.CompletedNS > r.CompletedNS || p.CompletedNS-p.StartedNS > int64(1500*time.Millisecond) {
					bad("OBSERVATIONS_CONTRADICTORY", "INVALID_PROBE_TIMING")
					return
				}
				if p.Outcome == "REQUEST_FAILED" && p.Response == nil && p.HTTPCode == 0 {
					measured = false
					continue
				}
				if p.Outcome != "MEASURED" || p.Response == nil || !kubefault.VerifyData(*p.Response, reg.Plan.Target.Fixture, r.Nonce, kind, p.HTTPCode) {
					bad("OBSERVATIONS_CONTRADICTORY", "INVALID_RESPONSE_NONCE_BODY_IDENTITY_OR_SIGNATURE")
					return
				}
				if p.HTTPCode < 200 || p.HTTPCode > 599 || p.Response.ProxyDelayNS < 0 || p.Response.ProxyDelayNS > p.CompletedNS-p.StartedNS || kind != "proxy" && p.Response.ProxyDelayNS != 0 {
					bad("OBSERVATIONS_CONTRADICTORY", "IMPOSSIBLE_HTTP_OR_SIGNED_HOLD_TIMING")
					return
				}
				if kind == "direct" && p.Response.InvocationID != "" || kind != "direct" && p.Response.InvocationID != "" && p.Response.InvocationID != reg.InvocationID {
					bad("OBSERVATIONS_CONTRADICTORY", "CROSS_INVOCATION_RESPONSE")
					return
				}
			}
			if !measured {
				if r.Phase != "unknown" || r.Outcome != "MEASUREMENT_UNAVAILABLE" {
					bad("OBSERVATIONS_CONTRADICTORY", "MISSING_PROBE_MISLABELED")
					return
				}
				f.Problems = append(f.Problems, "MISSING_OR_TIMED_OUT_PROBE")
				continue
			}
			phase := Phase(r.Probes, reg, active)
			if r.Phase != phase || r.Outcome != "MEASURED" {
				bad("OBSERVATIONS_CONTRADICTORY", "AMBIGUOUS_OR_FORGED_PHASE")
				return
			}
			if phase == "transition" {
				f.Problems = append(f.Problems, "TRANSITION_SAMPLE_NOT_COUNTED")
				continue
			}
			direct := r.Probes[0].CompletedNS - r.Probes[0].StartedNS
			proxy := r.Probes[1].CompletedNS - r.Probes[1].StartedNS
			app := r.Probes[2]
			appDuration := app.CompletedNS - app.StartedNS
			delay := int64(reg.Plan.Fault.DelayMS) * int64(time.Millisecond)
			switch phase {
			case "baseline":
				if appDuration > f.BaselineApplicationMaxNS {
					f.BaselineApplicationMaxNS = appDuration
				}
				if active || recovered {
					bad("OBSERVATIONS_CONTRADICTORY", "PHASE_REGRESSION")
					return
				}
				if r.Probes[0].HTTPCode == 200 && r.Probes[1].HTTPCode == 200 && app.HTTPCode == 200 && !app.Response.Degraded && proxy-direct <= delay/4 && direct < delay/2 {
					f.Baseline++
				} else {
					f.Problems = append(f.Problems, "BASELINE_NOT_HEALTHY")
				}
			case "intervention":
				if appDuration > f.InterventionApplicationMaxNS {
					f.InterventionApplicationMaxNS = appDuration
				}
				if !ready || recovered {
					bad("OBSERVATIONS_CONTRADICTORY", "INTERVENTION_BEFORE_REGISTRATION_OR_AFTER_RECOVERY")
					return
				}
				active = true
				f.Intervention++
				if r.Probes[1].HTTPCode == 200 && proxy-direct >= delay*7/10 && direct < delay/2 && r.Probes[1].Response.ProxyDelayNS >= delay*7/10 && app.Response.Degraded && appDuration >= int64(50*time.Millisecond) && appDuration-f.BaselineApplicationMaxNS >= int64(40*time.Millisecond) {
					f.EffectSamples++
				}
				if app.HTTPCode != 200 {
					f.ApplicationFailures++
				}
				if app.CompletedNS-app.StartedNS > int64(reg.MaxApplicationMillis)*int64(time.Millisecond) {
					f.TimingFailures++
				}
			case "recovery":
				if appDuration > f.RecoveryApplicationMaxNS {
					f.RecoveryApplicationMaxNS = appDuration
				}
				recovered = true
				if app.HTTPCode == 200 && !app.Response.Degraded && r.Probes[1].HTTPCode == 200 && proxy-direct <= delay/4 && direct < delay/2 && appDuration <= int64(reg.MaxApplicationMillis)*int64(time.Millisecond) && appDuration-f.BaselineApplicationMaxNS <= int64(40*time.Millisecond) {
					f.Recovery++
				} else {
					f.Problems = append(f.Problems, "RECOVERY_NOT_HEALTHY")
				}
			}
		case "END", "INTERRUPTED":
			if i == 0 || r.Phase != "" || len(r.Probes) != 0 || r.Type == "END" && r.Outcome != "COMPLETED" || r.Type == "INTERRUPTED" && (r.Outcome != "WINDOW_EXHAUSTED" && r.Outcome != "CANCELLED" && r.Outcome != "IDENTITY_UNAVAILABLE") {
				bad("OBSERVATIONS_CONTRADICTORY", "INVALID_TERMINAL_RECORD")
				return
			}
			closed = true
			ended = r.Type == "END"
			if !ended {
				f.Problems = append(f.Problems, "SESSION_INTERRUPTED")
			}
		default:
			bad("UNSUPPORTED_SOURCE", "UNSUPPORTED_RECORD_TYPE")
			return
		}
	}
	f.SignatureChain = "VALID"
	if torn {
		f.Problems = append(f.Problems, "TORN_JOURNAL")
	}
	if !ended {
		f.Problems = append(f.Problems, "MISSING_SESSION_END")
	}
	f.Complete = !torn && ended && ready && f.Baseline >= 3 && f.Intervention >= 3 && f.Recovery >= 3
	for _, problem := range f.Problems {
		if problem != "TRANSITION_SAMPLE_NOT_COUNTED" {
			f.Complete = false
		}
	}
	if f.EffectSamples < 3 {
		f.Problems = append(f.Problems, "INTERVENTION_EFFECT_NOT_CORROBORATED")
	}
	if f.ApplicationFailures > 0 || f.TimingFailures > 0 {
		f.ApplicationVerdict = "FAIL"
	} else if f.Complete && f.EffectSamples >= 3 {
		f.ApplicationVerdict = "PASS"
	}
	if !Trusted(reg, policy, now) {
		bad("WITNESS_IDENTITY_UNTRUSTED", "NO_CURRENT_EXTERNAL_EXACT_SCOPE_TRUST")
		return
	}
	f.WitnessTrust = "TRUSTED"
	if f.Complete && f.EffectSamples >= 3 && len(records) > 0 {
		f.Status = "OBSERVED_AND_CORRELATED"
	}
	return
}
