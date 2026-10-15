package experiment

import (
	"math/big"
	"time"

	"github.com/tamen25/themis/internal/fixture"
	"github.com/tamen25/themis/internal/localpolicy"
	"github.com/tamen25/themis/internal/plan"
	"github.com/tamen25/themis/internal/result"
)

type phaseEvidence struct {
	observations []Observation
	start, end   int64
	started      bool
}

func trusted(p Probe, o Observation, id plan.FixtureIdentity, windowEnd int64) bool {
	return p.Outcome == "http" && p.Response != nil && p.Response.HTTPStatus == p.StatusCode && p.CompletedNS <= windowEnd && p.CompletedNS-p.StartedNS <= int64(localpolicy.RequestLimit) && fixture.VerifyData(*p.Response, id, o.RequestID, p.Kind)
}
func latency(p Probe) int64   { return p.CompletedNS - p.StartedNS }
func successful(p Probe) bool { return p.StatusCode >= 200 && p.StatusCode < 300 }

// evaluate derives all assertions from observations. State labels and adapter
// receipts alone cannot confirm an intervention, coverage, or recovery.
func evaluate(p plan.ExperimentPlan, m Manifest, events []Event) Report {
	d := p.Snapshot()
	s := d.Contract.Spec
	latencyBudget, _ := time.ParseDuration(s.Fault.Latency)
	r := Report{Version: Version, RunID: m.Handle.RunID, ContractName: d.Contract.Metadata.Name, PlanDigest: p.Digest(), FixtureID: d.Target.InstanceID, Execution: result.Execution{Status: result.CleanupPending}, Verdict: result.Inconclusive, Observations: []Observation{}, Assertions: []result.AssertionResult{}, Unknowns: []string{}, EvidenceLimit: "Paired client latency and signed fixture responses provide bounded empirical evidence, not causal certainty. Client timings and the journal are unsigned; replay checks consistency, not operator or clock authenticity. Same-user processes and administrators are trusted."}
	legacy := len(events) > 0 && events[0].Version == LegacyJournalVersion
	if legacy {
		r.Version = LegacyVersion
	}
	attemptAcknowledged := false
	r.FaultAttempted = &attemptAcknowledged
	phases := map[State]*phaseEvidence{Baseline: {}, Intervention: {}, Recovery: {}}
	var current *phaseEvidence
	var abort bool
	var removed bool
	var finalized bool
	var clean bool
	for _, e := range events {
		if e.Observation != nil {
			r.Observations = append(r.Observations, *e.Observation)
			if current != nil {
				current.observations = append(current.observations, *e.Observation)
			}
			continue
		}
		if current != nil {
			current.end = e.AtNS
			current = nil
		}
		if phase, ok := phases[e.State]; ok {
			phase.start = e.AtNS
			phase.started = true
			current = phase
		}
		switch e.State {
		case Intent:
			r.FaultAttempted = nil
		case Applied:
			attemptAcknowledged = true
			r.FaultAttempted = &attemptAcknowledged
		case Removed:
			removed = true
		case Aborted:
			abort = true
			r.Execution.Status = e.Status
			if !legacy && e.Failure != nil {
				r.Failure = e.Failure
				r.FaultAttempted = e.Failure.FaultAttempted
				r.Execution.Error = &result.ExecutionError{Code: e.Failure.Code, Message: e.Failure.Reason}
			}
		case Cleaned:
			clean = residualsClosed(e.Residuals)
		case Pending:
			clean = false
		case Finalized:
			finalized = true
			r.Execution.Status = e.Status
			if !legacy && e.Failure != nil {
				r.Failure = e.Failure
				r.FaultAttempted = e.Failure.FaultAttempted
				r.Execution.Error = &result.ExecutionError{Code: e.Failure.Code, Message: e.Failure.Reason}
			}
		}
	}
	complete := func(state State) bool {
		phase := phases[state]
		_, duration, count := phaseConfig(p, state)
		budget, _ := time.ParseDuration(s.Execution.MaxDuration)
		if !phase.started || phase.end-phase.start < int64(duration) || phase.end > int64(budget) || len(phase.observations) != count {
			return false
		}
		end := phase.start + int64(duration)
		for i, o := range phase.observations {
			if o.Index != i || len(o.Probes) != 3 {
				return false
			}
			for _, probe := range o.Probes {
				if !trusted(probe, o, d.Target, end) {
					return false
				}
			}
		}
		return true
	}
	windowEnd := func(state State) int64 {
		_, duration, _ := phaseConfig(p, state)
		return phases[state].start + int64(duration)
	}
	baseGood := complete(Baseline)
	var baseMax int64
	for _, o := range phases[Baseline].observations {
		if len(o.Probes) != 3 {
			baseGood = false
			continue
		}
		for _, probe := range o.Probes {
			if !successful(probe) {
				baseGood = false
			}
		}
		delta := latency(o.Probes[1]) - latency(o.Probes[0])
		if delta < -int64(latencyBudget/4) || delta > int64(latencyBudget/4) || latency(o.Probes[0]) > int64(latencyBudget/4) {
			baseGood = false
		}
		baseMax = max(baseMax, delta)
	}
	r.BaselineSatisfied = baseGood
	for _, o := range phases[Intervention].observations {
		if len(o.Probes) != 3 {
			continue
		}
		direct, proxy := o.Probes[0], o.Probes[1]
		if trusted(direct, o, d.Target, windowEnd(Intervention)) && trusted(proxy, o, d.Target, windowEnd(Intervention)) && successful(direct) && successful(proxy) && latency(direct) <= int64(latencyBudget/4) && latency(proxy)-latency(direct)-baseMax >= int64(latencyBudget*3/4) {
			r.ConfirmedRequests++
		}
	}
	r.InterventionConfirmed = baseGood && attemptAcknowledged && r.ConfirmedRequests >= s.Observation.MinConfirmed
	recoveryGood := removed && complete(Recovery)
	for _, o := range phases[Recovery].observations {
		if len(o.Probes) != 3 {
			recoveryGood = false
			continue
		}
		for _, probe := range o.Probes {
			if !successful(probe) {
				recoveryGood = false
			}
		}
		delta := latency(o.Probes[1]) - latency(o.Probes[0])
		if delta > int64(latencyBudget/4) || delta < -int64(latencyBudget/4) || latency(o.Probes[0]) > int64(latencyBudget/4) {
			recoveryGood = false
		}
	}
	r.RecoveryObserved = recoveryGood
	r.CleanupCompleted = clean && finalized
	r.SufficientObservations = complete(Baseline) && complete(Intervention) && complete(Recovery)
	assert := func(id string, passed bool, reason string) {
		a := result.AssertionResult{ID: id, Verdict: result.Inconclusive, Evidence: result.Insufficient, Reason: reason}
		if passed {
			a.Verdict = result.Pass
			a.Evidence = result.Sufficient
			a.Reason = "required observations verified"
		}
		r.Assertions = append(r.Assertions, a)
		if !passed {
			r.Unknowns = append(r.Unknowns, reason)
		}
	}
	assert("baseline", baseGood, "baseline prerequisites or paired control measurements insufficient")
	assert("intervention", r.InterventionConfirmed, "intended latency was not independently confirmed")
	// Missing observations count as potential successes when establishing a
	// lower bound on failure. A credible failure cannot be hidden by lost samples.
	application := result.AssertionResult{ID: "application", Verdict: result.Inconclusive, Evidence: result.Insufficient, Reason: "application observations incomplete"}
	failed := 0
	for _, o := range phases[Intervention].observations {
		if len(o.Probes) == 3 && trusted(o.Probes[2], o, d.Target, windowEnd(Intervention)) && !successful(o.Probes[2]) {
			failed++
		}
	}
	threshold, ok := new(big.Rat).SetString(s.Assertions.MaximumErrorFraction.String())
	if ok && new(big.Rat).SetFrac64(int64(failed), int64(s.Observation.Samples)).Cmp(threshold) > 0 {
		application.Verdict = result.Fail
		application.Evidence = result.Sufficient
		application.Reason = "observed error fraction lower bound exceeds exact declared maximum"
	} else if complete(Intervention) {
		application.Verdict = result.Pass
		application.Evidence = result.Sufficient
		application.Reason = "exact observed error fraction meets declared maximum"
	}
	r.Assertions = append(r.Assertions, application)
	assert("recovery", recoveryGood, "normal post-removal behavior lacks complete independent observations")
	// A signed application failure after confirmed removal violates the required
	// recovery guarantee. A dead proxy with no signed response remains unknown.
	if removed {
		for _, o := range phases[Recovery].observations {
			if len(o.Probes) == 3 && trusted(o.Probes[2], o, d.Target, windowEnd(Recovery)) && !successful(o.Probes[2]) {
				a := &r.Assertions[len(r.Assertions)-1]
				a.Verdict = result.Fail
				a.Evidence = result.Sufficient
				a.Reason = "signed post-removal application response violates recovery guarantee"
			}
		}
	}
	assert("coverage", r.SufficientObservations, "one or more planned observation windows or samples are missing")
	assert("cleanup", r.CleanupCompleted, "owned listeners have not all been observed closed with a durable terminal event")
	if !finalized || !clean {
		r.Execution.Status = result.CleanupPending
		r.Unknowns = append(r.Unknowns, "interrupted or unresolved resources require cleanup reconciliation; independent expiry remains active")
	}
	if r.FaultAttempted == nil {
		r.Unknowns = append(r.Unknowns, "fault intent is durable but application acknowledgment is missing; whether application occurred is unknown")
	}
	if abort && r.Execution.Status == result.Succeeded {
		r.Execution.Status = result.Error
	}
	r.Verdict = result.Aggregate([]string{"baseline", "intervention", "application", "recovery", "coverage", "cleanup"}, r.Assertions, result.RunEvidence{PreconditionsMet: baseGood && !abort, InterventionRequired: true, InterventionObserved: r.InterventionConfirmed})
	if r.Verdict == result.Pass && r.Execution.Status != result.Succeeded {
		r.Verdict = result.Inconclusive
	}
	if !legacy {
		r.Provenance = classifyProvenance(r, m, UnsignedReplay)
		r.Deadlines = deadlineSummary(m, events)
	}
	return r
}
