package run

import (
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"time"

	"github.com/tamen25/themis/internal/contract"
	"github.com/tamen25/themis/internal/probe"
	"github.com/tamen25/themis/internal/result"
)

func evaluate(id string, c contract.Validated, m Manifest, slots []slot, duration time.Duration, samples []probe.Observation, end terminal, digest string) Report {
	snapshot := c.Snapshot()
	sort.SliceStable(snapshot.Spec.Assertions, func(i, j int) bool { return snapshot.Spec.Assertions[i].Type < snapshot.Spec.Assertions[j].Type })
	r := Report{
		SchemaVersion: SchemaVersion, RunID: id, ContractName: snapshot.Metadata.Name,
		ContractDigest: c.Digest(), PlanDigest: m.PlanDigest, PolicyVersion: PolicyVersion,
		JournalDigest: digest, Target: snapshot.Spec.Target, StartedAt: m.StartedAt,
		ElapsedNS: end.ElapsedNS, ExpectedSamples: len(slots), Coverage: result.Insufficient,
		Execution: result.Execution{Status: end.Status}, Assertions: []result.AssertionResult{},
	}
	for _, o := range samples {
		if observed(o) {
			r.Samples++
		}
	}
	complete := end.Status == result.Succeeded && end.ElapsedNS >= int64(duration)
	if r.Samples == len(slots) && complete {
		r.Coverage = result.Sufficient
	}
	if r.Samples == 0 {
		r.Coverage = result.Missing
	}
	if !complete {
		r.Execution.Error = &result.ExecutionError{Code: "INCOMPLETE_COLLECTION", Message: "run cancelled, expired or missing a terminal event; observation window is incomplete"}
	}
	var required []string
	for _, a := range snapshot.Spec.Assertions {
		if a.Required {
			required = append(required, a.ID)
		}
		ar := result.AssertionResult{ID: a.ID, Verdict: result.Inconclusive, Evidence: result.Insufficient}
		switch a.Type {
		case "http-ready":
			deadline, _ := time.ParseDuration(a.Deadline)
			expected, measured, successes := 0, 0, 0
			for _, s := range slots {
				if s.at < deadline {
					expected++
				}
			}
			for _, o := range samples {
				if slots[o.Index].at < deadline && observed(o) {
					measured++
				}
				if o.CompletedNS <= int64(deadline) && successful(o) {
					successes++
				}
			}
			if successes >= a.MinSamples {
				ar.Verdict, ar.Evidence, ar.Reason = result.Pass, result.Sufficient, fmt.Sprintf("%d successful responses by %s; minimum %d", successes, a.Deadline, a.MinSamples)
			} else if end.ElapsedNS >= int64(deadline) && measured == expected {
				ar.Verdict, ar.Evidence, ar.Reason = result.Fail, result.Sufficient, fmt.Sprintf("%d successful responses by %s; minimum %d", successes, a.Deadline, a.MinSamples)
			} else {
				ar.Reason = "readiness deadline or scheduled observations incomplete"
			}
		case "http-success-rate":
			failures := 0
			for _, o := range samples {
				if observed(o) && !successful(o) {
					failures++
				}
			}
			if r.Coverage == result.Sufficient && r.Samples >= a.MinSamples {
				ar.Evidence, ar.Verdict = result.Sufficient, result.Pass
				if exceeds(failures, r.Samples, *a.MaximumErrorFraction) {
					ar.Verdict = result.Fail
				}
				ar.Reason = fmt.Sprintf("%d/%d unsuccessful probes; maximum error fraction %s", failures, r.Samples, strconv.FormatFloat(*a.MaximumErrorFraction, 'g', -1, 64))
			} else {
				ar.Reason = fmt.Sprintf("%d/%d scheduled probes observed; minimum %d; complete window required", r.Samples, len(slots), a.MinSamples)
			}
		}
		r.Assertions = append(r.Assertions, ar)
	}
	r.Verdict = result.Aggregate(required, r.Assertions, result.RunEvidence{PreconditionsMet: r.Coverage == result.Sufficient, CollectionError: r.Execution.Error})
	return r
}

// v1alpha1 thresholds are normalized float64 values. Interpret their canonical
// JSON decimals exactly when comparing a count ratio; never round that ratio or
// apply an epsilon that could admit an above-threshold failure rate.
func exceeds(failures, samples int, maximum float64) bool {
	threshold, ok := new(big.Rat).SetString(strconv.FormatFloat(maximum, 'g', -1, 64))
	if !ok || samples <= 0 {
		return true
	}
	return new(big.Rat).SetFrac64(int64(failures), int64(samples)).Cmp(threshold) > 0
}
