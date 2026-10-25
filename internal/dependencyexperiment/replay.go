package dependencyexperiment

import (
	"errors"
	"reflect"

	wire "github.com/tamen25/themis/internal/dependencyhttp"
)

// Replay validates supported signatures/bindings and recomputes candidate client
// predicates. It never authenticates the unsigned collection clock or whole run.
func Replay(r Report) (Evaluation, error) {
	empty := Evaluation{Verdict: "INCONCLUSIVE", Problems: []string{}}
	if r.Version != "themis.native-http-report/v1alpha1" || !r.Plan.Valid() || r.PlanDigest != r.Plan.Digest() || len(r.Events) < 4 || len(r.Events) > 64 {
		return empty, errors.New("unsupported or incomplete native report")
	}
	previous := ""
	applied, cleaned, identityConfirmed := false, false, false
	for i, e := range r.Events {
		h := e.Hash
		e.Hash = ""
		if e.Version != r.Version || e.Sequence != i || e.Previous != previous || e.PlanDigest != r.PlanDigest || e.Invocation != r.Invocation || wire.Hash(e) != h {
			return empty, errors.New("execution chain mismatch")
		}
		previous = h
		if e.Kind == "IDENTITY_CONFIRMED" {
			identityConfirmed = true
		}
		if e.Kind == "IDENTITY_UNCERTAIN" {
			identityConfirmed = false
		}
		if e.Reply != nil && e.Reply.Code == 200 {
			reply := *e.Reply
			if !reply.Verified(r.Plan.Binding.Target.Proxy.Process, reply.Nonce, "control") || reply.PlanDigest != r.PlanDigest || reply.State.Invocation != r.Invocation || reply.State.ApplyCount > 1 {
				return empty, errors.New("control reply binding mismatch")
			}
			if e.Kind == "APPLIED" && reply.Action == "apply" && reply.State.Applied && reply.State.ApplyCount == 1 {
				applied = true
			}
			if e.Kind == "CLEANUP_CONFIRMED" && reply.Action == "remove" && !reply.State.Active && reply.State.Fenced {
				cleaned = true
			}
		}
	}
	if r.Events[0].Kind != "CLAIMED" || r.Events[len(r.Events)-1].Kind != "FINAL" {
		return empty, errors.New("missing terminal history")
	}
	actualCleanup := "PENDING"
	if cleaned {
		actualCleanup = "COMPLETE"
	}
	if r.Cleanup != actualCleanup {
		return empty, errors.New("fabricated cleanup claim")
	}
	result := Evaluate(r.Plan, r.Observations, r.Invocation, cleaned)
	if !applied || r.Execution == "CANCELLED" || !identityConfirmed {
		result.Verdict = "INCONCLUSIVE"
	}
	if r.Verdict != result.Verdict || !reflect.DeepEqual(r.Evaluation, Evaluate(r.Plan, r.Observations, r.Invocation, cleaned)) {
		return empty, errors.New("fabricated measurement verdict")
	}
	return result, nil
}
