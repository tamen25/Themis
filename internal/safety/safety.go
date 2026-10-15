// Package safety makes deny-by-default decisions independently of contract permissions.
package safety

import (
	"errors"
	"fmt"
	"time"

	"github.com/tamen25/themis/internal/localpolicy"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/plan"
)

var ErrDenied = errors.New("experiment admission denied")

type Authorization struct {
	ID             string           `json:"id"`
	PlanDigest     string           `json:"planDigest"`
	Actor          localstate.Actor `json:"actor"`
	FixtureID      string           `json:"fixtureID"`
	ServiceID      string           `json:"serviceID"`
	ProxyID        string           `json:"proxyID"`
	Action         string           `json:"action"`
	AdapterVersion string           `json:"adapterVersion"`
	IssuedAt       time.Time        `json:"issuedAt"`
	ExpiresAt      time.Time        `json:"expiresAt"`
	Seal           string           `json:"seal"`
}

// Evaluate grants no capability. Only the owned fixture authority can mint and
// consume an authorization after a fresh explicit approval of this resolved plan.
func Evaluate(p plan.ExperimentPlan, actor localstate.Actor, now time.Time) error {
	deny := func(reason string) error { return fmt.Errorf("%w: %s", ErrDenied, reason) }
	if p.Digest() == "" {
		return deny("resolved plan required")
	}
	d := p.Snapshot()
	s := d.Contract.Spec
	if d.PolicyVersion != localpolicy.ExperimentVersion || d.PlannerVersion != plan.ExperimentPlannerVersion {
		return deny("unsupported execution policy/planner")
	}
	if err := plan.ValidateFixture(d.Target); err != nil {
		return deny(err.Error())
	}
	if actor.UID == "" || actor.UID != d.Target.OwnerUID || actor.Host != d.Target.Host {
		return deny("fixture is not owned by this local OS user and host")
	}
	if s.Target.Fixture != d.Target.Name || s.Target.Kind != "owned-local-http" || s.Execution.Profile != "owned-local-test" || s.Execution.MaxConcurrentFaults != 1 || s.Fault.Type != "http.response-latency" {
		return deny("scope, profile, concurrency or action is not allowed")
	}
	budget, _ := time.ParseDuration(s.Execution.MaxDuration)
	latency, _ := time.ParseDuration(s.Fault.Latency)
	fault, _ := time.ParseDuration(s.Fault.Duration)
	baseline, _ := time.ParseDuration(s.Baseline.Duration)
	recovery, _ := time.ParseDuration(s.Recovery.Duration)
	cleanup, _ := time.ParseDuration(s.Cleanup.Timeout)
	if budget <= 0 || budget > localpolicy.MaxExperimentDuration || fault <= 0 || fault > localpolicy.MaxFaultDuration || latency < localpolicy.MinLatency || latency > localpolicy.MaxLatency || cleanup <= 0 || cleanup > localpolicy.CleanupLimit {
		return deny("duration, latency or cleanup limit exceeded")
	}
	if baseline < 300*time.Millisecond || recovery < 300*time.Millisecond || baseline > 3*time.Second || recovery > 3*time.Second || baseline+fault+recovery > budget {
		return deny("invalid phase budgets")
	}
	if !now.Before(d.Target.ExpiresAt) || now.Add(budget+cleanup).After(d.Target.ExpiresAt) {
		return deny("fixture expires before the experiment and cleanup can finish")
	}
	if s.Observation.MinConfirmed < 3 || s.Observation.MinConfirmed > s.Observation.Samples || s.Evidence.Intervention != "independent-client" || s.Evidence.RawResponses || !s.Cleanup.Required {
		return deny("required independent evidence or cleanup is missing")
	}
	for _, phase := range []struct {
		duration time.Duration
		samples  int
		minimum  time.Duration
	}{{baseline, s.Baseline.Samples, 50 * time.Millisecond}, {fault, s.Observation.Samples, latency + 50*time.Millisecond}, {recovery, s.Recovery.Samples, 50 * time.Millisecond}} {
		if phase.samples < 3 || phase.samples > localpolicy.MaxPhaseSamples || phase.duration/time.Duration(phase.samples) < phase.minimum {
			return deny("sample slots cannot meet the trusted rate/latency bounds")
		}
	}
	return nil
}

func CheckAuthorization(a Authorization, p plan.ExperimentPlan, actor localstate.Actor, now time.Time) error {
	if err := Evaluate(p, actor, now); err != nil {
		return err
	}
	id := p.Snapshot().Target
	if !plan.ValidInstanceID(a.ID) || a.PlanDigest != p.Digest() || a.Actor != actor || a.FixtureID != id.InstanceID || a.ServiceID != id.ServiceID || a.ProxyID != id.ProxyID || a.Action != "http.response-latency" || a.AdapterVersion != localpolicy.AdapterVersion || a.IssuedAt.After(now) || !now.Before(a.ExpiresAt) || a.ExpiresAt.Sub(a.IssuedAt) > localpolicy.AuthorizationTTL {
		return fmt.Errorf("%w: stale, expired or mismatched authorization", ErrDenied)
	}
	return nil
}
