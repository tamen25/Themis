// Package run executes admitted local observation runs and replays their journals.
package run

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tamen25/themis/internal/contract"
	"github.com/tamen25/themis/internal/localpolicy"
	"github.com/tamen25/themis/internal/plan"
	"github.com/tamen25/themis/internal/probe"
	"github.com/tamen25/themis/internal/result"
)

const (
	SchemaVersion   = "themis.run/v1alpha1"
	PolicyVersion   = localpolicy.Version
	Interval        = localpolicy.Interval
	maxJournalBytes = 16 << 20
)

var ErrAdmission = errors.New("local run admission denied")

type Options struct {
	Directory          string
	ApprovedPlanDigest string
}

type Manifest struct {
	Contract       json.RawMessage `json:"contract"`
	Plan           json.RawMessage `json:"plan"`
	ContractDigest string          `json:"contractDigest"`
	PlanDigest     string          `json:"planDigest"`
	PolicyVersion  string          `json:"policyVersion"`
	ApprovedPlan   string          `json:"approvedPlan,omitempty"`
	StartedAt      time.Time       `json:"startedAt"`
}

type Report struct {
	SchemaVersion   string                   `json:"schemaVersion"`
	RunID           string                   `json:"runID"`
	ContractName    string                   `json:"contractName"`
	ContractDigest  string                   `json:"contractDigest"`
	PlanDigest      string                   `json:"planDigest"`
	PolicyVersion   string                   `json:"policyVersion"`
	JournalDigest   string                   `json:"journalDigest"`
	Target          contract.Target          `json:"target"`
	StartedAt       time.Time                `json:"startedAt"`
	ElapsedNS       int64                    `json:"elapsedNS"`
	Samples         int                      `json:"samples"`
	ExpectedSamples int                      `json:"expectedSamples"`
	Coverage        result.EvidenceStatus    `json:"coverage"`
	Execution       result.Execution         `json:"execution"`
	Assertions      []result.AssertionResult `json:"assertions"`
	Verdict         result.Verdict           `json:"verdict"`
	Signed          bool                     `json:"signed"`
}

type slot struct {
	phase   string
	at, end time.Duration
}

// schedule is fixed by policy, independent of target responses or assertion
// outcomes. Slow requests leave gaps; missed slots are never caught up in bursts.
func schedule(c contract.Validated) ([]slot, time.Duration, error) {
	if c.Digest() == "" {
		return nil, 0, fmt.Errorf("%w: validated contract required", ErrAdmission)
	}
	var slots []slot
	var elapsed time.Duration
	for _, phase := range c.Snapshot().Spec.Scenario.Phases {
		d, _ := time.ParseDuration(phase.Duration) // Parse has validated all durations.
		for at := elapsed; at < elapsed+d; at += Interval {
			slots = append(slots, slot{phase.Name, at, elapsed + d})
		}
		elapsed += d
	}
	for _, a := range c.Snapshot().Spec.Assertions {
		available := len(slots)
		if a.Type == "http-ready" {
			deadline, _ := time.ParseDuration(a.Deadline)
			available = 0
			for _, s := range slots {
				if s.at < deadline {
					available++
				}
			}
		}
		if a.MinSamples > available {
			return nil, 0, fmt.Errorf("%w: assertion %q requires %d samples, policy permits %d", ErrAdmission, a.ID, a.MinSamples, available)
		}
	}
	return slots, elapsed, nil
}

func admit(c contract.Validated, p plan.Plan, approved string) error {
	if c.Snapshot().Spec.Execution.RequireApproval && approved != p.Digest() {
		return fmt.Errorf("%w: use --approve-plan %s after reviewing themis plan", ErrAdmission, p.Digest())
	}
	if approved != "" && approved != p.Digest() {
		return fmt.Errorf("%w: approval does not match this plan", ErrAdmission)
	}
	return nil
}

func observed(o probe.Observation) bool {
	return o.Outcome == "http" || o.Outcome == "transport-error" || o.Outcome == "timeout"
}

func successful(o probe.Observation) bool {
	return o.Outcome == "http" && o.StatusCode >= 200 && o.StatusCode < 300
}
