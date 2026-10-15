// Package plan compiles immutable, non-mutating execution previews.
package plan

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/tamen25/themis/internal/contract"
	"github.com/tamen25/themis/internal/localpolicy"
)

const (
	SchemaVersion  = "themis.plan/v1alpha1"
	PlannerVersion = "themis.planner/t0-v2"
)

type check struct {
	Assertion   contract.Assertion `json:"assertion"`
	Support     string             `json:"support"`
	Explanation string             `json:"explanation"`
}

type safety struct {
	Profile         string   `json:"profile"`
	RequireApproval bool     `json:"requireApproval"`
	Admission       string   `json:"admission"`
	Requirements    []string `json:"requirements"`
}

type document struct {
	SchemaVersion    string             `json:"schemaVersion"`
	PlannerVersion   string             `json:"plannerVersion"`
	ExecutionPolicy  string             `json:"executionPolicy"`
	ContractDigest   string             `json:"contractDigest"`
	Contract         contract.Contract  `json:"contract"`
	Mode             string             `json:"mode"`
	ExecutionAllowed bool               `json:"executionAllowed"`
	TargetIdentity   string             `json:"targetIdentity"`
	Bounds           contract.Execution `json:"bounds"`
	Safety           safety             `json:"safety"`
	Checks           []check            `json:"checks"`
	Explanation      []string           `json:"explanation"`
}

// Plan owns the serialized snapshot; callers cannot mutate its underlying data.
// The digest covers the compact JSON value under "plan", excluding the envelope.
type Plan struct {
	json   string
	digest string
}

func (p Plan) Digest() string { return p.digest }

func (p Plan) JSON() []byte { return []byte(p.json) }

// Compile requires a validated contract. It performs no I/O, discovery, policy
// admission, authorization, probes or fault injection.
func Compile(c contract.Validated) (Plan, error) {
	if c.Digest() == "" {
		return Plan{}, errors.New("a validated contract is required")
	}
	snapshot := c.Snapshot()
	doc := document{
		SchemaVersion:    SchemaVersion,
		PlannerVersion:   PlannerVersion,
		ExecutionPolicy:  localpolicy.Version,
		ContractDigest:   c.Digest(),
		Contract:         snapshot,
		Mode:             "planning-only",
		ExecutionAllowed: false,
		TargetIdentity:   "declared-only; no runtime identity resolved",
		Bounds:           snapshot.Spec.Execution,
		Safety: safety{
			Profile:         snapshot.Spec.Execution.Profile,
			RequireApproval: snapshot.Spec.Execution.RequireApproval,
			Admission:       "not-requested",
			Requirements: []string{
				"Only the declared literal loopback endpoint is in scope.",
				"No fault, resource mutation, raw trace collection or signature is supported.",
				"The local runner independently admits this exact loopback endpoint under the versioned execution policy.",
				"Approval, when required, must bind to this exact plan digest; a plan is not authorization.",
			},
		},
		Checks: make([]check, 0, len(snapshot.Spec.Assertions)),
		Explanation: []string{
			"This command only validates and describes a contract; it sends no HTTP requests and writes no files.",
			"The run command observes declared phases in order: one sequential GET slot per 100ms, no catch-up bursts, no early success.",
			"Requests have a 1s timeout capped by the phase deadline, a 16KiB response-header limit, no body collection, redirects or environment proxies.",
			"2xx responses succeed; HTTP errors, TLS/network failures and request timeouts are unsuccessful probes. Cancellation leaves missing evidence.",
			"Coverage requires every scheduled slot and the complete observation window. Impossible minimum sample counts are denied before execution.",
			"Thresholds use the normalized v1alpha1 decimal; count ratios are compared exactly without rounding or tolerance.",
			"Only required assertions determine the verdict; missing observations and tool errors cannot establish PASS.",
			"No intervention is requested. The HTTP-only run creates no fault resources requiring cleanup.",
			"Target ownership, runtime identity, connectivity and actual workload health remain unverified.",
		},
	}
	for _, assertion := range snapshot.Spec.Assertions {
		var explanation string
		switch assertion.Type {
		case "http-ready":
			explanation = fmt.Sprintf("Would require successful HTTP responses (minimum %d) by %s from scenario start.", assertion.MinSamples, assertion.Deadline)
		case "http-success-rate":
			explanation = fmt.Sprintf("Would require at least %d HTTP samples across the scenario with error fraction <= %g.", assertion.MinSamples, *assertion.MaximumErrorFraction)
		default:
			return Plan{}, fmt.Errorf("unsupported assertion type %q", assertion.Type)
		}
		doc.Checks = append(doc.Checks, check{Assertion: assertion, Support: "local-http runner; separate admission required", Explanation: explanation})
	}
	canonical, err := json.Marshal(doc)
	if err != nil {
		return Plan{}, fmt.Errorf("serialize plan: %w", err)
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(canonical))
	envelope, err := json.Marshal(struct {
		Digest string          `json:"planDigest"`
		Plan   json.RawMessage `json:"plan"`
	}{digest, canonical})
	if err != nil {
		return Plan{}, fmt.Errorf("serialize plan envelope: %w", err)
	}
	return Plan{json: string(envelope), digest: digest}, nil
}
