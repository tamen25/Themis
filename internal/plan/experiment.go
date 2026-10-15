package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/tamen25/themis/internal/contract"
	"github.com/tamen25/themis/internal/localpolicy"
)

const ExperimentSchemaVersion = "themis.plan/v1alpha2"
const ExperimentPlannerVersion = "themis.planner/t1.1-v1"

// FixtureIdentity is a resolved instance, not a contract-supplied URL selector.
// The fixture client authenticates its nonce proof before this value is planned.
type FixtureIdentity struct {
	Name           string    `json:"name"`
	InstanceID     string    `json:"instanceID"`
	ServiceID      string    `json:"serviceID"`
	ProxyID        string    `json:"proxyID"`
	OwnerUID       string    `json:"ownerUID"`
	Host           string    `json:"host"`
	PID            int       `json:"pid"`
	ControlURL     string    `json:"controlURL"`
	ServiceURL     string    `json:"serviceURL"`
	ProxyURL       string    `json:"proxyURL"`
	AdapterVersion string    `json:"adapterVersion"`
	EvidenceKey    string    `json:"evidenceKey"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

type ExperimentDocument struct {
	SchemaVersion         string              `json:"schemaVersion"`
	PlannerVersion        string              `json:"plannerVersion"`
	PolicyVersion         string              `json:"policyVersion"`
	ContractDigest        string              `json:"contractDigest"`
	Contract              contract.Experiment `json:"contract"`
	Target                FixtureIdentity     `json:"target"`
	AuthorizationRequired bool                `json:"authorizationRequired"`
	Explanation           []string            `json:"explanation"`
}

type ExperimentPlan struct{ data, digest string }

func (p ExperimentPlan) Digest() string { return p.digest }
func (p ExperimentPlan) JSON() []byte   { return []byte(p.data) }
func (p ExperimentPlan) Snapshot() ExperimentDocument {
	var envelope struct {
		Plan ExperimentDocument `json:"plan"`
	}
	_ = json.Unmarshal(p.JSON(), &envelope)
	return envelope.Plan
}

func ValidInstanceID(id string) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 32
}

func ValidateFixture(id FixtureIdentity) error {
	if !ValidInstanceID(id.InstanceID) || !ValidInstanceID(id.ServiceID) || !ValidInstanceID(id.ProxyID) || !ValidInstanceID(id.EvidenceKey) || id.InstanceID == id.ServiceID || id.ServiceID == id.ProxyID || id.InstanceID == id.ProxyID || id.OwnerUID == "" || id.Host == "" || id.PID <= 0 || id.ExpiresAt.IsZero() {
		return errors.New("incomplete fixture identity")
	}
	if id.AdapterVersion != localpolicy.AdapterVersion {
		return errors.New("unsupported fixture adapter version")
	}
	seen := map[string]bool{}
	for _, endpoint := range []string{id.ControlURL, id.ServiceURL, id.ProxyURL} {
		u, err := url.Parse(endpoint)
		if err != nil {
			return errors.New("invalid fixture endpoint")
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "" || u.Opaque != "" || seen[endpoint] {
			return errors.New("fixture endpoints must be distinct allocated IPv4 loopback listeners")
		}
		seen[endpoint] = true
	}
	return nil
}

func CompileExperiment(c contract.ValidatedExperiment, id FixtureIdentity) (ExperimentPlan, error) {
	if c.Digest() == "" {
		return ExperimentPlan{}, errors.New("validated experiment required")
	}
	if err := ValidateFixture(id); err != nil {
		return ExperimentPlan{}, err
	}
	if c.Snapshot().Spec.Target.Fixture != id.Name {
		return ExperimentPlan{}, errors.New("resolved fixture name differs from contract target")
	}
	d := ExperimentDocument{ExperimentSchemaVersion, ExperimentPlannerVersion, localpolicy.ExperimentVersion, c.Digest(), c.Snapshot(), id, true, []string{
		"Experimental: only this owned service, dependency proxy and instance may be affected.",
		"A separate explicit authorization from the fixture authority is required; T0 approval flags cannot authorize faults.",
		"Baseline, intervention and recovery use fixed evenly distributed sample slots; missed slots block PASS.",
		"The proxy adds bounded response latency only to authenticated synthetic dependency requests, with independent monotonic expiry.",
		"Independent paired client measurements, correlated request IDs and matching instance identities are required to confirm intervention.",
		"Cleanup removes the fault, verifies recovery, stops the owned fixture and checks its listeners closed. Failure remains CLEANUP_PENDING.",
		"Client latency evidence is bounded empirical evidence, not proof of causality; unsigned replay does not authenticate observations.",
	}}
	data, err := json.Marshal(d)
	if err != nil {
		return ExperimentPlan{}, err
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(data))
	envelope, err := json.Marshal(struct {
		Digest string          `json:"planDigest"`
		Plan   json.RawMessage `json:"plan"`
	}{digest, data})
	if err != nil {
		return ExperimentPlan{}, err
	}
	return ExperimentPlan{string(envelope), digest}, nil
}
