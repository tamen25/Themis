// Package chaosmesh implements researched, non-executable external-provider
// planning. No fault mutation, authorization issuer or cleanup actuator exists.
package chaosmesh

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"time"

	api "github.com/tamen25/themis/api/kubernetes/v1alpha1"
	"github.com/tamen25/themis/internal/kube"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
	"k8s.io/apimachinery/pkg/util/validation"
	strictjson "sigs.k8s.io/json"
)

const PlanVersion = "themis.chaosmesh-plan/v1alpha1"
const PolicyVersion = "themis.chaosmesh-safety/t2.4-planning-only-v1"
const DecisionVersion = "themis.chaosmesh-admission/v1alpha1"
const APIVersion = "chaos-mesh.org/v1alpha1"
const SourceCommit = "e020a2df5a69e99e49d2a3dda9e6be22237fd0d8"
const PlanningProvenance = "UNSIGNED_API_SNAPSHOT_NO_PROVIDER_EXECUTION_EVIDENCE"

var ErrDenied = errors.New("external-provider admission denied")
var hexID = regexp.MustCompile(`^[a-f0-9]{64}$`)
var uuid = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var kindName = regexp.MustCompile(`^themis-t24-[a-f0-9]{12}$`)
var image = regexp.MustCompile(`^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$`)
var containerID = regexp.MustCompile(`^containerd://[a-f0-9]{64}$`)
var shaDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type Provider struct {
	Name            string `json:"name"`
	Release         string `json:"release"`
	Commit          string `json:"sourceCommit"`
	SourceSHA256    string `json:"sourceArchiveSHA256"`
	ChartSHA256     string `json:"chartSHA256"`
	CRDSHA256       string `json:"networkChaosCRDSHA256"`
	ControllerImage string `json:"controllerImage"`
	DaemonImage     string `json:"daemonImage"`
}

// PinnedProvider describes audited upstream artifacts, not an installed or
// attested provider. Image digests are OCI indexes, not platform manifests.
func PinnedProvider() Provider {
	return Provider{"chaos-mesh", "v2.8.5", SourceCommit,
		"36be4a4dc1baecd8a4f1210fc6c930b006fee87165e7b00795122f85b7885f72",
		"342aa09792d77c874d7ce7ca4083005bf7342c5aace12ea818010e20eac8cb54",
		"d151d3d38cfb4e906df457a2927a8bad8872241655b0267e08e3315b1b615974",
		"ghcr.io/chaos-mesh/chaos-mesh@sha256:942bff26d591537f655df50532e3880d73fa8b6fca34a233fc69f8ccfd36188d",
		"ghcr.io/chaos-mesh/chaos-daemon@sha256:d794bf427ab1dfacfd51c2f417d26731ce46919637b1c83620f0afd40f580bd4"}
}

type Actor struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}
type Target struct {
	ReplicaSetName string `json:"replicaSetName"`
	ReplicaSetUID  string `json:"replicaSetUID"`
	PodName        string `json:"podName"`
	PodUID         string `json:"podUID"`
	PodSpecDigest  string `json:"podSpecDigest"`
	Container      string `json:"container"`
	ContainerID    string `json:"containerID"`
	Image          string `json:"image"`
	ImageID        string `json:"imageID"`
}

type Snapshot struct {
	ClusterName  string          `json:"clusterName"`
	ClusterUID   string          `json:"clusterUID"`
	NamespaceUID string          `json:"namespaceUID"`
	Actor        Actor           `json:"actor"`
	RunName      string          `json:"runName"`
	Requested    api.RunSpec     `json:"requestedSpecification"`
	Preview      api.PlanPreview `json:"controllerPreview"`
	Target       Target          `json:"target"`
}

// The closed wire subset deliberately admits only one candidate delay. It is
// schema-compatible upstream intent, NOT an identity-safe executable action.
type Selector struct {
	Pods map[string][]string `json:"pods"`
}
type Delay struct {
	Latency     string `json:"latency"`
	Jitter      string `json:"jitter"`
	Correlation string `json:"correlation"`
}
type DelaySpec struct {
	Action    string   `json:"action"`
	Mode      string   `json:"mode"`
	Selector  Selector `json:"selector"`
	Device    string   `json:"device"`
	Direction string   `json:"direction"`
	Duration  string   `json:"duration"`
	Delay     Delay    `json:"delay"`
}
type ResourceMetadata struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}
type CandidateResource struct {
	APIVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	Metadata   ResourceMetadata `json:"metadata"`
	Spec       DelaySpec        `json:"spec"`
}

type Document struct {
	Version             string            `json:"version"`
	Policy              string            `json:"policy"`
	Provider            Provider          `json:"provider"`
	Snapshot            Snapshot          `json:"snapshot"`
	InvocationID        string            `json:"invocationID"`
	ApproverPublicKey   string            `json:"proposedIndependentApproverPublicKey"`
	CreatedAt           time.Time         `json:"createdAt"`
	StartBefore         time.Time         `json:"requestedStartBefore"`
	HardStopBy          time.Time         `json:"requiredHardStopBy"`
	CleanupBefore       time.Time         `json:"requiredCleanupBefore"`
	Resource            CandidateResource `json:"candidateResource"`
	ResourceIdentity    string            `json:"resourceIdentity"`
	AuthorizationDomain string            `json:"requiredAuthorizationDomain"`
	Evidence            string            `json:"requiredEvidence"`
	ExecutionAllowed    bool              `json:"executionAllowed"`
	Provenance          string            `json:"provenance"`
}

type Plan struct {
	Digest   string   `json:"digest"`
	Document Document `json:"plan"`
}

func digest(domain string, value any) string {
	data, _ := json.Marshal(value)
	return fmt.Sprintf("sha256:%x", sha256.Sum256(append([]byte(domain+"\n"), data...)))
}

func candidate(s Snapshot, invocation string) CandidateResource {
	return CandidateResource{APIVersion, "NetworkChaos", ResourceMetadata{kube.Namespace, "themis-delay-" + invocation[:24]}, DelaySpec{"delay", "one", Selector{map[string][]string{kube.Namespace: {s.Target.PodName}}}, "eth0", "to", "2500ms", Delay{"200ms", "0ms", "0"}}}
}

func Compile(s Snapshot, invocation, approver string, now time.Time) (Plan, error) {
	if !hexID.MatchString(invocation) || !hexID.MatchString(approver) {
		return Plan{}, ErrDenied
	}
	data, err := json.Marshal(s)
	if err != nil {
		return Plan{}, err
	}
	var frozen Snapshot
	if err = json.Unmarshal(data, &frozen); err != nil {
		return Plan{}, err
	}
	s = frozen
	now = now.UTC()
	d := Document{Version: PlanVersion, Policy: PolicyVersion, Provider: PinnedProvider(), Snapshot: s, InvocationID: invocation, ApproverPublicKey: approver, CreatedAt: now, StartBefore: now.Add(20 * time.Second), HardStopBy: now.Add(22500 * time.Millisecond), CleanupBefore: now.Add(90 * time.Second), Resource: candidate(s, invocation), ResourceIdentity: "UNCREATED_UID_UNBOUND", AuthorizationDomain: "themis.chaosmesh-authorization/v1alpha1", Evidence: "INDEPENDENT_BASELINE_TRAFFIC_EFFECT_ASSERTIONS_RECOVERY_AND_RESIDUAL_CHECKS_REQUIRED", ExecutionAllowed: false, Provenance: PlanningProvenance}
	p := Plan{digest(PlanVersion, d), d}
	return p, p.Validate()
}

func (p Plan) Validate() error {
	d, s := p.Document, p.Document.Snapshot
	preview := s.Preview.Plan
	if d.Version != PlanVersion || d.Policy != PolicyVersion || !reflect.DeepEqual(d.Provider, PinnedProvider()) || !hexID.MatchString(d.InvocationID) || !hexID.MatchString(d.ApproverPublicKey) || d.ExecutionAllowed || d.Provenance != PlanningProvenance || d.ResourceIdentity != "UNCREATED_UID_UNBOUND" || d.AuthorizationDomain != "themis.chaosmesh-authorization/v1alpha1" || d.Evidence != "INDEPENDENT_BASELINE_TRAFFIC_EFFECT_ASSERTIONS_RECOVERY_AND_RESIDUAL_CHECKS_REQUIRED" || d.CreatedAt.IsZero() || d.StartBefore.Sub(d.CreatedAt) != 20*time.Second || d.HardStopBy.Sub(d.CreatedAt) != 22500*time.Millisecond || d.CleanupBefore.Sub(d.CreatedAt) != 90*time.Second || p.Digest != digest(PlanVersion, d) {
		return ErrDenied
	}
	policy, err := kube.NewPolicy(kube.Namespace, preview.Target.ClusterUID, preview.Target.NamespaceUID)
	if err != nil || !kindName.MatchString(s.ClusterName) || !uuid.MatchString(s.ClusterUID) || !uuid.MatchString(s.NamespaceUID) || s.ClusterUID == s.NamespaceUID || s.ClusterUID != string(preview.Target.ClusterUID) || s.NamespaceUID != string(preview.Target.NamespaceUID) || s.Actor.Name != PlannerActor || !uuid.MatchString(s.Actor.UID) || s.RunName != "external-latency-request" || policy.Validate(kube.Namespace, s.Requested) != "" || s.Requested.Target.Name != "synthetic" || preview.SchemaVersion != "themis.kubernetes-plan/v1alpha1" || preview.PlannerVersion != "themis.kubernetes-planner/t2.0-v1" || preview.PolicyVersion != kube.PolicyVersion || preview.ExecutionAllowed || preview.ExecutionProfile != kube.Profile || !uuid.MatchString(string(preview.RunUID)) || preview.RunGeneration < 1 || preview.SpecDigest != digest("themis.kubernetes-spec/v1alpha1", s.Requested) || preview.ContractDigest != digest("themis.kubernetes-contract/v1alpha1", s.Requested.Contract) || !reflect.DeepEqual(preview.Contract, s.Requested.Contract) || !reflect.DeepEqual(preview.Target.Reference, s.Requested.Target) || s.Preview.Digest != digest(preview.SchemaVersion, preview) {
		return ErrDenied
	}
	if !uuid.MatchString(s.Target.ReplicaSetUID) || !uuid.MatchString(s.Target.PodUID) || len(validation.IsDNS1123Subdomain(s.Target.PodName)) != 0 || len(validation.IsDNS1123Subdomain(s.Target.ReplicaSetName)) != 0 || s.Target.Container != "echo" || !image.MatchString(s.Target.Image) || !containerID.MatchString(s.Target.ContainerID) || !shaDigest.MatchString(s.Target.ImageID) && !image.MatchString(s.Target.ImageID) || !shaDigest.MatchString(s.Target.PodSpecDigest) || len(preview.Target.Images) != 1 || preview.Target.Images[0].Container != "echo" || preview.Target.Images[0].Image != s.Target.Image || preview.Target.Images[0].Init || !reflect.DeepEqual(d.Resource, candidate(s, d.InvocationID)) {
		return ErrDenied
	}
	return nil
}

func Decode(data []byte) (Plan, error) {
	var p Plan
	if err := localstate.Unmarshal(data, &p); err != nil {
		return p, err
	}
	fields, err := strictjson.UnmarshalStrict(data, &p)
	if err != nil || len(fields) != 0 {
		return p, ErrDenied
	}
	return p, p.Validate()
}

type Decision struct {
	Version           string         `json:"version"`
	PlanDigest        string         `json:"planDigest"`
	Admission         string         `json:"admission"`
	Verdict           result.Verdict `json:"verdict"`
	MutationAttempted bool           `json:"mutationAttempted"`
	Cleanup           string         `json:"cleanup"`
	Reasons           []string       `json:"reasons"`
	Provenance        string         `json:"provenance"`
}

// Admit is intentionally unconditional denial for this audited provider release.
// Caller-supplied capability flags, an old synthetic grant, API success or an
// updated status cannot bypass the missing hard safety boundaries.
func Admit(p Plan, expected string, now time.Time) Decision {
	r := Decision{Version: DecisionVersion, PlanDigest: p.Digest, Admission: "DENIED", Verdict: result.NotRun, MutationAttempted: false, Cleanup: "NOT_REQUIRED_NO_PROVIDER_OPERATION", Reasons: []string{}, Provenance: PlanningProvenance}
	if p.Validate() != nil || expected != p.Digest {
		r.Reasons = append(r.Reasons, "InvalidOrAlteredPlan")
	}
	if !now.Before(p.Document.StartBefore) || now.Before(p.Document.CreatedAt) {
		r.Reasons = append(r.Reasons, "PlanWindowInvalidOrExpired")
	}
	r.Reasons = append(r.Reasons, "ApprovedPodUIDNotEnforcedByProviderSelection", "DaemonSideHardExpiryUnavailable", "IndependentCleanupNotDemonstrated", "ProviderSpecificGrantNotIssued", "ProviderResourceUIDUnbound", "IndependentInterventionAndRecoveryNotCollected")
	return r
}
