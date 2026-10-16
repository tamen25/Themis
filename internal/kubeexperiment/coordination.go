package kubeexperiment

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	api "github.com/tamen25/themis/api/kubernetes/v1alpha1"
	"github.com/tamen25/themis/internal/kube"
	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/localstate"
	"sigs.k8s.io/controller-runtime/pkg/client"
	strictjson "sigs.k8s.io/json"
)

const CoordinationVersion = "themis.kubernetes-coordination/v1alpha1"
const CoordinationProposalVersion = "themis.kubernetes-coordination-proposal/v1alpha1"
const CoordinationStateVersion = "themis.kubernetes-coordination-state/v1alpha1"
const CoordinationApprovalVersion = "themis.kubernetes-coordination-approval/v1alpha1"
const CoordinationClaimVersion = "themis.kubernetes-coordination-claim/v1alpha1"
const CoordinationActionVersion = "themis.kubernetes-coordination-action/v1alpha1"

// CoordinationProposal is publishable intent, never execution authority.
type CoordinationProposal struct {
	Version        string          `json:"version"`
	ID             string          `json:"id"`
	Namespace      string          `json:"namespace"`
	Requested      api.RunSpec     `json:"requestedSpecification"`
	SpecDigest     string          `json:"requestedSpecificationDigest"`
	ContractDigest string          `json:"requestedContractDigest"`
	Preview        api.PlanPreview `json:"controllerPreview"`
	Plan           kubefault.Plan  `json:"executionPlan"`
	PlanDigest     string          `json:"executionPlanDigest"`
	ApproverKey    string          `json:"approverPublicKey"`
}

func (p CoordinationProposal) Digest() string {
	return kubefault.Digest(CoordinationProposalVersion, p)
}

func (p CoordinationProposal) Validate() error {
	d := p.Preview.Plan
	if p.Version != CoordinationProposalVersion || !validID(p.ID) || p.Namespace != kube.Namespace || p.Plan.Validate() != nil || p.PlanDigest != p.Plan.Digest() || p.SpecDigest != kubefault.Digest("themis.kubernetes-spec/v1alpha1", p.Requested) || p.ContractDigest != kubefault.Digest("themis.kubernetes-contract/v1alpha1", p.Requested.Contract) || !validID(p.ApproverKey) {
		return kubefault.ErrDenied
	}
	policy, err := kube.NewPolicy(p.Namespace, d.Target.ClusterUID, d.Target.NamespaceUID)
	if err != nil || policy.Validate(p.Namespace, p.Requested) != "" || d.SchemaVersion != "themis.kubernetes-plan/v1alpha1" || d.PlannerVersion != "themis.kubernetes-planner/t2.0-v1" || d.PolicyVersion != kube.PolicyVersion || d.ExecutionAllowed || d.ExecutionProfile != kube.Profile || p.Preview.Digest != kubefault.Digest(d.SchemaVersion, d) || p.Preview.Digest != p.Plan.PreviewDigest || string(d.RunUID) != p.Plan.RunUID || d.RunGeneration != p.Plan.RunGeneration || d.SpecDigest != p.SpecDigest || d.ContractDigest != p.ContractDigest || !reflect.DeepEqual(d.Contract, p.Requested.Contract) || !reflect.DeepEqual(d.Target.Reference, p.Requested.Target) || string(d.Target.ClusterUID) != p.Plan.Target.Fixture.ClusterUID || string(d.Target.NamespaceUID) != p.Plan.Target.Fixture.NamespaceUID || string(d.Target.Reference.UID) != p.Plan.Target.DeploymentUID || d.Target.Reference.Name != p.Plan.Target.DeploymentName || d.Target.Reference.Generation != p.Plan.Target.DeploymentGeneration || d.Target.TemplateDigest != p.Plan.Target.TemplateDigest {
		return kubefault.ErrDenied
	}
	return nil
}

type CoordinationApproval struct {
	Version        string    `json:"version"`
	ProposalDigest string    `json:"proposalDigest"`
	PlanDigest     string    `json:"planDigest"`
	InvocationID   string    `json:"invocationID"`
	ApproverKey    string    `json:"approverPublicKey"`
	IssuedAt       time.Time `json:"issuedAt"`
	ApplyBefore    time.Time `json:"applyBefore"`
	CleanupBefore  time.Time `json:"cleanupBefore"`
}

func (a CoordinationApproval) Digest() string {
	return kubefault.Digest(CoordinationApprovalVersion, a)
}

type CoordinationReferences struct {
	RunDirectory string `json:"runDirectory"`
	Journal      string `json:"journal"`
	Report       string `json:"report"`
}

type CoordinationAction struct {
	Version          string    `json:"version"`
	ID               string    `json:"id"`
	ProposalDigest   string    `json:"proposalDigest"`
	PlanDigest       string    `json:"planDigest"`
	InvocationID     string    `json:"invocationID,omitempty"`
	RequestedAt      time.Time `json:"requestedAt"`
	AlreadyFinalized bool      `json:"alreadyFinalized"`
}

type CoordinationProvenance struct {
	Index                string   `json:"index"`
	ControllerPreview    string   `json:"controllerPreview"`
	ExecutionAttestation string   `json:"executionAttestation"`
	Limitations          []string `json:"limitations"`
}

// The record projects the experiment's existing report and inspection. It has
// no independent verdict field or evaluator and cannot authenticate history.
type CoordinationRecord struct {
	Version            string                  `json:"version"`
	Proposal           CoordinationProposal    `json:"proposal"`
	ProposalDigest     string                  `json:"proposalDigest"`
	Approval           *CoordinationApproval   `json:"approval,omitempty"`
	ApprovalReference  string                  `json:"approvalReference,omitempty"`
	InvocationID       string                  `json:"invocationID,omitempty"`
	References         *CoordinationReferences `json:"evidenceReferences,omitempty"`
	ExecutionState     string                  `json:"executionState"`
	CancellationState  string                  `json:"cancellationState"`
	CleanupDisposition string                  `json:"cleanupDisposition"`
	Action             *CoordinationAction     `json:"action,omitempty"`
	Historical         *Inspection             `json:"historicalAndCurrent,omitempty"`
	LiveResult         *Report                 `json:"locallyCollectedExecutionResult,omitempty"`
	CleanupReceipt     *CleanupReceipt         `json:"cleanupReceipt,omitempty"`
	Verification       *EvidenceVerification   `json:"evidenceVerification,omitempty"`
	Provenance         CoordinationProvenance  `json:"provenance"`
	Problems           []string                `json:"problems"`
}

type coordinationState struct {
	Version        string               `json:"version"`
	Directory      string               `json:"directory"`
	StateDirectory string               `json:"stateDirectory"`
	Proposal       CoordinationProposal `json:"proposal"`
	ProposalDigest string               `json:"proposalDigest"`
}

type coordinationClaim struct {
	Version        string    `json:"version"`
	ProposalDigest string    `json:"proposalDigest"`
	InvocationID   string    `json:"invocationID"`
	CreatedAt      time.Time `json:"createdAt"`
}

func baseCoordination(p CoordinationProposal) CoordinationRecord {
	return CoordinationRecord{Version: CoordinationVersion, Proposal: p, ProposalDigest: p.Digest(), ExecutionState: "NOT_RUN", CancellationState: "NOT_REQUESTED", CleanupDisposition: "NOT_REQUIRED", Problems: []string{}, Provenance: CoordinationProvenance{Index: "UNSIGNED_OPERATOR_OPERATIONAL_INDEX", ControllerPreview: "UNTRUSTED_KUBERNETES_STATUS_INDEPENDENTLY_RECOMPILED", ExecutionAttestation: "UNVERIFIED", Limitations: []string{"The index is not approval authority, an evidence bundle signature or a remote release gate.", "Measurement verdicts come only from the experiment journal and existing evaluator.", "Fixture signatures, unsigned client timing and whole execution provenance remain distinct."}}}
}

func loadCoordination(dir string) (coordinationState, error) {
	var state coordinationState
	if err := localstate.Read(filepath.Join(dir, "coordination-inventory.json"), &state); err != nil {
		return state, err
	}
	abs, err := filepath.Abs(dir)
	if err != nil || state.Version != CoordinationStateVersion || state.Directory != abs || !filepath.IsAbs(state.StateDirectory) || state.Proposal.Validate() != nil || state.ProposalDigest != state.Proposal.Digest() {
		return state, kubefault.ErrDenied
	}
	var proposal CoordinationProposal
	if err = localstate.Read(filepath.Join(dir, "proposal.json"), &proposal); err != nil {
		return state, err
	}
	if !reflect.DeepEqual(proposal, state.Proposal) {
		return state, kubefault.ErrDenied
	}
	return state, nil
}

func OpenCoordination(ctx context.Context, dir, explicitState string) (*Cluster, error) {
	state, err := loadCoordination(dir)
	if err != nil {
		return nil, err
	}
	if explicitState != "" {
		abs, e := filepath.Abs(explicitState)
		if e != nil || abs != state.StateDirectory {
			return nil, kubefault.ErrDenied
		}
	}
	c, err := openCluster(ctx, state.StateDirectory, false)
	if err != nil {
		return nil, err
	}
	p := state.Proposal
	if p.ApproverKey != c.Owner.ApproverKey || p.Plan.Operator != c.Owner.Operator || p.Plan.Target.Fixture.ClusterUID != c.Owner.ClusterUID || p.Plan.Target.Fixture.NamespaceUID != c.Owner.NamespaceUID || p.Plan.Target.DeploymentUID != c.Owner.DeploymentUID {
		return nil, kubefault.ErrDenied
	}
	return c, nil
}

func (c *Cluster) resolveCoordination(ctx context.Context, runName, scenario string) (CoordinationProposal, error) {
	p, err := c.Plan(ctx, runName, scenario)
	if err != nil {
		return CoordinationProposal{}, err
	}
	run := kube.RunObject()
	if err = c.Reader.Get(ctx, client.ObjectKey{Namespace: kube.Namespace, Name: runName}, run); err != nil {
		return CoordinationProposal{}, err
	}
	data, err := json.Marshal(run.Object["spec"])
	if err != nil {
		return CoordinationProposal{}, err
	}
	spec, err := kube.DecodeSpec(data)
	if err != nil {
		return CoordinationProposal{}, err
	}
	status := kube.ReadStatus(run)
	if status.Preview == nil || string(run.GetUID()) != p.RunUID || run.GetGeneration() != p.RunGeneration || status.Invalidated || status.PlanDigest != p.PreviewDigest {
		return CoordinationProposal{}, kubefault.ErrDenied
	}
	proposal := CoordinationProposal{Version: CoordinationProposalVersion, ID: kubefault.RandomID(), Namespace: kube.Namespace, Requested: spec, SpecDigest: kubefault.Digest("themis.kubernetes-spec/v1alpha1", spec), ContractDigest: kubefault.Digest("themis.kubernetes-contract/v1alpha1", spec.Contract), Preview: *status.Preview, Plan: p, PlanDigest: p.Digest(), ApproverKey: c.Owner.ApproverKey}
	if err = proposal.Validate(); err != nil {
		return proposal, err
	}
	if err = c.Revalidate(ctx, p); err != nil {
		return proposal, err
	}
	return proposal, nil
}

func (c *Cluster) PrepareCoordination(ctx context.Context, runName, scenario, dir string) (CoordinationRecord, error) {
	p, err := c.resolveCoordination(ctx, runName, scenario)
	if err != nil {
		return CoordinationRecord{}, err
	}
	dir, err = localstate.CreateDirectory(dir)
	if err != nil {
		return CoordinationRecord{}, err
	}
	stateDir, err := filepath.Abs(c.StateDirectory)
	if err != nil {
		return CoordinationRecord{}, err
	}
	state := coordinationState{CoordinationStateVersion, dir, stateDir, p, p.Digest()}
	if err = writePrivate(filepath.Join(dir, "coordination-inventory.json"), state); err != nil {
		return baseCoordination(p), err
	}
	if err = writePrivate(filepath.Join(dir, "proposal.json"), p); err != nil {
		return baseCoordination(p), err
	}
	r := baseCoordination(p)
	return r, publishCoordination(dir, r)
}

func (c *Cluster) PreviewCoordination(ctx context.Context, runName, scenario string) (CoordinationRecord, error) {
	p, err := c.resolveCoordination(ctx, runName, scenario)
	if err != nil {
		return CoordinationRecord{}, err
	}
	return baseCoordination(p), nil
}

func publishCoordination(dir string, r CoordinationRecord) error {
	if err := r.Validate(); err != nil {
		return err
	}
	return writePrivate(filepath.Join(dir, "record-"+kubefault.RandomID()+".json"), r)
}

func readCoordinationApproval(dir string, state coordinationState, c *Cluster) (CoordinationApproval, kubefault.Authorization, error) {
	var approval CoordinationApproval
	var auth kubefault.Authorization
	err := localstate.Read(filepath.Join(dir, "authorization.json"), &auth)
	if errors.Is(err, os.ErrNotExist) {
		if _, other := os.Lstat(filepath.Join(dir, "approval.json")); !errors.Is(other, os.ErrNotExist) {
			return approval, auth, kubefault.ErrDenied
		}
		return approval, auth, os.ErrNotExist
	}
	if err != nil {
		return approval, auth, err
	}
	if err = localstate.Read(filepath.Join(dir, "approval.json"), &approval); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return approval, auth, kubefault.ErrDenied
		}
		return approval, auth, err
	}
	if auth.CheckKeys() != nil || !reflect.DeepEqual(auth.Grant.Plan, state.Proposal.Plan) || auth.Grant.PlanDigest != state.Proposal.PlanDigest || c.validateInventory(inventory{Plan: state.Proposal.Plan, Authorization: auth}) != nil {
		return approval, auth, kubefault.ErrDenied
	}
	want := CoordinationApproval{CoordinationApprovalVersion, state.ProposalDigest, auth.Grant.PlanDigest, auth.Grant.InvocationID, c.Owner.ApproverKey, auth.Grant.IssuedAt, auth.Grant.ApplyBefore, auth.Grant.CleanupBefore}
	if !reflect.DeepEqual(approval, want) {
		return approval, auth, kubefault.ErrDenied
	}
	return approval, auth, nil
}

func coordinationReferences(invocation string) CoordinationReferences {
	dir := "runs/run-" + invocation
	return CoordinationReferences{dir, dir + "/events.jsonl", dir + "/report.json"}
}

func (c *Cluster) checkCoordination(ctx context.Context, state coordinationState) error {
	p, err := c.resolveCoordination(ctx, state.Proposal.Plan.RunName, state.Proposal.Plan.Scenario)
	if err != nil {
		return err
	}
	p.ID = state.Proposal.ID
	if !reflect.DeepEqual(p, state.Proposal) {
		return kubefault.ErrDenied
	}
	return nil
}

func coordinationLock(ctx context.Context, dir string) (*localstate.Lock, error) {
	lock, err := localstate.OpenLock(filepath.Join(dir, "coordination.lock"), true)
	if err != nil {
		return nil, err
	}
	if err = lock.Acquire(ctx); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return lock, nil
}

// DecodeCoordinationRecord validates a public index's shape and bindings. It
// does not authenticate any claim, signature key origin or historical timing.
func DecodeCoordinationRecord(data []byte) (CoordinationRecord, error) {
	var r CoordinationRecord
	if err := localstate.Unmarshal(data, &r); err != nil {
		return r, err
	}
	fields, err := strictjson.UnmarshalStrict(data, &r)
	if err != nil || len(fields) != 0 {
		return r, errors.New("invalid coordination record fields")
	}
	return r, r.Validate()
}
