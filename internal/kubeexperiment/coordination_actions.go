package kubeexperiment

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"time"

	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/localstate"
)

type executionGate struct{ outer, inner *localstate.Lock }

func (g *executionGate) Close() error {
	err := g.inner.Close()
	if g.outer != nil {
		if other := g.outer.Close(); err == nil {
			err = other
		}
	}
	return err
}

// Coordinated execution always acquires the operator gate before the run gate.
// A direct legacy cancel needs only the inner gate and cannot invert this order.
func executionLock(ctx context.Context, runDir, coordDir string) (*executionGate, error) {
	g := &executionGate{}
	var err error
	if coordDir != "" {
		g.outer, err = coordinationLock(ctx, coordDir)
		if err != nil {
			return nil, err
		}
	}
	g.inner, err = lifecycleLock(ctx, runDir)
	if err != nil {
		if g.outer != nil {
			_ = g.outer.Close()
		}
		return nil, err
	}
	return g, nil
}

func coordinationStop(dir, plan, invocation, proposal string) (*CoordinationAction, error) {
	var action CoordinationAction
	err := localstate.Read(filepath.Join(dir, "stop-request.json"), &action)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if action.Version != CoordinationActionVersion || !validID(action.ID) || action.PlanDigest != plan || action.ProposalDigest != proposal || action.InvocationID != "" && action.InvocationID != invocation || action.AlreadyFinalized || action.RequestedAt.IsZero() {
		return nil, kubefault.ErrDenied
	}
	return &action, nil
}

func executionStop(dir string, inv inventory, coordDir, proposalDigest string) error {
	if err := acceptedStop(dir, inv); err != nil {
		return err
	}
	if coordDir != "" {
		action, err := coordinationStop(coordDir, inv.Plan.Digest(), inv.Authorization.Grant.InvocationID, proposalDigest)
		if err != nil {
			return err
		}
		if action != nil {
			return errCancelled
		}
	}
	return nil
}

func (c *Cluster) boundCoordination(dir string) (coordinationState, error) {
	state, err := loadCoordination(dir)
	if err != nil {
		return state, err
	}
	abs, err := filepath.Abs(c.StateDirectory)
	p := state.Proposal
	if err != nil || abs != state.StateDirectory || p.ApproverKey != c.Owner.ApproverKey || p.Plan.Operator != c.Owner.Operator || p.Plan.Target.Fixture.ClusterUID != c.Owner.ClusterUID || p.Plan.Target.Fixture.NamespaceUID != c.Owner.NamespaceUID || p.Plan.Target.DeploymentUID != c.Owner.DeploymentUID {
		return state, kubefault.ErrDenied
	}
	return state, nil
}

func absent(path string) bool { _, err := os.Lstat(path); return errors.Is(err, os.ErrNotExist) }

func (c *Cluster) ApproveCoordination(ctx context.Context, dir, digest string) (CoordinationRecord, error) {
	state, err := c.boundCoordination(dir)
	if err != nil {
		return CoordinationRecord{}, err
	}
	r := baseCoordination(state.Proposal)
	gate, err := coordinationLock(ctx, dir)
	if err != nil {
		return r, err
	}
	defer gate.Close()
	if digest != state.Proposal.PlanDigest || !absent(filepath.Join(dir, "stop-request.json")) || !absent(filepath.Join(dir, "invalidated.json")) || !absent(filepath.Join(dir, "authorization.json")) || !absent(filepath.Join(dir, "approval.json")) {
		return r, kubefault.ErrDenied
	}
	if err = c.checkCoordination(ctx, state); err != nil {
		_ = writePrivate(filepath.Join(dir, "invalidated.json"), coordinationInvalidation{Version: "themis.kubernetes-coordination-invalidation/v1alpha1", ProposalDigest: state.ProposalDigest, Reason: "ObservedAdmissionFailure"})
		return r, err
	}
	auth, err := c.Approve(ctx, state.Proposal.Plan, digest)
	if err != nil {
		return r, err
	}
	approval := CoordinationApproval{CoordinationApprovalVersion, state.ProposalDigest, digest, auth.Grant.InvocationID, c.Owner.ApproverKey, auth.Grant.IssuedAt, auth.Grant.ApplyBefore, auth.Grant.CleanupBefore}
	// Interrupted publication cannot mint a replacement approval on retry.
	if err = writePrivate(filepath.Join(dir, "authorization.json"), auth); err != nil {
		return r, err
	}
	if err = writePrivate(filepath.Join(dir, "approval.json"), approval); err != nil {
		return r, err
	}
	r.Approval, r.ApprovalReference, r.InvocationID = &approval, approval.Digest(), approval.InvocationID
	refs := coordinationReferences(approval.InvocationID)
	r.References = &refs
	r.ExecutionState = "APPROVED"
	return r, publishCoordination(dir, r)
}

type coordinationInvalidation struct {
	Version        string `json:"version"`
	ProposalDigest string `json:"proposalDigest"`
	Reason         string `json:"reason"`
}

type coordinationReturn struct {
	Version        string `json:"version"`
	ProposalDigest string `json:"proposalDigest"`
	InvocationID   string `json:"invocationID"`
	EngineInvoked  bool   `json:"engineInvoked"`
	Reason         string `json:"reason"`
}

func (c *Cluster) StartCoordination(ctx context.Context, dir string) (CoordinationRecord, error) {
	state, err := c.boundCoordination(dir)
	if err != nil {
		return CoordinationRecord{}, err
	}
	r := baseCoordination(state.Proposal)
	gate, err := coordinationLock(ctx, dir)
	if err != nil {
		return r, err
	}
	closed := false
	defer func() {
		if !closed {
			_ = gate.Close()
		}
	}()
	approval, auth, err := readCoordinationApproval(dir, state, c)
	if err != nil {
		return r, err
	}
	r.Approval, r.ApprovalReference, r.InvocationID = &approval, approval.Digest(), approval.InvocationID
	refs := coordinationReferences(approval.InvocationID)
	r.References = &refs
	if !absent(filepath.Join(dir, "stop-request.json")) || !absent(filepath.Join(dir, "invalidated.json")) || !absent(filepath.Join(dir, "execution-claim.json")) {
		r.ExecutionState = "START_REFUSED"
		return r, kubefault.ErrDenied
	}
	claim := coordinationClaim{CoordinationClaimVersion, state.ProposalDigest, approval.InvocationID, time.Now().UTC()}
	if err = writePrivate(filepath.Join(dir, "execution-claim.json"), claim); err != nil {
		return r, err
	}
	r.ExecutionState, r.CleanupDisposition = "EXECUTION_UNCERTAIN", "UNKNOWN"
	if err = gate.Close(); err != nil {
		return r, err
	}
	closed = true
	// The existing engine revalidates immediately before Apply. This additional
	// check compares the exact frozen request/preview at the operator boundary.
	err = c.checkCoordination(ctx, state)
	invoked := err == nil
	var report Report
	if invoked {
		report, _, err = c.executeCoordinated(ctx, state.Proposal.Plan, auth, filepath.Join(dir, "runs"), func(path string) (journalFile, error) { return localstate.OpenNew(path) }, dir, state.ProposalDigest)
	}
	reason := "EngineReturned"
	if !invoked {
		reason = "AdmissionFailedBeforeEngine"
		r.ExecutionState, r.CleanupDisposition = "DENIED_NOT_RUN", "NOT_REQUIRED"
	}
	if report.Version != "" {
		r.LiveResult = &report
		r.ExecutionState, r.CleanupDisposition = string(report.Execution), report.Cleanup
	}
	publicationErr := writePrivate(filepath.Join(dir, "execution-return.json"), coordinationReturn{"themis.kubernetes-coordination-return/v1alpha1", state.ProposalDigest, approval.InvocationID, invoked, reason})
	if publicationErr == nil {
		publicationErr = publishCoordination(dir, r)
	}
	if publicationErr != nil {
		r.Problems = append(r.Problems, "coordination publication failed; experiment history remains authoritative")
		return r, publicationErr
	}
	return r, err
}

func readCoordinationClaim(dir string, state coordinationState, invocation string) (*coordinationClaim, error) {
	var claim coordinationClaim
	err := localstate.Read(filepath.Join(dir, "execution-claim.json"), &claim)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if claim.Version != CoordinationClaimVersion || claim.ProposalDigest != state.ProposalDigest || claim.InvocationID != invocation || claim.CreatedAt.IsZero() {
		return nil, kubefault.ErrDenied
	}
	return &claim, nil
}

func (c *Cluster) InspectCoordination(ctx context.Context, dir string) (CoordinationRecord, error) {
	state, err := c.boundCoordination(dir)
	if err != nil {
		return CoordinationRecord{}, err
	}
	r := baseCoordination(state.Proposal)
	approval, auth, err := readCoordinationApproval(dir, state, c)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		r.ExecutionState, r.CleanupDisposition = "APPROVAL_UNCERTAIN", "UNKNOWN"
		r.Problems = append(r.Problems, "approval is missing, corrupt or incompletely published")
		return r, nil
	}
	if err == nil {
		r.Approval, r.ApprovalReference, r.InvocationID = &approval, approval.Digest(), approval.InvocationID
		refs := coordinationReferences(approval.InvocationID)
		r.References = &refs
		r.ExecutionState = "APPROVED"
		if !time.Now().Before(approval.ApplyBefore) {
			r.ExecutionState = "APPROVAL_EXPIRED_NOT_RUN"
		}
	}
	stop, err := coordinationStop(dir, state.Proposal.PlanDigest, r.InvocationID, state.ProposalDigest)
	if err != nil {
		r.Problems = append(r.Problems, "invalid cancellation record")
		r.CancellationState = "UNKNOWN"
	} else if stop != nil {
		r.Action = stop
		r.CancellationState = "ACCEPTED"
	}
	if stop == nil && err == nil {
		var late CoordinationAction
		lateErr := localstate.Read(filepath.Join(dir, "late-cancel.json"), &late)
		if lateErr == nil && late.Version == CoordinationActionVersion && late.ProposalDigest == state.ProposalDigest && late.PlanDigest == state.Proposal.PlanDigest && late.InvocationID == r.InvocationID && late.AlreadyFinalized && validID(late.ID) && !late.RequestedAt.IsZero() {
			r.Action = &late
			r.CancellationState = "AFTER_FINALIZATION"
		} else if !errors.Is(lateErr, os.ErrNotExist) {
			r.CancellationState = "UNKNOWN"
			r.Problems = append(r.Problems, "invalid late cancellation record")
		}
	}
	if !absent(filepath.Join(dir, "invalidated.json")) {
		r.ExecutionState = "INVALIDATED_NOT_RUN"
	}
	if r.Approval == nil {
		return r, nil
	}
	claim, err := readCoordinationClaim(dir, state, r.InvocationID)
	if err != nil {
		r.ExecutionState, r.CleanupDisposition = "CLAIM_UNCERTAIN", "UNKNOWN"
		r.Problems = append(r.Problems, "invalid execution claim")
		return r, nil
	}
	if claim == nil {
		if stop != nil {
			r.ExecutionState, r.CleanupDisposition = "NOT_RUN", "CLEANUP_PENDING"
			receipt, problem := priorReceipt(dir, inventory{Plan: state.Proposal.Plan, Authorization: auth})
			if problem != "" {
				r.Problems = append(r.Problems, problem)
			}
			if receipt != nil {
				r.CleanupReceipt, r.CleanupDisposition = receipt, receipt.OperationalState
				if receipt.Status != nil && receipt.Status.Applied {
					r.ExecutionState = "UNINDEXED_APPLICATION_OBSERVED"
				}
			}
		}
		return r, nil
	}
	r.ExecutionState, r.CleanupDisposition = "EXECUTION_UNCERTAIN", "UNKNOWN"
	var returned coordinationReturn
	if localstate.Read(filepath.Join(dir, "execution-return.json"), &returned) == nil && returned.Version == "themis.kubernetes-coordination-return/v1alpha1" && returned.ProposalDigest == state.ProposalDigest && returned.InvocationID == r.InvocationID && !returned.EngineInvoked && returned.Reason == "AdmissionFailedBeforeEngine" {
		r.ExecutionState, r.CleanupDisposition = "DENIED_NOT_RUN", "NOT_REQUIRED"
		return r, nil
	}
	runDir := filepath.Join(dir, filepath.FromSlash(r.References.RunDirectory))
	inspection, err := c.Inspect(ctx, runDir)
	if err != nil {
		r.Problems = append(r.Problems, "original protected execution inventory unavailable; no target identity guessed")
		return r, nil
	}
	r.Historical = &inspection
	if inspection.Historical != nil && inspection.JournalValid {
		r.ExecutionState, r.CleanupDisposition = string(inspection.Historical.Execution), inspection.Historical.Cleanup
	}
	if !inspection.JournalComplete {
		r.ExecutionState = "INTERRUPTED_OR_ACTIVE"
	}
	if inspection.Current.PriorCleanupReceipt != nil && inspection.Current.PriorCleanupReceipt.OperationalState == "CLEANUP_COMPLETE" {
		r.CleanupDisposition = "COMPLETE_CURRENT_RECEIPT"
	}
	return r, nil
}

func (c *Cluster) CancelCoordination(ctx context.Context, dir string) (CoordinationRecord, error) {
	state, err := c.boundCoordination(dir)
	if err != nil {
		return CoordinationRecord{}, err
	}
	r := baseCoordination(state.Proposal)
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	gate, err := coordinationLock(ctx, dir)
	if err != nil {
		return r, err
	}
	closed := false
	defer func() {
		if !closed {
			_ = gate.Close()
		}
	}()
	approval, auth, authErr := readCoordinationApproval(dir, state, c)
	if authErr != nil && !errors.Is(authErr, os.ErrNotExist) {
		return r, authErr
	}
	var claim *coordinationClaim
	if authErr == nil {
		r.Approval, r.ApprovalReference, r.InvocationID = &approval, approval.Digest(), approval.InvocationID
		refs := coordinationReferences(approval.InvocationID)
		r.References = &refs
		claim, err = readCoordinationClaim(dir, state, approval.InvocationID)
		if err != nil {
			return r, err
		}
	}
	finalized := false
	if r.References != nil {
		events, readErr := ReadJournal(filepath.Join(dir, filepath.FromSlash(r.References.Journal)))
		if readErr == nil {
			finalized = events[0].Plan.Digest() == state.Proposal.PlanDigest && events[0].Authorization.InvocationID == r.InvocationID && events[len(events)-1].Type == "FINAL"
		}
	}
	action := CoordinationAction{CoordinationActionVersion, kubefault.RandomID(), state.ProposalDigest, state.Proposal.PlanDigest, r.InvocationID, time.Now().UTC(), finalized}
	if err = writePrivate(filepath.Join(dir, "action-"+action.ID+".json"), action); err != nil {
		return r, err
	}
	if !finalized && absent(filepath.Join(dir, "stop-request.json")) {
		if err = writePrivate(filepath.Join(dir, "stop-request.json"), action); err != nil {
			return r, err
		}
	}
	if finalized && absent(filepath.Join(dir, "late-cancel.json")) {
		if err = writePrivate(filepath.Join(dir, "late-cancel.json"), action); err != nil {
			return r, err
		}
	}
	if err = gate.Close(); err != nil {
		return r, err
	}
	closed = true
	r.Action = &action
	r.CancellationState = "ACCEPTED"
	if finalized {
		r.CancellationState = "AFTER_FINALIZATION"
	}
	if authErr == nil {
		var receipt CleanupReceipt
		if claim != nil {
			receipt, err = c.Cancel(ctx, filepath.Join(dir, filepath.FromSlash(r.References.RunDirectory)))
		} else {
			// No execution claim can appear after the durable stop. This protected
			// pre-execution approval can safely fence its unused fixture invocation.
			a := Action{ActionVersion, action.ID, "cancel", action.PlanDigest, action.InvocationID, action.RequestedAt, false}
			receipt = c.cleanupOriginal(ctx, inventory{Plan: state.Proposal.Plan, Authorization: auth}, a)
			persisted := true
			receipt.ReceiptPersisted = &persisted
			if err = writePrivate(filepath.Join(dir, "cleanup-"+action.ID+".json"), receipt); err != nil {
				persisted = false
				receipt.OperationalState = "CLEANUP_PENDING"
				err = ErrReceiptPublication
			}
		}
		if receipt.Version != "" {
			r.CleanupReceipt = &receipt
			r.CleanupDisposition = receipt.OperationalState
			if claim == nil && receipt.Status != nil && receipt.Status.Applied {
				r.ExecutionState = "UNINDEXED_APPLICATION_OBSERVED"
				r.Problems = append(r.Problems, "fixture records application outside this coordination execution claim; no execution history inferred")
			}
		} else {
			r.CleanupDisposition = "CLEANUP_PENDING"
			r.Problems = append(r.Problems, "execution inventory unavailable; no cleanup mutation attempted")
		}
	}
	if claim != nil {
		if current, inspectErr := c.InspectCoordination(ctx, dir); inspectErr == nil {
			r.Historical = current.Historical
			r.ExecutionState = current.ExecutionState
			r.Problems = append(r.Problems, current.Problems...)
		}
	}
	if publicationErr := publishCoordination(dir, r); publicationErr != nil {
		return r, publicationErr
	}
	return r, err
}

func (c *Cluster) ReconcileCoordination(ctx context.Context, dir string) (CoordinationRecord, error) {
	state, err := c.boundCoordination(dir)
	if err != nil {
		return CoordinationRecord{}, err
	}
	approval, _, err := readCoordinationApproval(dir, state, c)
	if err != nil {
		return baseCoordination(state.Proposal), err
	}
	claim, err := readCoordinationClaim(dir, state, approval.InvocationID)
	if err != nil {
		return baseCoordination(state.Proposal), err
	}
	if claim == nil {
		return c.CancelCoordination(ctx, dir)
	}
	refs := coordinationReferences(approval.InvocationID)
	receipt, cleanupErr := c.Reconcile(ctx, filepath.Join(dir, filepath.FromSlash(refs.RunDirectory)))
	r, err := c.InspectCoordination(ctx, dir)
	if err != nil {
		return r, err
	}
	if receipt.Version != "" {
		r.CleanupReceipt = &receipt
		r.CleanupDisposition = receipt.OperationalState
	} else {
		r.CleanupDisposition = "CLEANUP_PENDING"
	}
	if err = publishCoordination(dir, r); err != nil {
		return r, err
	}
	return r, cleanupErr
}

func VerifyCoordination(dir string) (EvidenceVerification, error) {
	state, err := loadCoordination(dir)
	if err != nil {
		return EvidenceVerification{}, err
	}
	var approval CoordinationApproval
	if err = localstate.Read(filepath.Join(dir, "approval.json"), &approval); err != nil {
		return EvidenceVerification{}, err
	}
	if approval.Version != CoordinationApprovalVersion || approval.ProposalDigest != state.ProposalDigest || approval.PlanDigest != state.Proposal.PlanDigest || !validID(approval.InvocationID) {
		return EvidenceVerification{}, kubefault.ErrDenied
	}
	refs := coordinationReferences(approval.InvocationID)
	r, err := VerifyEvidence(filepath.Join(dir, filepath.FromSlash(refs.Journal)), state.Proposal.PlanDigest)
	if err == nil && r.InvocationID != approval.InvocationID {
		r.BindingsValid = false
		r.Problems = append(r.Problems, "journal invocation differs from coordination approval")
	}
	return r, err
}

// Public shape validation checks bindings, not the truth of imported claims.
func (r CoordinationRecord) Validate() error {
	if r.Version != CoordinationVersion || r.Proposal.Validate() != nil || r.ProposalDigest != r.Proposal.Digest() || !reflect.DeepEqual(r.Provenance, baseCoordination(r.Proposal).Provenance) {
		return kubefault.ErrDenied
	}
	if !slices.Contains([]string{"NOT_RUN", "APPROVED", "APPROVAL_EXPIRED_NOT_RUN", "APPROVAL_UNCERTAIN", "INVALIDATED_NOT_RUN", "START_REFUSED", "CLAIM_UNCERTAIN", "EXECUTION_UNCERTAIN", "DENIED_NOT_RUN", "INTERRUPTED_OR_ACTIVE", "UNINDEXED_APPLICATION_OBSERVED", "SUCCEEDED", "FAILED", "CANCELLED", "TIMED_OUT", "ERROR", "CLEANUP_PENDING"}, r.ExecutionState) || !slices.Contains([]string{"NOT_REQUESTED", "ACCEPTED", "AFTER_FINALIZATION", "UNKNOWN"}, r.CancellationState) || !slices.Contains([]string{"NOT_REQUIRED", "UNKNOWN", "COMPLETE", "PENDING", "CLEANUP_COMPLETE", "CLEANUP_PENDING", "COMPLETE_CURRENT_RECEIPT"}, r.CleanupDisposition) {
		return kubefault.ErrDenied
	}
	if r.Approval != nil {
		a := r.Approval
		if a.Version != CoordinationApprovalVersion || a.ProposalDigest != r.ProposalDigest || a.PlanDigest != r.Proposal.PlanDigest || a.ApproverKey != r.Proposal.ApproverKey || !validID(a.InvocationID) || r.InvocationID != a.InvocationID || r.ApprovalReference != a.Digest() || a.IssuedAt.IsZero() || a.ApplyBefore.Sub(a.IssuedAt) != 20*time.Second || a.CleanupBefore.Sub(a.IssuedAt) != 90*time.Second || r.References == nil || !reflect.DeepEqual(*r.References, coordinationReferences(a.InvocationID)) {
			return kubefault.ErrDenied
		}
	} else if r.InvocationID != "" || r.ApprovalReference != "" || r.References != nil {
		return kubefault.ErrDenied
	}
	if r.LiveResult != nil && (r.LiveResult.PlanDigest != r.Proposal.PlanDigest || r.LiveResult.Plan.Digest() != r.Proposal.PlanDigest || r.LiveResult.Authorization.PlanDigest != r.Proposal.PlanDigest || r.LiveResult.Authorization.InvocationID != r.InvocationID) {
		return kubefault.ErrDenied
	}
	if r.Action != nil && (r.Action.Version != CoordinationActionVersion || !validID(r.Action.ID) || r.Action.ProposalDigest != r.ProposalDigest || r.Action.PlanDigest != r.Proposal.PlanDigest || r.Action.InvocationID != "" && r.Action.InvocationID != r.InvocationID || r.Action.RequestedAt.IsZero()) {
		return kubefault.ErrDenied
	}
	if r.CleanupReceipt != nil && (r.CleanupReceipt.PlanDigest != r.Proposal.PlanDigest || r.CleanupReceipt.InvocationID != r.InvocationID) {
		return kubefault.ErrDenied
	}
	if r.Historical != nil {
		for _, report := range []*Report{r.Historical.Historical, r.Historical.RecordedReport} {
			if report != nil && (report.PlanDigest != r.Proposal.PlanDigest || report.Authorization.InvocationID != r.InvocationID) {
				return kubefault.ErrDenied
			}
		}
		if v := r.Historical.Verification; v != nil && (v.PlanDigest != r.Proposal.PlanDigest || v.InvocationID != r.InvocationID || v.TrustedExecutionVerdict == "PASS") {
			return kubefault.ErrDenied
		}
	}
	if r.Verification != nil && (r.Verification.PlanDigest != r.Proposal.PlanDigest || r.Verification.InvocationID != r.InvocationID || r.Verification.TrustedExecutionVerdict == "PASS") {
		return kubefault.ErrDenied
	}
	return nil
}
