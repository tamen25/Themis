package kubeexperiment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/kube"
	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Controlled Kubernetes reads, real signed HTTP fixture, durable private files
// and OS locks. Real Kind coverage uses independent CLI processes separately.
func coordinatedFixture(t *testing.T, scenario string, approve bool) (*Cluster, string, CoordinationRecord) {
	t.Helper()
	c, _, _ := executionFixture(t)
	dir := filepath.Join(c.StateDirectory, "coordination")
	r, err := c.PrepareCoordination(context.Background(), "latency-request", scenario, dir)
	if err != nil {
		t.Fatal(err)
	}
	if approve {
		r, err = c.ApproveCoordination(context.Background(), dir, r.Proposal.PlanDigest)
		if err != nil {
			t.Fatal(err)
		}
	}
	return c, dir, r
}

func TestCoordinationUsesMeasuredEngineAndExistingVerifier(t *testing.T) {
	for _, scenario := range []string{"healthy", "buggy", "noop", "cleanup-denied"} {
		t.Run(scenario, func(t *testing.T) {
			c, dir, approved := coordinatedFixture(t, scenario, true)
			ctx := context.Background()
			r, err := c.StartCoordination(ctx, dir)
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]result.Verdict{"healthy": result.Pass, "buggy": result.Fail, "noop": result.Inconclusive, "cleanup-denied": result.Inconclusive}[scenario]
			if r.LiveResult == nil || r.LiveResult.Verdict != want || r.LiveResult.PlanDigest != approved.Proposal.PlanDigest || r.LiveResult.Authorization.InvocationID != approved.InvocationID || len(r.LiveResult.Observations) == 0 {
				t.Fatalf("actual measured execution: %+v", r.LiveResult)
			}
			data, _ := json.Marshal(r)
			if _, err = DecodeCoordinationRecord(data); err != nil {
				t.Fatal("public record", err)
			}
			var auth kubefault.Authorization
			if localstate.Read(filepath.Join(dir, "authorization.json"), &auth) != nil {
				t.Fatal("missing private approval")
			}
			if bytes.Contains(data, []byte(auth.InvocationKey)) || bytes.Contains(data, []byte(auth.CleanupKey)) || bytes.Contains(data, []byte(c.StateDirectory)) {
				t.Fatal("private authority or absolute state path exposed")
			}
			before, _ := os.ReadDir(dir)
			status, err := c.InspectCoordination(ctx, dir)
			if err != nil || status.Historical == nil {
				t.Fatal("inspection", err)
			}
			after, _ := os.ReadDir(dir)
			if len(before) != len(after) {
				t.Fatal("status published mutable operational state")
			}
			verification, err := VerifyCoordination(dir)
			if err != nil || verification.TrustedExecutionVerdict == result.Pass || verification.Report.CandidateVerdict != want {
				t.Fatal("index changed historical evidence trust", err, verification.Report.CandidateVerdict)
			}
			if _, err = c.StartCoordination(ctx, dir); !errors.Is(err, kubefault.ErrDenied) {
				t.Fatal("duplicate execution admitted", err)
			}
			if _, err = c.ApproveCoordination(ctx, dir, r.Proposal.PlanDigest); !errors.Is(err, kubefault.ErrDenied) {
				t.Fatal("approval replaced", err)
			}
			runDir := filepath.Join(dir, filepath.FromSlash(r.References.RunDirectory))
			journalBefore, _ := os.ReadFile(filepath.Join(runDir, "events.jsonl"))
			if scenario == "cleanup-denied" {
				time.Sleep(time.Second)
			}
			_, _ = c.ReconcileCoordination(ctx, dir)
			journalAfter, _ := os.ReadFile(filepath.Join(runDir, "events.jsonl"))
			if !bytes.Equal(journalBefore, journalAfter) {
				t.Fatal("reconciliation rewrote history")
			}
		})
	}
}

func changeRun(t *testing.T, c *Cluster, f func(map[string]any)) {
	t.Helper()
	u := kube.RunObject()
	if err := c.Reader.Get(context.Background(), client.ObjectKey{Namespace: kube.Namespace, Name: "latency-request"}, u); err != nil {
		t.Fatal(err)
	}
	f(u.Object)
	if err := c.Reader.Update(context.Background(), u); err != nil {
		t.Fatal(err)
	}
}

func TestCoordinationDeniesChangedPreviewAndStickyDrift(t *testing.T) {
	for _, phase := range []string{"before approval", "after approval"} {
		t.Run(phase, func(t *testing.T) {
			c, dir, r := coordinatedFixture(t, "healthy", phase == "after approval")
			changeRun(t, c, func(obj map[string]any) {
				obj["status"].(map[string]any)["preview"].(map[string]any)["digest"] = "sha256:" + strings.Repeat("f", 64)
			})
			if c.Revalidate(context.Background(), r.Proposal.Plan) == nil {
				t.Fatal("untrusted preview content admitted under old digest")
			}
			if phase == "before approval" {
				_, err := c.ApproveCoordination(context.Background(), dir, r.Proposal.PlanDigest)
				if err == nil {
					t.Fatal("changed preview approved")
				}
			} else {
				if _, err := c.StartCoordination(context.Background(), dir); err == nil {
					t.Fatal("changed preview executed")
				}
			}
			changeRun(t, c, func(obj map[string]any) {
				obj["status"].(map[string]any)["preview"].(map[string]any)["digest"] = r.Proposal.Preview.Digest
			})
			if phase == "before approval" {
				if _, err := c.ApproveCoordination(context.Background(), dir, r.Proposal.PlanDigest); err == nil {
					t.Fatal("observed drift reverted and revived proposal")
				}
			} else {
				if _, err := c.StartCoordination(context.Background(), dir); err == nil {
					t.Fatal("observed drift reverted and revived invocation")
				}
			}
		})
	}
}

func TestCoordinationInterruptedApprovalAndMissingInventory(t *testing.T) {
	c, dir, r := coordinatedFixture(t, "healthy", true)
	// A durable execution claim with no engine inventory is ambiguous. Cleanup
	// must never reconstruct a target from the public proposal or journal.
	if err := writePrivate(filepath.Join(dir, "execution-claim.json"), coordinationClaim{CoordinationClaimVersion, r.ProposalDigest, r.InvocationID, time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	status, err := c.InspectCoordination(context.Background(), dir)
	if err != nil || status.ExecutionState != "EXECUTION_UNCERTAIN" || status.CleanupDisposition != "UNKNOWN" {
		t.Fatal(status, err)
	}
	cancelled, err := c.CancelCoordination(context.Background(), dir)
	if err == nil || cancelled.CleanupDisposition != "CLEANUP_PENDING" {
		t.Fatal("missing protected execution inventory guessed", cancelled, err)
	}
	if _, err = c.StartCoordination(context.Background(), dir); err == nil {
		t.Fatal("ambiguous invocation resumed")
	}
	// Half-published approvals cannot be replaced with a fresh lease.
	c2, dir2, r2 := coordinatedFixture(t, "healthy", true)
	if err = os.Remove(filepath.Join(dir2, "approval.json")); err != nil {
		t.Fatal(err)
	}
	if _, err = c2.ApproveCoordination(context.Background(), dir2, r2.Proposal.PlanDigest); err == nil {
		t.Fatal("interrupted approval renewed")
	}
	if _, err = c2.StartCoordination(context.Background(), dir2); err == nil {
		t.Fatal("incomplete approval executed")
	}
	status, err = c2.InspectCoordination(context.Background(), dir2)
	if err != nil || status.ExecutionState != "APPROVAL_UNCERTAIN" || status.CleanupDisposition != "UNKNOWN" {
		t.Fatal("half-published approval reported unused success", status, err)
	}
}

func TestCoordinationExpiredAuthorityCopiedStateAndCorruptClaim(t *testing.T) {
	c, dir, r := coordinatedFixture(t, "healthy", true)
	state, err := loadCoordination(dir)
	if err != nil {
		t.Fatal(err)
	}
	copyDir, err := localstate.CreateDirectory(filepath.Join(c.StateDirectory, "copied"))
	if err != nil {
		t.Fatal(err)
	}
	if writePrivate(filepath.Join(copyDir, "coordination-inventory.json"), state) != nil || writePrivate(filepath.Join(copyDir, "proposal.json"), r.Proposal) != nil {
		t.Fatal("copy setup")
	}
	if _, err = c.boundCoordination(copyDir); err == nil {
		t.Fatal("copied state became authority")
	}
	var signing struct {
		Key string `json:"privateKey"`
	}
	if localstate.Read(filepath.Join(c.StateDirectory, "approver-key.json"), &signing) != nil {
		t.Fatal("missing test approver")
	}
	key, _ := hex.DecodeString(signing.Key)
	auth, err := kubefault.Approve(r.Proposal.Plan, r.Proposal.PlanDigest, ed25519.PrivateKey(key), time.Now().Add(-91*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	approval := CoordinationApproval{CoordinationApprovalVersion, r.ProposalDigest, r.Proposal.PlanDigest, auth.Grant.InvocationID, c.Owner.ApproverKey, auth.Grant.IssuedAt, auth.Grant.ApplyBefore, auth.Grant.CleanupBefore}
	for _, name := range []string{"authorization.json", "approval.json"} {
		if err = os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	if writePrivate(filepath.Join(dir, "authorization.json"), auth) != nil || writePrivate(filepath.Join(dir, "approval.json"), approval) != nil {
		t.Fatal("expired approval setup")
	}
	status, err := c.InspectCoordination(context.Background(), dir)
	if err != nil || status.ExecutionState != "APPROVAL_EXPIRED_NOT_RUN" {
		t.Fatal("expired approval not explicit", err)
	}
	if _, err = c.StartCoordination(context.Background(), dir); !errors.Is(err, kubefault.ErrDenied) {
		t.Fatal("expired invocation executed", err)
	}
	s, err := c.Connect(context.Background(), r.Proposal.Plan)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.Client.Control(context.Background(), auth, "remove"); !errors.Is(err, kubefault.ErrDenied) {
		t.Fatal("expired cleanup authority accepted", err)
	}
	c2, dir2, r2 := coordinatedFixture(t, "healthy", true)
	if writePrivate(filepath.Join(dir2, "execution-claim.json"), coordinationClaim{CoordinationClaimVersion, r2.ProposalDigest, kubefault.RandomID(), time.Now().UTC()}) != nil {
		t.Fatal("claim setup")
	}
	status, err = c2.InspectCoordination(context.Background(), dir2)
	if err != nil || status.ExecutionState != "CLAIM_UNCERTAIN" || status.CleanupDisposition != "UNKNOWN" {
		t.Fatal("corrupt claim guessed", status, err)
	}
	if _, err = c2.StartCoordination(context.Background(), dir2); err == nil {
		t.Fatal("corrupt claim resumed")
	}
}

func TestCoordinationCancellationBeforeApprovalAndBeforeInventory(t *testing.T) {
	for _, phase := range []string{"unapproved", "approved", "claimed"} {
		t.Run(phase, func(t *testing.T) {
			c, dir, r := coordinatedFixture(t, "healthy", phase != "unapproved")
			if phase == "claimed" {
				if err := writePrivate(filepath.Join(dir, "execution-claim.json"), coordinationClaim{CoordinationClaimVersion, r.ProposalDigest, r.InvocationID, time.Now().UTC()}); err != nil {
					t.Fatal(err)
				}
			}
			cancelled, err := c.CancelCoordination(context.Background(), dir)
			if cancelled.CancellationState != "ACCEPTED" {
				t.Fatal("stop not accepted", err)
			}
			if phase != "claimed" && err != nil {
				t.Fatal(err)
			}
			if _, err = c.ApproveCoordination(context.Background(), dir, r.Proposal.PlanDigest); err == nil {
				t.Fatal("cancelled proposal approved")
			}
			if _, err = c.StartCoordination(context.Background(), dir); err == nil {
				t.Fatal("cancelled invocation started")
			}
			if phase == "claimed" {
				var auth kubefault.Authorization
				_ = localstate.Read(filepath.Join(dir, "authorization.json"), &auth)
				report, _, err := c.executeCoordinated(context.Background(), r.Proposal.Plan, auth, filepath.Join(dir, "runs"), func(path string) (journalFile, error) { return localstate.OpenNew(path) }, dir, r.ProposalDigest)
				if err != nil || report.Verdict == result.Pass || !report.CancellationAccepted || *report.FaultAttempted {
					t.Fatal("pre-inventory stop lost", report, err)
				}
			}
		})
	}
}

func TestCoordinationCancellationOrdersWithApplyAndFinal(t *testing.T) {
	for _, phase := range []string{"BASELINE", "INTENT", "APPLIED", "REMOVED", "RECOVERY", "FINAL"} {
		t.Run(phase, func(t *testing.T) {
			c, dir, r := coordinatedFixture(t, "healthy", true)
			var auth kubefault.Authorization
			_ = localstate.Read(filepath.Join(dir, "authorization.json"), &auth)
			if err := writePrivate(filepath.Join(dir, "execution-claim.json"), coordinationClaim{CoordinationClaimVersion, r.ProposalDigest, r.InvocationID, time.Now().UTC()}); err != nil {
				t.Fatal(err)
			}
			pause := &pausedWrite{match: `"type":"` + phase + `"`, entered: make(chan struct{}), release: make(chan struct{})}
			var once sync.Once
			defer once.Do(func() { close(pause.release) })
			done := make(chan Report, 1)
			go func() {
				report, _, _ := c.executeCoordinated(context.Background(), r.Proposal.Plan, auth, filepath.Join(dir, "runs"), func(path string) (journalFile, error) {
					f, err := localstate.OpenNew(path)
					pause.journalFile = f
					return pause, err
				}, dir, r.ProposalDigest)
				done <- report
			}()
			select {
			case <-pause.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("engine never reached", phase)
			}
			actions := make(chan CoordinationRecord, 1)
			go func() { record, _ := c.CancelCoordination(context.Background(), dir); actions <- record }()
			if phase == "INTENT" || phase == "APPLIED" || phase == "FINAL" {
				once.Do(func() { close(pause.release) })
			}
			var action CoordinationRecord
			select {
			case action = <-actions:
			case <-time.After(9 * time.Second):
				t.Fatal("cancel did not finish")
			}
			once.Do(func() { close(pause.release) })
			report := <-done
			if action.Action == nil {
				t.Fatal("missing accepted action")
			}
			if !action.Action.AlreadyFinalized && (report.Verdict == result.Pass || !report.CancellationAccepted) {
				t.Fatal("accepted stop raced into PASS", phase, report)
			}
			if action.Action.AlreadyFinalized && report.Verdict != result.Pass {
				t.Fatal("late cancellation rewrote completion", report)
			}
		})
	}
}

func TestCoordinationPublicFormatRejectsUnboundAndUnsupportedClaims(t *testing.T) {
	_, _, r := coordinatedFixture(t, "healthy", true)
	data, _ := json.Marshal(r)
	for _, test := range []string{"version", "unknown", "case", "duplicate", "identity", "path", "trust", "state"} {
		t.Run(test, func(t *testing.T) {
			var copy CoordinationRecord
			_ = json.Unmarshal(data, &copy)
			var candidate []byte
			switch test {
			case "version":
				copy.Version = "future"
			case "identity":
				copy.Proposal.Plan.Target.Fixture.PodUID = "unrelated"
			case "path":
				copy.References.Journal = "../../unrelated"
			case "trust":
				copy.Provenance.ExecutionAttestation = "VERIFIED"
			case "state":
				copy.ExecutionState = "PASS"
			case "unknown":
				candidate = append([]byte(`{"unknown":true,`), data[1:]...)
			case "case":
				candidate = bytes.Replace(data, []byte(`"version"`), []byte(`"Version"`), 1)
			case "duplicate":
				candidate = append([]byte(`{"version":"bad",`), data[1:]...)
			}
			if candidate == nil {
				candidate, _ = json.Marshal(copy)
			}
			if _, err := DecodeCoordinationRecord(candidate); err == nil {
				t.Fatal("invalid public format accepted", test)
			}
		})
	}
}

func FuzzCoordinationIndexNeverAuthenticatesExecution(f *testing.F) {
	f.Add([]byte(`{"version":"themis.kubernetes-coordination/v1alpha1","executionState":"PASS"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := DecodeCoordinationRecord(data)
		if err == nil && r.Provenance.ExecutionAttestation != "UNVERIFIED" {
			t.Fatal("index authenticated execution")
		}
	})
}
