package kubeexperiment

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

type CurrentObservation struct {
	ObservedAt               time.Time         `json:"observedAt"`
	OriginalFixtureReachable bool              `json:"originalFixtureReachable"`
	ResidualIntervention     string            `json:"residualIntervention"`
	DeadlinePassed           *bool             `json:"deadlinePassed,omitempty"`
	CleanupAuthorityExpired  bool              `json:"cleanupAuthorityExpired"`
	SafeReconciliation       string            `json:"safeReconciliation"`
	Status                   *kubefault.Status `json:"signedStatus,omitempty"`
	PriorCleanupReceipt      *CleanupReceipt   `json:"priorCleanupReceipt,omitempty"`
	ReceiptProblem           string            `json:"receiptProblem,omitempty"`
}

type Inspection struct {
	Version         string                `json:"version"`
	JournalValid    bool                  `json:"journalValid"`
	JournalComplete bool                  `json:"journalComplete"`
	Historical      *Report               `json:"historicalReplay,omitempty"`
	Verification    *EvidenceVerification `json:"historicalVerification,omitempty"`
	RecordedVerdict result.Verdict        `json:"unsignedRecordedVerdict"`
	RecordedReport  *Report               `json:"unsignedRecordedReport,omitempty"`
	CurrentState    string                `json:"currentResourceState"`
	Status          *kubefault.Status     `json:"status,omitempty"`
	Current         CurrentObservation    `json:"currentObservation"`
	Cancellation    *Action               `json:"acceptedCancellation,omitempty"`
	Problems        []string              `json:"problems"`
}

func priorReceipt(dir string, inv inventory) (*CleanupReceipt, string) {
	files, err := os.ReadDir(dir)
	if err != nil || len(files) > 1024 {
		return nil, "ReceiptDirectoryUnavailableOrTooLarge"
	}
	var receipts []CleanupReceipt
	problem := ""
	for _, f := range files {
		if !strings.HasPrefix(f.Name(), "cleanup-") || !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		var receipt CleanupReceipt
		if localstate.Read(filepath.Join(dir, f.Name()), &receipt) != nil || (receipt.Version != "themis.kubernetes-cleanup-receipt/v1alpha1" && receipt.Version != "themis.kubernetes-cleanup-receipt/v1alpha2") || receipt.PlanDigest != inv.Plan.Digest() || receipt.InvocationID != inv.Authorization.Grant.InvocationID {
			problem = "InvalidOrUnboundCleanupReceipt"
			continue
		}
		receipts = append(receipts, receipt)
	}
	if len(receipts) == 0 {
		return nil, problem
	}
	sort.Slice(receipts, func(i, j int) bool { return receipts[i].At.After(receipts[j].At) })
	return &receipts[0], problem
}

// Inspect performs no local publication, target mutation or cleanup. Fresh
// signed state never upgrades the trust of unsigned historical bytes.
func (c *Cluster) Inspect(ctx context.Context, dir string) (Inspection, error) {
	r := Inspection{Version: "themis.kubernetes-experiment-inspection/v1alpha2", RecordedVerdict: result.Inconclusive, CurrentState: "UNKNOWN", Problems: []string{}}
	inv, err := loadInventory(dir)
	if err != nil {
		return r, err
	}
	if err = c.validateInventory(inv); err != nil {
		return r, err
	}
	var recorded Report
	if localstate.Read(filepath.Join(dir, "report.json"), &recorded) == nil && recorded.PlanDigest == inv.Plan.Digest() && recorded.Authorization.InvocationID == inv.Authorization.Grant.InvocationID {
		r.RecordedReport = &recorded
	}
	if verified, err := VerifyEvidence(filepath.Join(dir, "events.jsonl"), inv.Plan.Digest()); err == nil {
		r.Verification = &verified
		r.JournalValid, r.JournalComplete = verified.BindingsValid, verified.JournalComplete
		r.Historical = &verified.Report
		if verified.InvocationID != inv.Authorization.Grant.InvocationID {
			r.JournalValid = false
			r.Problems = append(r.Problems, "journal invocation does not match protected inventory")
		}
		if r.JournalValid && r.JournalComplete && r.RecordedReport != nil && recorded.Verdict == verified.Report.CandidateVerdict {
			r.RecordedVerdict = recorded.Verdict
		}
	} else {
		r.Problems = append(r.Problems, "historical journal is unavailable, corrupt or unsupported")
	}
	r.Cancellation, err = stopRequested(dir, inv)
	if err != nil {
		r.Problems = append(r.Problems, "cancellation record is invalid")
	}
	r.Current = CurrentObservation{ObservedAt: time.Now().UTC(), ResidualIntervention: "UNKNOWN", SafeReconciliation: "UNKNOWN", CleanupAuthorityExpired: !time.Now().Before(inv.Authorization.Grant.CleanupBefore)}
	r.Current.PriorCleanupReceipt, r.Current.ReceiptProblem = priorReceipt(dir, inv)
	s, err := c.connectOriginal(ctx, inv.Plan)
	if err != nil {
		r.CurrentState = "TARGET_UNAVAILABLE_OR_REPLACED"
		return r, nil
	}
	defer s.Close()
	r.Current.OriginalFixtureReachable = true
	status, err := s.Client.Control(ctx, inv.Authorization, "status")
	if err != nil {
		return r, nil
	}
	r.Status, r.Current.Status = &status, &status
	r.CurrentState, r.Current.ResidualIntervention = "INACTIVE", "ABSENT"
	if status.Active {
		r.CurrentState, r.Current.ResidualIntervention = "ACTIVE", "CONFIRMED"
	}
	if !status.ExpiresAt.IsZero() {
		passed := !time.Now().Before(status.ExpiresAt)
		r.Current.DeadlinePassed = &passed
	}
	if !r.Current.CleanupAuthorityExpired {
		r.Current.SafeReconciliation = "EXACT_ORIGINAL_IDENTITY_AND_AUTHORITY_AVAILABLE"
	}
	return r, nil
}
