package kubeexperiment

import (
	"context"
	"path/filepath"

	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

type Inspection struct {
	Version         string            `json:"version"`
	JournalValid    bool              `json:"journalValid"`
	Historical      *Report           `json:"historicalReplay,omitempty"`
	RecordedVerdict result.Verdict    `json:"unsignedRecordedVerdict"`
	CurrentState    string            `json:"currentResourceState"`
	Status          *kubefault.Status `json:"status,omitempty"`
}

// Inspect never repairs history or removes a fault. A signed current status is
// separate from the unsigned historical record and cannot manufacture recovery.
func (c *Cluster) Inspect(ctx context.Context, dir string) (Inspection, error) {
	r := Inspection{Version: "themis.kubernetes-experiment-inspection/v1alpha1", RecordedVerdict: result.Inconclusive, CurrentState: "UNKNOWN"}
	if replay, err := Replay(filepath.Join(dir, "events.jsonl")); err == nil {
		r.JournalValid = true
		r.Historical = &replay
		var recorded Report
		if localstate.Read(filepath.Join(dir, "report.json"), &recorded) == nil && recorded.PlanDigest == replay.PlanDigest && recorded.Verdict == replay.CandidateVerdict {
			r.RecordedVerdict = recorded.Verdict
		}
	}
	var inv inventory
	if err := localstate.Read(filepath.Join(dir, "inventory.json"), &inv); err != nil {
		return r, err
	}
	if inv.Version != "themis.kubernetes-execution-inventory/v1alpha1" || inv.Authorization.Grant.PlanDigest != inv.Plan.Digest() {
		return r, kubefault.ErrDenied
	}
	s, err := c.Connect(ctx, inv.Plan)
	if err != nil {
		r.CurrentState = "TARGET_UNAVAILABLE_OR_REPLACED"
		return r, nil
	}
	defer s.Close()
	status, err := s.Client.Control(ctx, inv.Authorization, "status")
	if err == nil {
		r.Status = &status
		r.CurrentState = "INACTIVE"
		if status.Active {
			r.CurrentState = "ACTIVE"
		}
	}
	return r, nil
}
