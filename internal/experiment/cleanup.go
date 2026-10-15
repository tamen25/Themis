package experiment

import (
	"context"
	"time"

	"github.com/tamen25/themis/internal/fixture"
	"github.com/tamen25/themis/internal/plan"
)

func residualsClosed(probes []fixture.ListenerState) bool {
	if len(probes) != 3 {
		return false
	}
	for _, probe := range probes {
		if probe.Outcome != "connection-refused" {
			return false
		}
	}
	return true
}

func cleanup(c *fixture.Client, h fixture.FaultHandle, timeout time.Duration) CleanupResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return cleanupResources(ctx, c.Identity, c, h, "runner")
}

// Read-only residual observations can establish disappearance after expiry even
// if private fixture credentials were lost. Mutation always needs a fresh proof
// and the exact inventoried handle; replacement listeners are never controlled.
func cleanupResources(ctx context.Context, id plan.FixtureIdentity, c *fixture.Client, h fixture.FaultHandle, reason string) CleanupResult {
	r := CleanupResult{Version: Version, RunID: h.RunID, CheckedAt: time.Now().UTC()}
	if c != nil {
		if _, err := c.Resolve(ctx); err == nil {
			if err := c.Quiesce(ctx, h, reason); err == nil {
				if err := c.StopRun(ctx, h); err != nil {
					r.Failure = &Failure{Operation: OpCleanup, Code: "SHUTDOWN_UNCONFIRMED", Reason: "owned fixture shutdown was denied or unacknowledged"}
				}
			} else {
				r.Failure = &Failure{Operation: OpCleanup, Code: "QUIESCENCE_UNCONFIRMED", Reason: "permanent fault stop fence was not acknowledged"}
			}
		} else {
			r.Failure = &Failure{Operation: OpCleanup, Code: "FIXTURE_IDENTITY_UNAVAILABLE", Reason: "fixture identity could not be authenticated; no mutation attempted"}
		}
	} else {
		r.Failure = &Failure{Operation: OpCleanup, Code: "FIXTURE_CREDENTIALS_UNAVAILABLE", Reason: "private fixture state is unavailable; no mutation attempted"}
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		r.Residuals, _ = fixture.InspectIdentityListeners(ctx, id)
		r.Completed = residualsClosed(r.Residuals)
		r.CheckedAt = time.Now().UTC()
		if r.Completed {
			r.Failure = nil
			return r
		}
		select {
		case <-ctx.Done():
			if r.Failure == nil {
				r.Failure = &Failure{Operation: OpCleanup, Code: "CLEANUP_DEADLINE_OR_CANCELLATION", Reason: "cleanup deadline expired or command was cancelled with unresolved listeners"}
			}
			return r
		case <-ticker.C:
		}
	}
}
