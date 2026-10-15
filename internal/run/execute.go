package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tamen25/themis/internal/contract"
	"github.com/tamen25/themis/internal/localpolicy"
	"github.com/tamen25/themis/internal/plan"
	"github.com/tamen25/themis/internal/probe"
	"github.com/tamen25/themis/internal/result"
)

// Execute persists the frozen inputs before any request, then writes each event
// once and syncs it. It never resumes requests from a previous journal.
func Execute(ctx context.Context, c contract.Validated, options Options) (Report, string, error) {
	slots, duration, err := schedule(c)
	if err != nil {
		return Report{}, "", err
	}
	p, err := plan.Compile(c)
	if err != nil {
		return Report{}, "", err
	}
	if err := admit(c, p, options.ApprovedPlanDigest); err != nil {
		return Report{}, "", err
	}
	if err := ctx.Err(); err != nil {
		return Report{}, "", err
	}
	root := options.Directory
	if root == "" {
		root = filepath.Join(".themis", "runs")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return Report{}, "", fmt.Errorf("create runs directory: %w", err)
	}
	dir, err := os.MkdirTemp(root, "run-")
	if err != nil {
		return Report{}, "", err
	}
	path := filepath.Join(dir, "events.jsonl")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0600)
	if err != nil {
		return Report{}, dir, err
	}
	defer f.Close()
	sequence := 0
	appendEvent := func(e event) error {
		sequence++
		e.SchemaVersion, e.RunID, e.Sequence = SchemaVersion, filepath.Base(dir), sequence
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if _, err := f.Write(append(b, '\n')); err != nil {
			return err
		}
		return f.Sync()
	}
	m := Manifest{Contract: c.NormalizedJSON(), Plan: p.JSON(), ContractDigest: c.Digest(), PlanDigest: p.Digest(), PolicyVersion: PolicyVersion, ApprovedPlan: options.ApprovedPlanDigest, StartedAt: time.Now().UTC()}
	if err := appendEvent(event{Type: "started", Manifest: &m}); err != nil {
		return Report{}, dir, err
	}
	// The observation clock starts after preparation is durable. Startup disk
	// latency is not a missed HTTP observation. Subsequent journal delays are.
	start := time.Now()
	budget, _ := time.ParseDuration(c.Snapshot().Spec.Execution.MaxDuration)
	bounded, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	client := probe.NewClient()
	defer client.Close()
	targetURL := c.Snapshot().Spec.Target.URL
	status := result.Succeeded
	for i, s := range slots {
		if err := waitUntil(bounded, start.Add(s.at)); err != nil {
			break
		}
		if time.Since(start) >= min(s.at+Interval, s.end) {
			continue
		}
		requestCtx, stop := context.WithDeadline(bounded, start.Add(s.end))
		o := client.Collect(requestCtx, targetURL, start)
		stop()
		// Timer delivery and transport completion can race at a deadline. A late
		// response must not fill a slot with evidence outside its phase window.
		if o.CompletedNS > int64(s.end) {
			o.Outcome, o.StatusCode = "cancelled", 0
		} else if o.Outcome == "http" && o.CompletedNS-o.StartedNS > int64(localpolicy.RequestTimeout) {
			o.Outcome, o.StatusCode = "timeout", 0
		}
		if o.StartedNS >= int64(min(s.at+Interval, s.end)) {
			continue
		}
		o.Index, o.Phase = i, s.phase
		if err := appendEvent(event{Type: "sample", Sample: &o}); err != nil {
			return Report{}, dir, fmt.Errorf("journal sample: %w", err)
		}
	}
	// The entire declared observation window must elapse, even when assertions
	// already look healthy. Early success would conceal late failures.
	waitUntil(bounded, start.Add(duration))
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		status = result.TimedOut
	} else if ctx.Err() != nil {
		status = result.Cancelled
	} else if bounded.Err() != nil && time.Since(start) < duration {
		status = result.TimedOut
	}
	terminal := terminal{Status: status, ElapsedNS: time.Since(start).Nanoseconds()}
	if err := appendEvent(event{Type: "finished", Terminal: &terminal}); err != nil {
		return Report{}, dir, err
	}
	if err := f.Close(); err != nil {
		return Report{}, dir, err
	}
	report, err := ReplayFile(path)
	if err != nil {
		return Report{}, dir, err
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return Report{}, dir, err
	}
	// Publish the complete report once; no existing report is overwritten.
	tempReport := filepath.Join(dir, "report.json.tmp")
	output, err := os.OpenFile(tempReport, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return Report{}, dir, err
	}
	_, writeErr := output.Write(append(data, '\n'))
	syncErr := output.Sync()
	closeErr := output.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return Report{}, dir, err
	}
	if err := os.Rename(tempReport, filepath.Join(dir, "report.json")); err != nil {
		return Report{}, dir, err
	}
	return report, dir, nil
}

func waitUntil(ctx context.Context, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	timer := time.NewTimer(time.Until(at))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}
