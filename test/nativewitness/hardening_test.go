package nativewitness_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	adapter "github.com/tamen25/themis/internal/dependencyexperiment"
)

func (h *harness) runnerEvent(p prepared, kind string) {
	h.t.Helper()
	for start := time.Now(); time.Since(start) < 5*time.Second; {
		raw, err := os.ReadFile(filepath.Join(p.directory, "events.jsonl"))
		if err == nil {
			for _, line := range bytes.Split(raw, []byte{'\n'}) {
				var event adapter.Event
				if json.Unmarshal(line, &event) == nil && event.Kind == kind {
					return
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatal("actual runner never reached expected durable boundary", kind)
}

func TestOwnedKindLateCancellationCannotBecomePass(t *testing.T) {
	h := newHarness(t)
	p := h.prepare("late-cancel", "delay", 500)
	runner := h.runner("late-cancel-original-runner", p)
	h.runnerEvent(p, "CLEANUP_CONFIRMED")
	if _, err := os.Stat(filepath.Join(p.directory, "report.json")); !os.IsNotExist(err) {
		t.Fatal("late cancellation was not before original final report")
	}
	h.save("late-cancel-boundary.json", struct {
		ObservedEvent string
		ReportAbsent  bool
	}{"CLEANUP_CONFIRMED", true})
	h.call("late-cancel-accepted-before-finalization", "themis-dependency", 0, "cancel", "--state", filepath.Join(h.state, "runner"), "--directory", p.directory)
	raw, code := h.wait(runner)
	_, _ = h.wait(p.observer)
	_, _ = h.wait(p.witness)
	// Preserve the actual baseline counterexample before asserting its rejection:
	// original T4.3 can return source PASS/exit 0 here despite accepted stop.
	verifyExit := 8
	if code == 0 {
		verifyExit = 0
	}
	result, _ := h.publish("late-cancel", p, "", verifyExit)
	if code != 9 || result.Evidence.Source.Execution != "CANCELLED" || result.Evidence.Source.CandidateVerdict != "INCONCLUSIVE" || result.NativeObservationCorroboration.Status != "OBSERVATIONS_INCOMPLETE" {
		t.Fatalf("accepted pre-final cancellation became success: child=%d source=%s execution=%s; actual output %s", code, result.Evidence.Source.CandidateVerdict, result.Evidence.Source.Execution, raw)
	}
	t.Log("REAL KIND stop accepted after cleanup but before FINAL; original execution remained CANCELLED/INCONCLUSIVE despite healthy independently signed traffic")
}
