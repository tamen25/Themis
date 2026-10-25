package run

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tamen25/themis/internal/plan"
	"github.com/tamen25/themis/internal/probe"
	"github.com/tamen25/themis/internal/result"
)

// These are explicitly synthetic unsigned journal fixtures, not live HTTP
// evidence. Exact-count semantics must not depend on host timer guarantees.
func TestControlled100SlotJournalCoverage(t *testing.T) {
	for _, missing := range []int{-1, 0, 37, 99} {
		t.Run(fmt.Sprintf("missing-%d", missing), func(t *testing.T) {
			c := testContract(t, "http://127.0.0.1:8080/", "10s", 100, false)
			p, err := plan.Compile(c)
			if err != nil {
				t.Fatal(err)
			}
			m := Manifest{Contract: c.NormalizedJSON(), Plan: p.JSON(), ContractDigest: c.Digest(), PlanDigest: p.Digest(), PolicyVersion: PolicyVersion, StartedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
			var data bytes.Buffer
			enc := json.NewEncoder(&data)
			seq := 0
			appendEvent := func(e event) {
				seq++
				e.Sequence, e.RunID, e.SchemaVersion = seq, "run-controlled", SchemaVersion
				if err := enc.Encode(e); err != nil {
					t.Fatal(err)
				}
			}
			appendEvent(event{Type: "started", Manifest: &m})
			for i := 0; i < 100; i++ {
				if i == missing {
					continue
				}
				o := probe.Observation{Index: i, Phase: "observe", StartedNS: int64(i)*int64(100*time.Millisecond) + 1, CompletedNS: int64(i)*int64(100*time.Millisecond) + 2, StatusCode: 200, Outcome: "http"}
				appendEvent(event{Type: "sample", Sample: &o})
			}
			end := terminal{Status: result.Succeeded, ElapsedNS: int64(10 * time.Second)}
			appendEvent(event{Type: "finished", Terminal: &end})
			r, err := Replay(bytes.NewReader(data.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			wantSamples, wantVerdict, wantCoverage := 100, result.Pass, result.Sufficient
			if missing >= 0 {
				wantSamples, wantVerdict, wantCoverage = 99, result.Inconclusive, result.Insufficient
			}
			if r.ExpectedSamples != 100 || r.Samples != wantSamples || r.Verdict != wantVerdict || r.Coverage != wantCoverage || r.Signed {
				t.Fatalf("%+v", r)
			}
		})
	}
}

func TestScheduleAndWaitUnderControlledClock(t *testing.T) {
	c := testContract(t, "http://127.0.0.1:8080/", "10s", 100, false)
	slots, duration, err := schedule(c)
	if err != nil || len(slots) != 100 || duration != 10*time.Second {
		t.Fatal("fixed 100-slot policy changed", err)
	}
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		for i, s := range slots {
			if s.at != time.Duration(i)*100*time.Millisecond || s.end != 10*time.Second || s.phase != "observe" {
				t.Fatal("fixed slot boundary changed", s)
			}
			if err := waitUntil(context.Background(), start.Add(s.at)); err != nil {
				t.Fatal(err)
			}
			if time.Since(start) != s.at {
				t.Fatal("controlled timer missed fixed boundary")
			}
		}
		if err := waitUntil(context.Background(), start.Add(duration)); err != nil || time.Since(start) != duration {
			t.Fatal("observation window shortened")
		}
	})
}
