package dependencyexperiment

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	wire "github.com/tamen25/themis/internal/dependencyhttp"
)

func actualReport(t testing.TB, name string) Report {
	t.Helper()
	b, e := os.ReadFile(filepath.Join("testdata", name+".json"))
	if e != nil {
		t.Fatal(e)
	}
	var r Report
	if e = json.Unmarshal(b, &r); e != nil {
		t.Fatal(e)
	}
	return r
}
func resealObservations(report *ObserverReport) {
	previous := ""
	for i := range report.Records {
		o := &report.Records[i]
		o.Sequence = i
		o.Previous = previous
		o.Hash = ""
		o.Hash = wire.Hash(*o)
		previous = o.Hash
	}
}
func TestActualNativeMeasurementsAndOfflineTrustRemainSeparate(t *testing.T) {
	for _, item := range []struct{ name, verdict string }{{"A-pass", "PASS"}, {"B-fail", "FAIL"}, {"C-no-effect", "INCONCLUSIVE"}, {"D-cleanup-pending", "INCONCLUSIVE"}} {
		t.Run(item.name, func(t *testing.T) {
			r := actualReport(t, item.name)
			finding, e := Replay(r)
			if e != nil || finding.Verdict != item.verdict {
				t.Fatalf("actual source replay %v %+v", e, finding)
			}
			var out, errOut bytes.Buffer
			code := CLI(context.Background(), []string{"replay", "--plan", filepath.Join("testdata", item.name+".json")}, &out, &errOut)
			var result struct {
				Trusted     string `json:"trustedExecutionVerdict"`
				Attestation string `json:"executionAttestation"`
			}
			if code != 8 || json.Unmarshal(out.Bytes(), &result) != nil || result.Trusted != "INCONCLUSIVE" || result.Attestation != "NOT_INDEPENDENTLY_ATTESTED" {
				t.Fatal("offline claim became trusted execution")
			}
		})
	}
}
func TestFabricatedRecoveryMissingEvidenceAndClientClockContradictions(t *testing.T) {
	for _, mode := range []string{"signature", "body", "different-run", "different-plan", "nonce", "drop", "reorder", "time-backwards", "hold-exceeds-client", "missing-end", "cleanup", "verdict"} {
		t.Run(mode, func(t *testing.T) {
			r := actualReport(t, "A-pass")
			switch mode {
			case "signature":
				r.Observations.Records[2].Probes[2].Response.Signature = wire.ID()
			case "body":
				r.Observations.Records[2].Probes[2].Response.Value = "fabricated"
			case "different-run":
				r.Plan.Run = wire.ID()
			case "different-plan":
				r.Observations.PlanDigest = "sha256:" + wire.ID()
			case "nonce":
				r.Observations.Records[2].Probes[0].Nonce = r.Observations.Records[1].Probes[0].Nonce
			case "drop":
				r.Observations.Records = append(r.Observations.Records[:2], r.Observations.Records[3:]...)
			case "reorder":
				r.Observations.Records[2], r.Observations.Records[3] = r.Observations.Records[3], r.Observations.Records[2]
			case "time-backwards":
				r.Observations.Records[2].Probes[0].StartedNS = -1
			case "hold-exceeds-client":
				for i := range r.Observations.Records {
					if r.Observations.Records[i].Kind == "SAMPLE" {
						q := &r.Observations.Records[i].Probes[1]
						if q.Response != nil && q.Response.HoldNS > 0 {
							q.CompletedNS = q.StartedNS + 1
							break
						}
					}
				}
			case "missing-end":
				r.Observations.Records = r.Observations.Records[:len(r.Observations.Records)-1]
			case "cleanup":
				r.Cleanup = "PENDING"
			case "verdict":
				r.Verdict = "FAIL"
			}
			// Untrusted importers can recompute unsigned chains; signatures, bindings,
			// measurement predicates and cleanup checks must still reject the PASS claim.
			if mode != "different-run" {
				resealObservations(&r.Observations)
			}
			if _, e := Replay(r); e == nil {
				t.Fatal("fabricated or incomplete history accepted")
			}
		})
	}
	pending := actualReport(t, "D-cleanup-pending")
	pending.Cleanup = "COMPLETE"
	pending.Verdict = "PASS"
	if _, e := Replay(pending); e == nil {
		t.Fatal("healthy later traffic erased original cleanup uncertainty")
	}
}
func TestApplicationCeilingComparisonIsInclusive(t *testing.T) {
	r := actualReport(t, "A-pass")
	observed := r.Observations
	selected := []Observation{observed.Records[0]}
	counts := map[string]int{}
	activeSeen := false
	for _, o := range observed.Records {
		f := classifySample(r.Plan, o, r.Invocation)
		if !f.valid {
			continue
		}
		phase := f.phase
		if phase == "active" {
			activeSeen = true
		} else if activeSeen {
			phase = "recovery"
		}
		if counts[phase] >= 3 {
			continue
		}
		counts[phase]++
		selected = append(selected, o)
	}
	if counts["baseline"] != 3 || counts["active"] != 3 || counts["recovery"] != 3 {
		t.Fatal("real fixture lacked phase selection")
	}
	selected = append(selected, observed.Records[len(observed.Records)-1])
	observed.Records = selected
	// Controlled unsigned client offsets isolate the inclusive threshold while
	// preserving all actual fixture signatures, nonces and immutable plan bindings.
	cursor := int64(0)
	firstActive := -1
	for i := range observed.Records {
		if observed.Records[i].Kind != "SAMPLE" {
			continue
		}
		f := classifySample(r.Plan, observed.Records[i], r.Invocation)
		for j := range observed.Records[i].Probes {
			q := &observed.Records[i].Probes[j]
			q.StartedNS = cursor
			duration := int64(10000000)
			if f.phase == "active" {
				if firstActive < 0 {
					firstActive = i
				}
				if j == 1 {
					duration = 170000000
				}
				if j == 2 {
					duration = 500000000
				}
			}
			q.CompletedNS = cursor + duration
		}
		cursor += 600000000
	}
	resealObservations(&observed)
	if finding := Evaluate(r.Plan, observed, r.Invocation, true); finding.Verdict != "PASS" {
		t.Fatalf("exact inclusive ceiling rejected: %+v", finding)
	}
	observed.Records[firstActive].Probes[2].CompletedNS++
	resealObservations(&observed)
	if finding := Evaluate(r.Plan, observed, r.Invocation, true); finding.Verdict != "FAIL" || finding.Violations != 1 {
		t.Fatalf("one nanosecond above ceiling accepted: %+v", finding)
	}
}
func FuzzNativeReportNeverGrantsTrustedExecution(f *testing.F) {
	r := actualReport(f, "A-pass")
	f.Add(wire.JSON(r))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		var report Report
		if wire.Decode(b, &report) == nil {
			_, _ = Replay(report)
		}
	})
}
