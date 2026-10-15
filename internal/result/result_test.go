package result_test

import (
	"slices"
	"testing"

	"github.com/tamen25/themis/internal/result"
)

func check(id string, verdict result.Verdict) result.AssertionResult {
	return result.AssertionResult{ID: id, Verdict: verdict, Evidence: result.Sufficient}
}

func TestAggregate(t *testing.T) {
	baseline := result.RunEvidence{PreconditionsMet: true}
	pass := check("ready", result.Pass)
	toolError := &result.ExecutionError{Code: "PROBE_ERROR", Message: "collector unavailable"}
	tests := []struct {
		name     string
		checks   []result.AssertionResult
		evidence result.RunEvidence
		want     result.Verdict
	}{
		{"all pass", []result.AssertionResult{pass, check("rate", result.Pass)}, baseline, result.Pass},
		{"fail dominates", []result.AssertionResult{check("f", result.Fail), check("i", result.Inconclusive), check("n", result.NotRun)}, baseline, result.Fail},
		{"inconclusive dominates skipped", []result.AssertionResult{check("i", result.Inconclusive), check("n", result.NotRun)}, baseline, result.Inconclusive},
		{"skipped", []result.AssertionResult{pass, check("n", result.NotRun)}, baseline, result.NotRun},
		{"empty", nil, baseline, result.NotRun},
		{"optional only", []result.AssertionResult{{ID: "optional", Verdict: result.Pass, Evidence: result.Sufficient}}, baseline, result.NotRun},
		{"optional failure visible separately", []result.AssertionResult{pass, {ID: "optional", Verdict: result.Fail}}, baseline, result.Pass},
		{"missing evidence", []result.AssertionResult{{ID: "ready", Verdict: result.Pass}}, baseline, result.Inconclusive},
		{"insufficient evidence", []result.AssertionResult{{ID: "ready", Verdict: result.Pass, Evidence: result.Insufficient}}, baseline, result.Inconclusive},
		{"unsubstantiated failure", []result.AssertionResult{{ID: "ready", Verdict: result.Fail, Evidence: result.Missing}}, baseline, result.Inconclusive},
		{"tool failure", []result.AssertionResult{{ID: "ready", Verdict: result.Pass, Evidence: result.Sufficient, ExecutionError: toolError}}, baseline, result.Inconclusive},
		{"collector failure", []result.AssertionResult{pass}, result.RunEvidence{PreconditionsMet: true, CollectionError: toolError}, result.Inconclusive},
		{"credible fail despite collector failure", []result.AssertionResult{check("f", result.Fail)}, result.RunEvidence{CollectionError: toolError}, result.Fail},
		{"preconditions unknown", []result.AssertionResult{pass}, result.RunEvidence{}, result.Inconclusive},
		{"intervention missing", []result.AssertionResult{pass}, result.RunEvidence{PreconditionsMet: true, InterventionRequired: true}, result.Inconclusive},
		{"intervention proven", []result.AssertionResult{pass}, result.RunEvidence{PreconditionsMet: true, InterventionRequired: true, InterventionObserved: true}, result.Pass},
		{"unknown verdict", []result.AssertionResult{check("unknown", "UNSUPPORTED")}, baseline, result.Inconclusive},
		{"zero verdict", []result.AssertionResult{check("unknown", "")}, baseline, result.Inconclusive},
		{"duplicate results", []result.AssertionResult{pass, pass}, baseline, result.Inconclusive},
		{"missing assertion id", []result.AssertionResult{check("", result.Pass)}, baseline, result.Inconclusive},
		{"all not attempted", []result.AssertionResult{check("n", result.NotRun)}, result.RunEvidence{}, result.NotRun},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var required []string
			for _, check := range tc.checks {
				if check.ID != "optional" && !slices.Contains(required, check.ID) {
					required = append(required, check.ID)
				}
			}
			if got := result.Aggregate(required, tc.checks, tc.evidence); got != tc.want {
				t.Fatalf("Aggregate = %s; want %s", got, tc.want)
			}
			reversed := slices.Clone(tc.checks)
			slices.Reverse(reversed)
			if got := result.Aggregate(required, reversed, tc.evidence); got != tc.want {
				t.Fatalf("reordering changed verdict to %s", got)
			}
		})
	}
}

func TestMissingRequiredResultCannotPass(t *testing.T) {
	baseline := result.RunEvidence{PreconditionsMet: true}
	for _, required := range [][]string{{"ready", "omitted"}, {"ready", "ready"}, {"ready", ""}} {
		if got := result.Aggregate(required, []result.AssertionResult{check("ready", result.Pass)}, baseline); got != result.Inconclusive {
			t.Fatalf("required=%v: got %s; want INCONCLUSIVE", required, got)
		}
	}
	if got := result.Aggregate([]string{"omitted"}, nil, baseline); got != result.Inconclusive {
		t.Fatalf("no results for a declared assertion: got %s", got)
	}
}

func TestAggregationProperties(t *testing.T) {
	verdicts := []result.Verdict{result.Pass, result.Fail, result.Inconclusive, result.NotRun, "UNKNOWN"}
	baseline := result.RunEvidence{PreconditionsMet: true}
	for _, a := range verdicts {
		for _, b := range verdicts {
			for _, c := range verdicts {
				results := []result.AssertionResult{check("a", a), check("b", b), check("c", c)}
				required := []string{"a", "b", "c"}
				want := result.Aggregate(required, results, baseline)
				for i := 0; i < len(results); i++ {
					results = append(results[1:], results[0])
					if got := result.Aggregate(required, results, baseline); got != want {
						t.Fatalf("order changed %s to %s", want, got)
					}
				}
				if want == result.Pass && (a != result.Pass || b != result.Pass || c != result.Pass) {
					t.Fatal("PASS with non-passing required assertion")
				}
				if (a == result.Fail || b == result.Fail || c == result.Fail) && want != result.Fail {
					t.Fatal("credible FAIL did not dominate")
				}
			}
		}
	}
}

func FuzzAggregateNeverFalsePass(f *testing.F) {
	f.Add([]byte{0, 0, 0})
	f.Add([]byte{1, 2, 3, 4})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64 {
			return
		}
		results := make([]result.AssertionResult, len(data))
		required := make([]string, len(data))
		allPass := len(data) > 0
		for i, b := range data {
			results[i] = check(string(rune('a'+i)), []result.Verdict{result.Pass, result.Fail, result.Inconclusive, result.NotRun}[b%4])
			required[i] = results[i].ID
			if b&4 != 0 {
				results[i].Evidence = result.Missing
			}
			if b&8 != 0 {
				results[i].ExecutionError = &result.ExecutionError{Code: "ERROR"}
			}
			allPass = allPass && results[i].Verdict == result.Pass && results[i].Evidence == result.Sufficient && results[i].ExecutionError == nil
		}
		got := result.Aggregate(required, results, result.RunEvidence{PreconditionsMet: true})
		if got == result.Pass && !allPass {
			t.Fatal("PASS without sufficient passing evidence for every required assertion")
		}
		slices.Reverse(results)
		if result.Aggregate(required, results, result.RunEvidence{PreconditionsMet: true}) != got {
			t.Fatal("order-dependent aggregation")
		}
	})
}
