package run

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/contract"
	"github.com/tamen25/themis/internal/plan"
	"github.com/tamen25/themis/internal/probe"
	"github.com/tamen25/themis/internal/result"
)

func testContract(t *testing.T, url, duration string, minimum int, approval bool) contract.Validated {
	t.Helper()
	input := fmt.Sprintf(`schemaVersion: themis.contract/v1alpha1
metadata: {name: local-http-health, owner: themis-test}
spec:
  target: {kind: local-http, name: demo, url: %q}
  execution: {maxDuration: 12s, requireApproval: %t}
  scenario: {id: health, phases: [{name: observe, duration: %s}]}
  assertions:
    - {id: readiness, type: http-ready, deadline: %s}
    - {id: error-rate, type: http-success-rate, minSamples: %d, maximumErrorFraction: 0.03}
`, url, approval, duration, duration, minimum)
	c, err := contract.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRealHealthyRunCollects100SamplesAndReplays(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(200) }))
	defer server.Close()
	c := testContract(t, server.URL, "10s", 100, false)
	r, dir, err := Execute(context.Background(), c, Options{Directory: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != result.Pass || r.Coverage != result.Sufficient || r.Samples != 100 || requests.Load() != 100 || r.Execution.Status != result.Succeeded || r.Signed {
		t.Fatalf("report=%+v requests=%d", r, requests.Load())
	}
	replayed, err := ReplayFile(filepath.Join(dir, "events.jsonl"))
	if err != nil || !reflect.DeepEqual(r, replayed) {
		t.Fatalf("replay=%+v err=%v", replayed, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved Report
	if err := json.Unmarshal(data, &saved); err != nil || !reflect.DeepEqual(r, saved) {
		t.Fatalf("saved=%+v err=%v", saved, err)
	}
	if requests.Load() != 100 {
		t.Fatal("replay contacted target")
	}
}

func TestRealUnhealthyRunFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer server.Close()
	r, _, err := Execute(context.Background(), testContract(t, server.URL, "200ms", 2, false), Options{Directory: t.TempDir()})
	if err != nil || r.Verdict != result.Fail || r.Coverage != result.Sufficient || r.Execution.Status != result.Succeeded {
		t.Fatalf("report=%+v err=%v", r, err)
	}
}

func TestSlowCollectionCannotPass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(130 * time.Millisecond); w.WriteHeader(200) }))
	defer server.Close()
	r, _, err := Execute(context.Background(), testContract(t, server.URL, "400ms", 4, false), Options{Directory: t.TempDir()})
	if err != nil || r.Verdict != result.Inconclusive || r.Coverage == result.Sufficient || r.Samples >= r.ExpectedSamples {
		t.Fatalf("report=%+v err=%v", r, err)
	}
}

func TestCancellationPersistsPartialEvidence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel()
		<-r.Context().Done()
	}))
	defer server.Close()
	r, dir, err := Execute(ctx, testContract(t, server.URL, "1s", 10, false), Options{Directory: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if r.Execution.Status != result.Cancelled || r.Verdict == result.Pass || r.Coverage == result.Sufficient {
		t.Fatalf("%+v", r)
	}
	replayed, err := ReplayFile(filepath.Join(dir, "events.jsonl"))
	if err != nil || !reflect.DeepEqual(r, replayed) {
		t.Fatalf("replay=%+v err=%v", replayed, err)
	}
}

func TestAdmissionPrecedesFilesAndRequests(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer server.Close()
	for _, tc := range []struct {
		name     string
		c        contract.Validated
		approval string
	}{
		{"missing approval", testContract(t, server.URL, "200ms", 2, true), ""},
		{"wrong approval", testContract(t, server.URL, "200ms", 2, false), "sha256:wrong"},
		{"impossible coverage", testContract(t, server.URL, "200ms", 100, false), ""},
		{"unvalidated", contract.Validated{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "must-not-exist")
			_, _, err := Execute(context.Background(), tc.c, Options{Directory: root, ApprovedPlanDigest: tc.approval})
			if !errors.Is(err, ErrAdmission) {
				t.Fatalf("%v", err)
			}
			if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("denial created state")
			}
		})
	}
	if requests.Load() != 0 {
		t.Fatal("denial contacted target")
	}
	c := testContract(t, server.URL, "200ms", 2, true)
	p, _ := plan.Compile(c)
	if r, _, err := Execute(context.Background(), c, Options{Directory: t.TempDir(), ApprovedPlanDigest: p.Digest()}); err != nil || r.Verdict != result.Pass {
		t.Fatalf("report=%+v err=%v", r, err)
	}
}

func TestThresholdUsesExactCanonicalDecimal(t *testing.T) {
	for _, tc := range []struct {
		failures, samples int
		threshold         float64
		want              bool
	}{
		{3, 100, 0.03, false}, {4, 100, 0.03, true}, {1, 33, 0.03, true}, {0, 100, 0, false}, {100, 100, 1, false},
		{3, 100, math.Nextafter(0.03, 0), true}, {3, 100, math.Nextafter(0.03, 1), false},
	} {
		if got := exceeds(tc.failures, tc.samples, tc.threshold); got != tc.want {
			t.Fatalf("%+v: %v", tc, got)
		}
	}
}

func TestReplayFixtures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		verdict result.Verdict
	}{{"healthy", result.Pass}, {"unhealthy", result.Fail}} {
		data, err := os.ReadFile(filepath.Join("testdata", tc.name+".jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		first, err := Replay(bytes.NewReader(data))
		if err != nil || first.Verdict != tc.verdict || first.Coverage != result.Sufficient {
			t.Fatalf("%s: %+v err=%v", tc.name, first, err)
		}
		second, err := Replay(bytes.NewReader(data))
		if err != nil || !reflect.DeepEqual(first, second) {
			t.Fatal("replay is nondeterministic")
		}
		golden, err := os.ReadFile(filepath.Join("testdata", tc.name+"-report.json"))
		if err != nil {
			t.Fatal(err)
		}
		actual, _ := json.MarshalIndent(first, "", "  ")
		if !bytes.Equal(bytes.TrimSpace(golden), actual) {
			t.Fatalf("%s report differs from reviewed fixture", tc.name)
		}
	}
}

func TestInvalidAndIncompleteJournal(t *testing.T) {
	data, err := os.ReadFile("testdata/healthy.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"truncated", data[:len(data)-5]},
		{"unknown version", bytes.Replace(data, []byte(SchemaVersion), []byte("unknown"), 1)},
		{"unknown field", bytes.Replace(data, []byte(`"sequence":1`), []byte(`"surprise":true,"sequence":1`), 1)},
		{"digest", bytes.Replace(data, []byte(`"contractDigest":"sha256:`), []byte(`"contractDigest":"sha256:x`), 1)},
		{"policy", bytes.Replace(data, []byte(PolicyVersion), []byte("unknown"), 1)},
		{"wrong plan", bytes.Replace(data, []byte(`"mode":"planning-only"`), []byte(`"mode":"execute"`), 1)},
		{"duplicate sample", bytes.Join([][]byte{lines[0], lines[1], lines[1], lines[2], lines[3]}, []byte("\n"))},
		{"wrong phase", bytes.Replace(data, []byte(`"phase":"observe"`), []byte(`"phase":"elsewhere"`), 1)},
		{"negative time", bytes.Replace(data, []byte(`"startedNS":1000000`), []byte(`"startedNS":-1`), 1)},
		{"late response", bytes.Replace(data, []byte(`"completedNS":102000000`), []byte(`"completedNS":201000000`), 1)},
		{"after terminal", append(bytes.Clone(data), lines[1]...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Replay(bytes.NewReader(tc.data)); err == nil {
				t.Fatal("invalid journal accepted")
			}
		})
	}
	// A crash between complete records is readable, but cannot establish PASS.
	partial := bytes.Join(lines[:3], []byte("\n"))
	r, err := Replay(bytes.NewReader(partial))
	if err != nil || r.Verdict == result.Pass || r.Execution.Status != result.Error || r.Coverage == result.Sufficient {
		t.Fatalf("report=%+v err=%v", r, err)
	}
	// A missing observation remains a gap even if the remaining probe is healthy.
	var last event
	if err := json.Unmarshal(lines[3], &last); err != nil {
		t.Fatal(err)
	}
	last.Sequence = 3
	lastJSON, _ := json.Marshal(last)
	r, err = Replay(bytes.NewReader(bytes.Join([][]byte{lines[0], lines[1], lastJSON}, []byte("\n"))))
	if err != nil || r.Verdict == result.Pass || r.Coverage == result.Sufficient {
		t.Fatalf("report=%+v err=%v", r, err)
	}
}

func TestCredibleReadinessFailureSurvivesLaterCancellation(t *testing.T) {
	c := testContract(t, "http://127.0.0.1:8080/", "1s", 10, false)
	// Change readiness deadline without altering the test helper's sample policy.
	c, err := contract.Parse(bytes.NewReader(bytes.Replace(c.NormalizedJSON(), []byte(`"deadline":"1s"`), []byte(`"deadline":"200ms"`), 1)))
	if err != nil {
		t.Fatal(err)
	}
	slots, duration, _ := schedule(c)
	samples := []probe.Observation{{Index: 0, CompletedNS: 1, StatusCode: 503, Outcome: "http"}, {Index: 1, CompletedNS: 100000001, StatusCode: 503, Outcome: "http"}}
	r := evaluate("run-1", c, Manifest{}, slots, duration, samples, terminal{Status: result.Cancelled, ElapsedNS: 300000000}, "digest")
	if r.Verdict != result.Fail || r.Execution.Status != result.Cancelled {
		t.Fatalf("%+v", r)
	}
}

func FuzzReplay(f *testing.F) {
	for _, name := range []string{"healthy", "unhealthy"} {
		data, err := os.ReadFile(filepath.Join("testdata", name+".jsonl"))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := Replay(bytes.NewReader(data))
		if err == nil && r.Verdict == result.Pass && (r.Coverage != result.Sufficient || r.Execution.Status != result.Succeeded || r.Samples != r.ExpectedSamples || r.Samples == 0) {
			t.Fatalf("false PASS: %+v", r)
		}
	})
}

func TestPhaseOrderAndRefusedConnections(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	url := server.URL
	server.Close()
	c := testContract(t, url, "200ms", 2, false)
	c, err := contract.Parse(bytes.NewReader(bytes.Replace(c.NormalizedJSON(), []byte(`[{"name":"observe","duration":"200ms"}]`), []byte(`[{"name":"first","duration":"100ms"},{"name":"second","duration":"100ms"}]`), 1)))
	if err != nil {
		t.Fatal(err)
	}
	r, dir, err := Execute(context.Background(), c, Options{Directory: t.TempDir()})
	if err != nil || r.Verdict != result.Fail || r.Samples != 2 {
		t.Fatalf("report=%+v err=%v", r, err)
	}
	f, err := os.Open(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	var phases []string
	for i := 0; i < 4; i++ {
		var e event
		if err := decoder.Decode(&e); err != nil {
			t.Fatal(err)
		}
		if e.Sample != nil {
			phases = append(phases, e.Sample.Phase)
		}
	}
	if !reflect.DeepEqual(phases, []string{"first", "second"}) {
		t.Fatalf("phases=%v", phases)
	}
}

func TestCallerExpiration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	r, _, err := Execute(ctx, testContract(t, server.URL, "1s", 10, false), Options{Directory: t.TempDir()})
	if err != nil || r.Execution.Status != result.TimedOut || r.Verdict == result.Pass {
		t.Fatalf("report=%+v err=%v", r, err)
	}
}
