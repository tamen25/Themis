package contract_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/tamen25/themis/internal/contract"
)

const minimal = `schemaVersion: themis.contract/v1alpha1
metadata: {name: demo, owner: platform}
spec:
  target: {kind: local-http, name: api, url: 'http://127.0.0.1:8080'}
  execution: {maxDuration: 1m}
  scenario:
    id: baseline
    phases: [{name: observe, duration: 30s}]
  assertions:
    - {id: ready, type: http-ready, deadline: 10s}
`

func mustParse(t *testing.T, input string) contract.Validated {
	t.Helper()
	c, err := contract.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestValidContractAndDefaults(t *testing.T) {
	c := mustParse(t, minimal)
	snapshot := c.Snapshot()
	if snapshot.Spec.Execution.Profile != "local" || !snapshot.Spec.Execution.RequireApproval || snapshot.Spec.Execution.MaxConcurrentFaults != 0 {
		t.Fatalf("unexpected execution defaults: %+v", snapshot.Spec.Execution)
	}
	if snapshot.Spec.Target.URL != "http://127.0.0.1:8080/" || snapshot.Spec.Execution.MaxDuration != "1m0s" {
		t.Fatalf("not normalized: %+v", snapshot.Spec)
	}
	if !snapshot.Spec.Assertions[0].Required || snapshot.Spec.Assertions[0].MinSamples != 1 {
		t.Fatalf("unexpected assertion defaults: %+v", snapshot.Spec.Assertions)
	}
	if snapshot.Metadata.Labels == nil || snapshot.Spec.Evidence.RequireSignature {
		t.Fatal("expected an empty labels map and unsigned evidence config")
	}
	want := fmt.Sprintf("sha256:%x", sha256.Sum256(c.NormalizedJSON()))
	if c.Digest() != want {
		t.Fatalf("digest = %s; want %s", c.Digest(), want)
	}
	golden, err := os.ReadFile("testdata/normalized.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.NormalizedJSON(), bytes.TrimSpace(golden)) {
		t.Fatal("normalized serialization differs from reviewed fixture")
	}
	// Normalized JSON must itself be an accepted, stable contract.
	roundTrip := mustParse(t, string(c.NormalizedJSON()))
	if !bytes.Equal(roundTrip.NormalizedJSON(), c.NormalizedJSON()) {
		t.Fatal("normalization is not idempotent")
	}
}

func TestInvalidContracts(t *testing.T) {
	tests := []struct {
		name, input, message string
	}{
		{"empty", "", "parse YAML"},
		{"malformed", "spec: [", "parse YAML"},
		{"scalar", "hello", "contract schema"},
		{"null", "null", "contract schema"},
		{"multiple documents", minimal + "\n---\n{}", "exactly one"},
		{"trailing malformed document", minimal + "\n---\n[", "trailing YAML"},
		{"unsupported version", strings.Replace(minimal, "v1alpha1", "v99", 1), "unsupported schemaVersion"},
		{"missing required field", strings.Replace(minimal, "owner: platform", "labels: {}", 1), "owner"},
		{"unknown root", minimal + "unknown: true\n", "unknown"},
		{"unknown nested", strings.Replace(minimal, "maxDuration: 1m", "maxDuration: 1m, typo: true", 1), "typo"},
		{"duplicate root", minimal + "schemaVersion: themis.contract/v1alpha1\n", "duplicate field"},
		{"duplicate nested", strings.Replace(minimal, "name: demo", "name: demo, name: other", 1), "duplicate field"},
		{"duplicate labels", strings.Replace(minimal, "owner: platform", "owner: platform, labels: {a: x, a: y}", 1), "duplicate field"},
		{"anchor", strings.Replace(minimal, "metadata:", "metadata: &m", 1), "anchors and aliases"},
		{"merge", strings.Replace(minimal, "name: demo", "'<<': {}, name: demo", 1), "<<"},
		{"YAML merge key", strings.Replace(minimal, "name: demo", "<<: {}, name: demo", 1), "merge keys are unsupported"},
		{"non-string key", minimal + "1: value\n", "keys must be plain strings"},
		{"custom tag", strings.Replace(minimal, "owner: platform", "owner: !secret platform", 1), "unsupported YAML type"},
		{"timestamp", strings.Replace(minimal, "owner: platform", "owner: 2026-10-15", 1), "unsupported YAML type"},
		{"null approval", strings.Replace(minimal, "maxDuration: 1m", "maxDuration: 1m, requireApproval: null", 1), "requireApproval"},
		{"string boolean", strings.Replace(minimal, "maxDuration: 1m", "maxDuration: 1m, requireApproval: 'false'", 1), "requireApproval"},
		{"legacy boolean", strings.Replace(minimal, "maxDuration: 1m", "maxDuration: 1m, requireApproval: yes", 1), "requireApproval"},
		{"zero duration", strings.Replace(minimal, "maxDuration: 1m", "maxDuration: 0s", 1), "between 1ms and 10m"},
		{"negative duration", strings.Replace(minimal, "maxDuration: 1m", "maxDuration: -1s", 1), "between 1ms and 10m"},
		{"duration overflow", strings.Replace(minimal, "maxDuration: 1m", "maxDuration: 999999999999999999999h", 1), "between 1ms and 10m"},
		{"duration too large", strings.Replace(minimal, "maxDuration: 1m", "maxDuration: 11m", 1), "between 1ms and 10m"},
		{"duration wrong unit", strings.Replace(minimal, "maxDuration: 1m", "maxDuration: 1d", 1), "between 1ms and 10m"},
		{"duration wrong type", strings.Replace(minimal, "maxDuration: 1m", "maxDuration: 60", 1), "maxDuration"},
		{"fault concurrency", strings.Replace(minimal, "maxDuration: 1m", "maxDuration: 1m, maxConcurrentFaults: 1", 1), "maxConcurrentFaults"},
		{"negative concurrency", strings.Replace(minimal, "maxDuration: 1m", "maxDuration: 1m, maxConcurrentFaults: -1", 1), "maxConcurrentFaults"},
		{"production profile", strings.Replace(minimal, "maxDuration: 1m", "maxDuration: 1m, profile: production", 1), "profile"},
		{"namespaces reserved", strings.Replace(minimal, "maxDuration: 1m", "maxDuration: 1m, allowedNamespaces: [default]", 1), "allowedNamespaces"},
		{"phase exceeds budget", strings.Replace(minimal, "maxDuration: 1m", "maxDuration: 20s", 1), "total duration exceeds"},
		{"zero phase", strings.Replace(minimal, "duration: 30s", "duration: 0s", 1), "between 1ms and 10m"},
		{"duplicate phase", strings.Replace(minimal, "phases: [{name: observe, duration: 30s}]", "phases: [{name: observe, duration: 10s}, {name: observe, duration: 10s}]", 1), "duplicate name"},
		{"empty phases", strings.Replace(minimal, "[{name: observe, duration: 30s}]", "[]", 1), "phases"},
		{"fault declaration", strings.Replace(minimal, "duration: 30s", "duration: 30s, fault: {type: network.latency}", 1), "fault"},
		{"unsupported target", strings.Replace(minimal, "kind: local-http", "kind: kubernetes-service", 1), "kind"},
		{"no required assertions", strings.Replace(minimal, "deadline: 10s", "deadline: 10s, required: false", 1), "at least one required"},
		{"duplicate assertion", minimal + "    - {id: ready, type: http-ready, deadline: 10s}\n", "duplicate id"},
		{"unsupported check", strings.Replace(minimal, "http-ready", "intervention-applied", 1), "assertions"},
		{"unknown check field", strings.Replace(minimal, "deadline: 10s", "deadline: 10s, script: dangerous", 1), "script"},
		{"missing deadline", strings.Replace(minimal, ", deadline: 10s", "", 1), "deadline"},
		{"deadline exceeds phases", strings.Replace(minimal, "deadline: 10s", "deadline: 31s", 1), "exceeds scenario duration"},
		{"zero sample count", strings.Replace(minimal, "deadline: 10s", "deadline: 10s, minSamples: 0", 1), "minSamples"},
		{"excessive sample count", strings.Replace(minimal, "deadline: 10s", "deadline: 10s, minSamples: 100001", 1), "minSamples"},
		{"fractional sample precision", strings.Replace(minimal, "deadline: 10s", "deadline: 10s, minSamples: 1.00000000000000001", 1), "minSamples"},
		{"non-JSON numeric notation", strings.Replace(minimal, "deadline: 10s", "deadline: 10s, minSamples: 1_00", 1), "JSON-compatible"},
		{"extreme numeric exponent", strings.Replace(minimal, "deadline: 10s", "deadline: 10s, minSamples: 1e-100000000", 1), "numeric exponent"},
		{"oversize numeric literal", strings.Replace(minimal, "deadline: 10s", "deadline: 10s, minSamples: 0."+strings.Repeat("0", 64)+"1", 1), "numeric literals"},
		{"raw traces unsupported", minimal + "  evidence: {includeRawTraces: true}\n", "includeRawTraces"},
		{"signing unsupported", minimal + "  evidence: {requireSignature: true}\n", "requireSignature"},
		{"retention reserved", minimal + "  evidence: {retention: 7d}\n", "retention"},
		{"oversize", strings.Repeat(" ", contract.MaxDocumentBytes+1), "exceeds"},
		{"excessive depth", "x: " + strings.Repeat("[", 40) + "0" + strings.Repeat("]", 40), "depth or node limit"},
		{"excessive nodes", "x: [" + strings.Repeat("0,", 10001) + "0]", "depth or node limit"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := contract.Parse(strings.NewReader(tc.input))
			if err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("error = %v; want message containing %q", err, tc.message)
			}
		})
	}
}

func TestLocalEndpointRestrictions(t *testing.T) {
	tests := []struct {
		url   string
		valid bool
	}{
		{"http://127.0.0.1:8080", true},
		{"https://127.2.3.4:8443/ready", true},
		{"http://[::1]:8080/health", true},
		{"http://localhost:8080/", false},
		{"http://example.org:80/", false},
		{"http://192.168.1.1:80/", false},
		{"http://169.254.169.254:80/", false},
		{"http://0.0.0.0:8080/", false},
		{"http://127.0.0.1/", false},
		{"http://127.0.0.1:0/", false},
		{"http://127.0.0.1:65536/", false},
		{"http://127.0.0.1:abc/", false},
		{"http://user:password@127.0.0.1:8080/", false},
		{"http://127.0.0.1:8080/?token=secret", false},
		{"http://127.0.0.1:8080/?", false},
		{"http://127.0.0.1:8080/#", false},
		{"file:///etc/passwd", false},
		{"http://[::1%25zone]:8080/", false},
		{"http://127.0.0.1:8080/%zz", false},
	}
	for _, tc := range tests {
		t.Run(tc.url, func(t *testing.T) {
			_, err := contract.Parse(strings.NewReader(strings.Replace(minimal, "http://127.0.0.1:8080", tc.url, 1)))
			if (err == nil) != tc.valid {
				t.Fatalf("valid = %t, error = %v", tc.valid, err)
			}
		})
	}
}

func TestNormalizedHashEquivalence(t *testing.T) {
	base := mustParse(t, minimal)
	equivalent := []string{
		strings.Replace(minimal, "maxDuration: 1m", "maxDuration: 60s", 1),
		strings.Replace(minimal, "duration: 30s", "duration: 30000ms", 1),
		strings.Replace(minimal, "http://127.0.0.1:8080", "http://127.0.0.1:08080/", 1),
		strings.Replace(minimal, "owner: platform", "owner: platform, labels: {}", 1),
		strings.Replace(minimal, "maxDuration: 1m", "requireApproval: true, maxConcurrentFaults: 0, profile: local, maxDuration: 1m0s", 1),
		strings.Replace(minimal, "deadline: 10s", "minSamples: 1, required: true, deadline: 10000ms", 1),
		strings.Replace(minimal, "deadline: 10s", "minSamples: 1.0, deadline: 10s", 1),
		strings.Replace(minimal, "deadline: 10s", "minSamples: 1e0, deadline: 10s", 1),
		minimal + "  evidence: {requireSignature: false, includeRawTraces: false}\n",
		"# comment\n" + minimal,
		string(base.NormalizedJSON()),
	}
	for i, input := range equivalent {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			other := mustParse(t, input)
			if other.Digest() != base.Digest() || !bytes.Equal(other.NormalizedJSON(), base.NormalizedJSON()) {
				t.Fatalf("equivalent input changed digest: %s != %s", other.Digest(), base.Digest())
			}
		})
	}
	for _, replacement := range [][2]string{
		{"maxDuration: 1m", "maxDuration: 2m"},
		{"deadline: 10s", "deadline: 11s"},
		{"owner: platform", "owner: another-team"},
		{"maxDuration: 1m", "maxDuration: 1m, requireApproval: false"},
		{"127.0.0.1:8080", "127.0.0.1:8081"},
	} {
		other := mustParse(t, strings.Replace(minimal, replacement[0], replacement[1], 1))
		if other.Digest() == base.Digest() {
			t.Fatalf("meaningful change %q did not alter digest", replacement[1])
		}
	}
}

func TestAssertionSetNormalization(t *testing.T) {
	withTwo := minimal + "    - {id: rate, type: http-success-rate, minSamples: 10, maximumErrorFraction: 0.03}\n"
	a := mustParse(t, withTwo)
	b := mustParse(t, strings.Replace(withTwo,
		"    - {id: ready, type: http-ready, deadline: 10s}\n    - {id: rate, type: http-success-rate, minSamples: 10, maximumErrorFraction: 0.03}",
		"    - {id: rate, type: http-success-rate, minSamples: 10, maximumErrorFraction: 0.030}\n    - {id: ready, type: http-ready, deadline: 10s}", 1))
	if a.Digest() != b.Digest() {
		t.Fatal("assertion ordering or fraction spelling changed digest")
	}
	for _, fraction := range []string{"-0.1", "1.1", "1.00000000000000001", "-1e-400", ".nan", ".inf", "null"} {
		if _, err := contract.Parse(strings.NewReader(strings.Replace(withTwo, "0.03", fraction, 1))); err == nil {
			t.Fatalf("accepted invalid fraction %s", fraction)
		}
	}
	zero := mustParse(t, strings.Replace(withTwo, "0.03", "0", 1))
	negativeZero := mustParse(t, strings.Replace(withTwo, "0.03", "-0.0", 1))
	if zero.Digest() != negativeZero.Digest() {
		t.Fatal("signed zero changed digest")
	}
	changed := mustParse(t, strings.Replace(withTwo, "0.03", "0.04", 1))
	if a.Digest() == changed.Digest() {
		t.Fatal("threshold change did not alter digest")
	}
}

func TestMapOrderingAndPhaseOrdering(t *testing.T) {
	a := mustParse(t, strings.Replace(minimal, "owner: platform", "owner: platform, labels: {a: first, z: last}", 1))
	b := mustParse(t, strings.Replace(minimal, "owner: platform", "labels: {z: last, a: first}, owner: platform", 1))
	if a.Digest() != b.Digest() {
		t.Fatal("metadata mapping order changed digest")
	}
	first := "[{name: first, duration: 10s}, {name: second, duration: 10s}]"
	second := "[{name: second, duration: 10s}, {name: first, duration: 10s}]"
	a = mustParse(t, strings.Replace(minimal, "[{name: observe, duration: 30s}]", first, 1))
	b = mustParse(t, strings.Replace(minimal, "[{name: observe, duration: 30s}]", second, 1))
	if a.Digest() == b.Digest() {
		t.Fatal("ordered phase change did not alter digest")
	}
}

func TestValidatedSnapshotIsImmutable(t *testing.T) {
	c := mustParse(t, minimal+"    - {id: rate, type: http-success-rate, minSamples: 10, maximumErrorFraction: 0.03}\n")
	before := string(c.NormalizedJSON())
	snapshot := c.Snapshot()
	snapshot.Metadata.Labels["new"] = "value"
	snapshot.Spec.Scenario.Phases[0].Name = "changed"
	for i := range snapshot.Spec.Assertions {
		snapshot.Spec.Assertions[i].ID = "changed"
		if snapshot.Spec.Assertions[i].MaximumErrorFraction != nil {
			*snapshot.Spec.Assertions[i].MaximumErrorFraction = 1
		}
	}
	encoded := c.NormalizedJSON()
	encoded[0] = '!'
	after, err := json.Marshal(c.Snapshot())
	if err != nil || string(after) != before || string(c.NormalizedJSON()) != before {
		t.Fatalf("snapshot mutation changed validated contract: %s (%v)", after, err)
	}
}

func TestExampleContracts(t *testing.T) {
	for _, tc := range []struct {
		path  string
		valid bool
	}{
		{"../../examples/local-http/contract.yaml", true},
		{"../../examples/invalid/unsupported-fault.yaml", false},
		{"../../examples/invalid/unsafe-budget.yaml", false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			data, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			_, err = contract.Parse(bytes.NewReader(data))
			if (err == nil) != tc.valid {
				t.Fatalf("valid = %t, error = %v", tc.valid, err)
			}
		})
	}
}

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestReaderError(t *testing.T) {
	_, err := contract.Parse(brokenReader{})
	if !errors.Is(err, contract.ErrRead) || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("reader failure lost classification: %v", err)
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{minimal, "{}", "", "x: &x [*x]", "spec: [", "null"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		c, err := contract.Parse(strings.NewReader(input))
		if err != nil {
			return
		}
		next, err := contract.Parse(bytes.NewReader(c.NormalizedJSON()))
		if err != nil || next.Digest() != c.Digest() {
			t.Fatalf("normalization is not stable: %v", err)
		}
	})
}
