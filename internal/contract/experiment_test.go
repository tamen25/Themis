package contract

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestExperimentSchemaAndExactNormalization(t *testing.T) {
	data, err := os.ReadFile("../../examples/owned-latency/experiment.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseExperiment(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"0.0300", "3e-2"} {
		other, err := ParseExperiment(strings.NewReader(strings.Replace(string(data), "0.03", value, 1)))
		if err != nil || other.Digest() != c.Digest() {
			t.Fatalf("equivalent decimal %s: %v", value, err)
		}
	}
	for _, value := range []string{"1e-400", "0.001e-400", "12345678901234567890123456789012345678901234567890123456789e-400", "0.030000000000000000000000000000000001"} {
		other, err := ParseExperiment(strings.NewReader(strings.Replace(string(data), "0.03", value, 1)))
		if err != nil {
			t.Fatal(err)
		}
		again, err := ParseExperiment(bytes.NewReader(other.NormalizedJSON()))
		if err != nil || again.Digest() != other.Digest() || other.Digest() == c.Digest() {
			t.Fatalf("exact round trip %s: %v", value, err)
		}
	}
	snapshot := c.Snapshot()
	snapshot.Metadata.Labels["mutable"] = "changed"
	if bytes.Contains(c.NormalizedJSON(), []byte("mutable")) {
		t.Fatal("mutable validated contract")
	}
	for name, changed := range map[string]string{
		"old schema":             strings.Replace(string(data), ExperimentSchemaVersion, SchemaVersion, 1),
		"unknown field":          string(data) + "  requireApproval: false\n",
		"wrong profile":          strings.Replace(string(data), "owned-local-test", "local", 1),
		"two faults":             strings.Replace(string(data), "maxConcurrentFaults: 1", "maxConcurrentFaults: 2", 1),
		"unsupported action":     strings.Replace(string(data), "http.response-latency", "host.firewall", 1),
		"unknown target URL":     strings.Replace(string(data), "fixture: demo", "fixture: demo\n    url: http://127.0.0.1:80", 1),
		"negative threshold":     strings.Replace(string(data), "0.03", "-0.01", 1),
		"excessive threshold":    strings.Replace(string(data), "0.03", "1.001", 1),
		"too many confirmations": strings.Replace(string(data), "minConfirmed: 3", "minConfirmed: 5", 1),
		"unbounded exponent":     strings.Replace(string(data), "0.03", "1e-999999", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseExperiment(strings.NewReader(changed)); err == nil {
				t.Fatal("invalid experiment accepted")
			}
		})
	}
}
