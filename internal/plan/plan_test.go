package plan_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/tamen25/themis/internal/contract"
	"github.com/tamen25/themis/internal/plan"
)

func example(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../../examples/local-http/contract.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func compile(t *testing.T, data []byte) plan.Plan {
	t.Helper()
	c, err := contract.Parse(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	p, err := plan.Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestStablePlanAndDigest(t *testing.T) {
	input := example(t)
	p := compile(t, input)
	for i := 0; i < 10; i++ {
		other := compile(t, bytes.ReplaceAll(input, []byte("maxDuration: 1m"), []byte("maxDuration: 60000ms")))
		if !bytes.Equal(p.JSON(), other.JSON()) || p.Digest() != other.Digest() {
			t.Fatal("equivalent input produced a different plan")
		}
	}
	var envelope struct {
		Digest string          `json:"planDigest"`
		Plan   json.RawMessage `json:"plan"`
	}
	if err := json.Unmarshal(p.JSON(), &envelope); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("sha256:%x", sha256.Sum256(envelope.Plan))
	if envelope.Digest != want || p.Digest() != want {
		t.Fatalf("plan digest does not cover payload: %s != %s", envelope.Digest, want)
	}
	changed := compile(t, bytes.ReplaceAll(input, []byte("maximumErrorFraction: 0.03"), []byte("maximumErrorFraction: 0.04")))
	if changed.Digest() == p.Digest() {
		t.Fatal("meaningful threshold change did not alter plan digest")
	}
	golden, err := os.ReadFile("testdata/plan.json")
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, golden); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.JSON(), compact.Bytes()) {
		t.Fatal("plan serialization differs from reviewed golden fixture")
	}
}

func TestPlanIsAnImmutableSnapshot(t *testing.T) {
	c, err := contract.Parse(bytes.NewReader(example(t)))
	if err != nil {
		t.Fatal(err)
	}
	p, err := plan.Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	before := string(p.JSON())
	snapshot := c.Snapshot()
	snapshot.Spec.Target.URL = "http://127.0.0.1:9999/"
	snapshot.Metadata.Labels["environment"] = "changed"
	output := p.JSON()
	output[0] = '!'
	if string(p.JSON()) != before {
		t.Fatal("caller mutated the frozen plan")
	}
}

func TestPlanHonestlyDescribesCapabilities(t *testing.T) {
	p := compile(t, example(t))
	var envelope struct {
		Plan struct {
			Mode             string `json:"mode"`
			ExecutionAllowed bool   `json:"executionAllowed"`
			TargetIdentity   string `json:"targetIdentity"`
			ExecutionPolicy  string `json:"executionPolicy"`
			Checks           []struct {
				Support string `json:"support"`
			} `json:"checks"`
		} `json:"plan"`
	}
	if err := json.Unmarshal(p.JSON(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Plan.Mode != "planning-only" || envelope.Plan.ExecutionAllowed || !strings.Contains(envelope.Plan.TargetIdentity, "declared-only") {
		t.Fatal("plan claims execution or verified identity")
	}
	if len(envelope.Plan.Checks) != 2 {
		t.Fatal("plan omitted declared checks")
	}
	for _, check := range envelope.Plan.Checks {
		if !strings.Contains(check.Support, "separate admission required") {
			t.Fatal("check omits the runtime admission boundary")
		}
	}
	if envelope.Plan.ExecutionPolicy != "themis.local-http/t0-v1" {
		t.Fatal("plan omits versioned execution policy")
	}
}

func TestRejectUnvalidatedContract(t *testing.T) {
	if _, err := plan.Compile(contract.Validated{}); err == nil {
		t.Fatal("accepted a zero-valued, unvalidated contract")
	}
}
