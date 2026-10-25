package evidencesource_test

import (
	"bytes"
	"encoding/json"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/tamen25/themis/internal/evidencesource"
	"github.com/tamen25/themis/pkg/evidenceverify"
	obs "github.com/tamen25/themis/pkg/liveobservation"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWitnessSchemaCannotAuthorizeExecutionPASS(t *testing.T) {
	compiler := jsonschema.NewCompiler()
	for _, entry := range []struct{ file, id string }{{"evidence-bundle-v1alpha1.json", "urn:themis:evidence-bundle:v1alpha1"}, {"witness-verification-v1alpha1.json", "urn:themis:witness-verification:v1alpha1"}} {
		raw, e := os.ReadFile(filepath.Join("..", "..", "schemas", entry.file))
		if e != nil {
			t.Fatal(e)
		}
		resource, e := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if e != nil {
			t.Fatal(e)
		}
		if e = compiler.AddResource(entry.id, resource); e != nil {
			t.Fatal(e)
		}
	}
	schema, e := compiler.Compile("urn:themis:witness-verification:v1alpha1")
	if e != nil {
		t.Fatal(e)
	}
	opened, _ := signed(t, obs.Engine, load(t, "witness-healthy", obs.Engine), nil)
	policy := witnessPolicy(t, "witness-healthy")
	f := evidencesource.Corroborate(opened, &policy, time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC))
	result := evidenceverify.ObservedResult{Version: "themis.witness-bundle-verification/v1alpha1", Evidence: opened.Result, ObservationCorroboration: f}
	raw, _ := json.Marshal(result)
	var value map[string]any
	json.Unmarshal(raw, &value)
	if e = schema.Validate(value); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"trusted-pass", "attested", "untrusted-corroboration", "missing-coverage", "unknown-state", "missing-uncertainty", "cleanup-erasure"} {
		t.Run(name, func(t *testing.T) {
			var v map[string]any
			json.Unmarshal(raw, &v)
			evidence := v["evidence"].(map[string]any)
			finding := v["observationCorroboration"].(map[string]any)
			switch name {
			case "trusted-pass":
				evidence["trustedExecutionVerdict"] = "PASS"
			case "attested":
				evidence["executionAttestation"] = "ATTESTED"
			case "untrusted-corroboration":
				finding["witnessTrust"] = "UNTRUSTED"
			case "missing-coverage":
				finding["recoverySamples"] = 0
			case "unknown-state":
				finding["status"] = "VERIFIED"
			case "missing-uncertainty":
				finding["limitations"] = []any{}
			case "cleanup-erasure":
				evidence["source"].(map[string]any)["cleanup"] = "PENDING"
			}
			if schema.Validate(v) == nil {
				t.Fatal("schema accepted execution-trust conflation", name)
			}
		})
	}
}
