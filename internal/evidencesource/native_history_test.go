package evidencesource_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	wire "github.com/tamen25/themis/internal/dependencyhttp"
	"github.com/tamen25/themis/internal/evidencesource"
	"github.com/tamen25/themis/pkg/evidence"
	"github.com/tamen25/themis/pkg/evidenceverify"
	obs "github.com/tamen25/themis/pkg/nativeobservation"
)

// These fixtures contain real DEVELOPMENT Kind measurements/publications.
// Independently selected policy inputs are test roots, never embedded trust.
func nativeHistory(t testing.TB, name string) ([]byte, evidence.Policy, obs.Policy, time.Time) {
	t.Helper()
	root := filepath.Join("testdata", "native-"+name)
	read := func(name string) []byte {
		b, e := os.ReadFile(filepath.Join(root, name))
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	publisher, e := evidence.ReadPolicy(read("publisher-policy.json"))
	if e != nil {
		t.Fatal(e)
	}
	witness, e := obs.ReadPolicy(read("witness-policy.json"))
	if e != nil {
		t.Fatal(e)
	}
	begin, e := obs.UTC(witness.Keys[0].NotBefore)
	if e != nil {
		t.Fatal(e)
	}
	return read("bundle.zip"), publisher, witness, begin.Add(time.Hour + time.Minute)
}
func TestActualNativeHistoriesKeepDistinctFindings(t *testing.T) {
	for _, tc := range []struct{ name, candidate, status string }{{"pass", "PASS", "OBSERVATIONS_CORROBORATED"}, {"fail", "FAIL", "OBSERVATIONS_CORROBORATED"}, {"no-effect", "INCONCLUSIVE", "OBSERVATIONS_INCOMPLETE"}, {"cleanup-pending", "INCONCLUSIVE", "OBSERVATIONS_INCOMPLETE"}, {"witness-death", "PASS", "OBSERVATIONS_INCOMPLETE"}, {"runner-death", "INCONCLUSIVE", "OBSERVATIONS_INCOMPLETE"}, {"cancelled", "INCONCLUSIVE", "OBSERVATIONS_INCOMPLETE"}} {
		t.Run(tc.name, func(t *testing.T) {
			b, p, w, now := nativeHistory(t, tc.name)
			r, e := evidenceverify.VerifyNative(bytes.NewReader(b), int64(len(b)), &p, &w, now)
			if e != nil {
				t.Fatal(e)
			}
			f := r.NativeObservationCorroboration
			if r.Evidence.ArtifactIntegrity != "VALID" || r.Evidence.PublisherTrust != "TRUSTED" || r.Evidence.Source.CandidateVerdict != tc.candidate || f.Status != tc.status || f.WitnessTrust != "TRUSTED" || f.SignatureChain != "VALID" || r.Evidence.TrustedExecutionVerdict != "INCONCLUSIVE" || f.TrustedExecutionVerdict != "INCONCLUSIVE" {
				t.Fatal("conflated native findings", r)
			}
			if tc.name == "fail" && (f.ApplicationVerdict != "FAIL" || f.Violations == 0) {
				t.Fatal("credible observed violation lost")
			}
			if tc.name == "cleanup-pending" && (f.Recovery < 3 || f.OriginalCleanup != "PENDING") {
				t.Fatal("observed recovery erased original cleanup")
			}
			if tc.name == "runner-death" && (r.Evidence.Source.Execution != "INTERRUPTED" || f.Recovery < 3) {
				t.Fatal("witness invented a historical runner success")
			}
			untrusted, e := evidenceverify.VerifyNative(bytes.NewReader(b), int64(len(b)), &p, nil, now)
			if e != nil || untrusted.NativeObservationCorroboration.Status != "WITNESS_IDENTITY_UNTRUSTED" {
				t.Fatal("embedded witness key became trust")
			}
		})
	}
}

func TestEarlySignedCancellationDoesNotClaimAbsenceOfEffect(t *testing.T) {
	b, p, w, now := nativeHistory(t, "early-cancel")
	r, err := evidenceverify.VerifyNative(bytes.NewReader(b), int64(len(b)), &p, &w, now)
	if err != nil {
		t.Fatal(err)
	}
	f := r.NativeObservationCorroboration
	if r.Evidence.SourceChecks.Status != "PASSED" || r.Evidence.Source.Execution != "CANCELLED" || r.Evidence.Source.CandidateVerdict != "INCONCLUSIVE" || f.Status != "OBSERVATIONS_INCOMPLETE" || f.RunnerCorrelation != "MATCHED" || f.Effects < 3 || f.ApplicationVerdict != "PASS" || f.SignatureChain != "VALID" || f.WitnessTrust != "TRUSTED" || r.Evidence.TrustedExecutionVerdict != "INCONCLUSIVE" || f.TrustedExecutionVerdict != "INCONCLUSIVE" {
		t.Fatal("independent effect coverage contradicted an uncertain canceled source", r)
	}
}
func TestNativeOfflineMappingsRejectAlteredClaimsChainsAndCrossRunRecords(t *testing.T) {
	for _, kind := range []string{"source-verdict", "source-cancellation", "source-phase-order", "signature", "duplicate", "reordered", "missing-middle", "torn-tail", "cross-run-witness", "unsupported-mapping"} {
		t.Run(kind, func(t *testing.T) {
			b, p, w, now := nativeHistory(t, "pass")
			o, e := evidenceverify.Verify(bytes.NewReader(b), int64(len(b)), &p, now)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "source-verdict", "source-cancellation":
				var r evidencesource.NativeResult
				if json.Unmarshal(o.Artifacts["artifacts/native-result.json"], &r) != nil {
					t.Fatal("source result")
				}
				if kind == "source-verdict" {
					r.Report.Verdict = "FAIL"
				} else {
					r.Report.Execution = "CANCELLED"
					r.Report.Verdict = "INCONCLUSIVE"
				}
				o.Artifacts["artifacts/native-result.json"] = wire.JSON(r)
			case "source-phase-order":
				raw, e := obs.DecodeJournal(o.Artifacts["artifacts/native-runner-journal.json"])
				if e != nil {
					t.Fatal(e)
				}
				lines := bytes.Split(raw, []byte{'\n'})
				lines[1], lines[2] = lines[2], lines[1]
				o.Artifacts["artifacts/native-runner-journal.json"], _ = obs.EncodeJournal(bytes.Join(lines, []byte{'\n'}))
			case "cross-run-witness":
				other, pp, _, tm := nativeHistory(t, "fail")
				foreign, e := evidence.Verify(bytes.NewReader(other), int64(len(other)), &pp, tm)
				if e != nil {
					t.Fatal(e)
				}
				o.Artifacts["artifacts/native-witness-journal.json"] = foreign.Artifacts["artifacts/native-witness-journal.json"]
			case "unsupported-mapping":
				o.Manifest.Source.Mapping = obs.Engine + "/v999"
			default:
				raw, e := obs.DecodeJournal(o.Artifacts["artifacts/native-witness-journal.json"])
				if e != nil {
					t.Fatal(e)
				}
				lines := bytes.Split(raw, []byte{'\n'})
				switch kind {
				case "signature":
					var r obs.Record
					if obs.Decode(lines[5], &r) != nil {
						t.Fatal("record")
					}
					r.Signature[0] ^= 1
					lines[5] = wire.JSON(r)
				case "duplicate":
					lines = append(lines[:5], append([][]byte{lines[4]}, lines[5:]...)...)
				case "reordered":
					lines[5], lines[6] = lines[6], lines[5]
				case "missing-middle":
					lines = append(lines[:5], lines[6:]...)
				case "torn-tail":
					lines = lines[:len(lines)-2]
					lines = append(lines, []byte(`{"version":`))
				}
				o.Artifacts["artifacts/native-witness-journal.json"], _ = obs.EncodeJournal(bytes.Join(lines, []byte{'\n'}))
			}
			// This intentionally tests pure mapping logic after envelope verification;
			// actual re-signed malicious publication is covered by the live H test.
			evidencesource.Check(&o)
			f := evidencesource.CorroborateNative(o, &w, now)
			if f.Status == "OBSERVATIONS_CORROBORATED" || o.Result.TrustedExecutionVerdict != "INCONCLUSIVE" || f.TrustedExecutionVerdict != "INCONCLUSIVE" {
				t.Fatal("altered source/witness evidence became complete", kind, o.Result.SourceChecks, f)
			}
		})
	}
}

func TestPublisherCannotHideActualSignedCancellation(t *testing.T) {
	b, p, w, now := nativeHistory(t, "cancelled")
	o, e := evidenceverify.Verify(bytes.NewReader(b), int64(len(b)), &p, now)
	if e != nil {
		t.Fatal(e)
	}
	var result evidencesource.NativeResult
	if json.Unmarshal(o.Artifacts["artifacts/native-result.json"], &result) != nil || result.Report == nil || result.Report.Execution != "CANCELLED" || result.Report.Evaluation.Verdict != "PASS" {
		t.Fatal("actual cancellation counterexample missing")
	}
	// Replaying this edited old-format report is internally coherent: only the
	// separate original runner assertion prevents hiding accepted cancellation.
	result.Report.Execution = "SUCCEEDED"
	result.Report.Verdict = "PASS"
	o.Artifacts["artifacts/native-result.json"] = wire.JSON(result)
	evidencesource.Check(&o)
	f := evidencesource.CorroborateNative(o, &w, now)
	if o.Result.SourceChecks.Status != "FAILED" || f.Status != "OBSERVATIONS_CONTRADICTORY" || f.SignatureChain != "VALID" || f.WitnessTrust != "TRUSTED" || f.TrustedExecutionVerdict != "INCONCLUSIVE" {
		t.Fatal("public source edits hid actual cancellation", o.Result.SourceChecks, f)
	}
}

func TestPublisherCannotUpgradeUncertainOrFailingNativeHistory(t *testing.T) {
	for _, name := range []string{"early-cancel", "fail", "no-effect", "cleanup-pending"} {
		t.Run(name, func(t *testing.T) {
			b, p, w, now := nativeHistory(t, name)
			o, err := evidenceverify.Verify(bytes.NewReader(b), int64(len(b)), &p, now)
			if err != nil {
				t.Fatal(err)
			}
			var result evidencesource.NativeResult
			if json.Unmarshal(o.Artifacts["artifacts/native-result.json"], &result) != nil || result.Report == nil {
				t.Fatal("missing authentic source result")
			}
			result.Report.Execution = "SUCCEEDED"
			result.Report.Verdict = "PASS"
			result.Report.Cleanup = "COMPLETE"
			result.Report.Evaluation.Effects = 3
			o.Artifacts["artifacts/native-result.json"] = wire.JSON(result)
			evidencesource.Check(&o)
			f := evidencesource.CorroborateNative(o, &w, now)
			if o.Result.SourceChecks.Status != "FAILED" || f.Status != "OBSERVATIONS_CONTRADICTORY" || f.TrustedExecutionVerdict != "INCONCLUSIVE" || o.Result.TrustedExecutionVerdict != "INCONCLUSIVE" {
				t.Fatal("publisher edits upgraded original signed uncertainty or failure", o.Result.SourceChecks, f)
			}
		})
	}
}

func TestNativeSchemaCannotConflateCorroborationWithExecutionTrust(t *testing.T) {
	compiler := jsonschema.NewCompiler()
	for _, entry := range []struct{ file, id string }{{"evidence-bundle-v1alpha1.json", "urn:themis:evidence-bundle:v1alpha1"}, {"native-witness-verification-v1alpha1.json", "urn:themis:native-witness-verification:v1alpha1"}} {
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
	schema, e := compiler.Compile("urn:themis:native-witness-verification:v1alpha1")
	if e != nil {
		t.Fatal(e)
	}
	b, p, w, now := nativeHistory(t, "pass")
	r, e := evidenceverify.VerifyNative(bytes.NewReader(b), int64(len(b)), &p, &w, now)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(r)
	var value map[string]any
	json.Unmarshal(raw, &value)
	if e = schema.Validate(value); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"execution-pass", "attested", "witness-execution-pass", "untrusted-corroboration", "unknown-green-status", "missing-recovery", "missing-authority", "cleanup-erasure", "cancellation-erasure", "unknown-field"} {
		t.Run(kind, func(t *testing.T) {
			var v map[string]any
			json.Unmarshal(raw, &v)
			ev := v["evidence"].(map[string]any)
			f := v["nativeObservationCorroboration"].(map[string]any)
			switch kind {
			case "execution-pass":
				ev["trustedExecutionVerdict"] = "PASS"
			case "attested":
				ev["executionAttestation"] = "ATTESTED"
			case "witness-execution-pass":
				f["trustedExecutionVerdict"] = "PASS"
			case "untrusted-corroboration":
				f["witnessTrust"] = "UNTRUSTED"
			case "unknown-green-status":
				f["status"] = "VERIFIED"
			case "missing-recovery":
				f["recoverySamples"] = 0
			case "missing-authority":
				f["authorityCorrelation"] = "NOT_CHECKED"
			case "cleanup-erasure":
				ev["source"].(map[string]any)["cleanup"] = "PENDING"
			case "cancellation-erasure":
				ev["source"].(map[string]any)["execution"] = "CANCELLED"
			case "unknown-field":
				f["automaticReleaseAllowed"] = true
			}
			if schema.Validate(v) == nil {
				t.Fatal("schema accepted conflated or unsupported trust", kind)
			}
		})
	}
}
