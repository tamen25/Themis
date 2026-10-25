package evidencesource_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"github.com/tamen25/themis/internal/evidencesource"
	"github.com/tamen25/themis/pkg/evidence"
	"github.com/tamen25/themis/pkg/evidenceverify"
	obs "github.com/tamen25/themis/pkg/liveobservation"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func witnessPolicy(t *testing.T, name string) obs.Policy {
	t.Helper()
	raw, e := os.ReadFile(filepath.Join("testdata", name, "witness-policy.json"))
	if e != nil {
		t.Fatal(e)
	}
	p, e := obs.ReadPolicy(raw)
	if e != nil {
		t.Fatal(e)
	}
	return p
}

func TestPublisherKeyCannotBeItsOwnIndependentWitness(t *testing.T) {
	files := load(t, "witness-healthy", obs.Engine)
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	var reg obs.Registration
	if obs.Decode(files["artifacts/witness-registration.json"], &reg) != nil {
		t.Fatal("registration")
	}
	reg.PublicKey = pub
	reg.KeyID = evidence.Fingerprint(pub)
	reg = obs.SignRegistration(reg, key)
	files["artifacts/witness-registration.json"], _ = json.Marshal(reg)
	raw, e := obs.DecodeJournalArtifact(files["artifacts/witness-journal.json"])
	if e != nil {
		t.Fatal(e)
	}
	previous := ""
	var journal bytes.Buffer
	for _, line := range bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'}) {
		var record obs.Record
		if obs.Decode(line, &record) != nil {
			t.Fatal("record")
		}
		record.KeyID = reg.KeyID
		record.RegistrationDigest = obs.RegistrationDigest(reg)
		record.Previous = previous
		record = obs.Seal(record, key)
		previous = record.Hash
		json.NewEncoder(&journal).Encode(record)
	}
	files["artifacts/witness-journal.json"], _ = obs.EncodeJournal(journal.Bytes())
	source, _, e := evidencesource.Describe(obs.Engine, files)
	if e != nil {
		t.Fatal(e)
	}
	m := evidence.Manifest{Source: source, Publisher: evidence.Publisher{Name: "same-authority", KeyID: reg.KeyID, PublicKey: pub, Algorithm: evidence.Algorithm, Domain: evidence.Domain}, PublishedAt: "2026-10-18T00:00:00Z", Artifacts: evidencesource.Inventory(obs.Engine)}
	bundle, e := evidence.Sign(m, files, key)
	if e != nil {
		t.Fatal(e)
	}
	witnessPolicy := witnessPolicy(t, "witness-healthy")
	witnessPolicy.Keys[0].PublicKey = pub
	witnessPolicy.Keys[0].KeyID = reg.KeyID
	publisherPolicy := evidence.Policy{Version: evidence.PolicyVersion, Keys: []evidence.TrustedKey{{Publisher: m.Publisher.Name, KeyID: reg.KeyID, PublicKey: pub, Algorithm: evidence.Algorithm, Engines: []string{obs.Engine}, NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}}}
	result, e := evidenceverify.VerifyObserved(bytes.NewReader(bundle), int64(len(bundle)), &publisherPolicy, &witnessPolicy, time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC))
	if e != nil || result.Evidence.Signature != "VALID" || result.Evidence.PublisherTrust != "TRUSTED" || result.ObservationCorroboration.Status != "WITNESS_IDENTITY_UNTRUSTED" || result.Evidence.TrustedExecutionVerdict != "INCONCLUSIVE" {
		t.Fatal("key-role reuse upgraded execution", result, e)
	}
}
func TestActualWitnessedHistoriesPreserveIndependentClassifications(t *testing.T) {
	for _, tc := range []struct{ name, source, status string }{{"healthy", "PASS", "OBSERVED_AND_CORRELATED"}, {"fail", "FAIL", "OBSERVED_AND_CORRELATED"}, {"noop", "INCONCLUSIVE", "OBSERVATIONS_INCOMPLETE"}, {"interrupted", "PASS", "OBSERVATIONS_INCOMPLETE"}, {"cleanup-pending", "INCONCLUSIVE", "OBSERVATIONS_INCOMPLETE"}} {
		t.Run(tc.name, func(t *testing.T) {
			name := "witness-" + tc.name
			files := load(t, name, obs.Engine)
			opened, _ := signed(t, obs.Engine, files, nil)
			policy := witnessPolicy(t, name)
			f := evidencesource.Corroborate(opened, &policy, time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC))
			if f.Status != tc.status || f.WitnessTrust != "TRUSTED" || f.SignatureChain != "VALID" || opened.Result.Source.CandidateVerdict != tc.source || opened.Result.TrustedExecutionVerdict != "INCONCLUSIVE" {
				t.Fatal(f, opened.Result)
			}
			untrusted := evidencesource.Corroborate(opened, nil, time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC))
			if untrusted.Status != "WITNESS_IDENTITY_UNTRUSTED" {
				t.Fatal("embedded key became trusted", untrusted)
			}
		})
	}
}
func TestValidPublisherCannotAuthenticateInvalidWitness(t *testing.T) {
	for _, name := range []string{"corrupt-signature", "reordered-chain", "phase-disagreement", "different-plan", "retroactive-label", "missing-journal"} {
		t.Run(name, func(t *testing.T) {
			files := load(t, "witness-healthy", obs.Engine)
			opened, _ := signed(t, obs.Engine, files, func(m *evidence.Manifest, f map[string][]byte) {
				if name == "missing-journal" {
					delete(f, "artifacts/witness-journal.json")
					for i, a := range m.Artifacts {
						if a.Path == "artifacts/witness-journal.json" {
							m.Artifacts = append(m.Artifacts[:i], m.Artifacts[i+1:]...)
							break
						}
					}
					return
				}
				if name == "different-plan" || name == "retroactive-label" {
					var r obs.Registration
					json.Unmarshal(f["artifacts/witness-registration.json"], &r)
					if name == "different-plan" {
						r.Plan.RunGeneration++
					} else {
						r.Provenance = "RETROSPECTIVE"
					}
					f["artifacts/witness-registration.json"], _ = json.Marshal(r)
					return
				}
				if name == "phase-disagreement" {
					var report map[string]json.RawMessage
					json.Unmarshal(f["artifacts/kubernetes-report.json"], &report)
					var samples []map[string]json.RawMessage
					json.Unmarshal(report["observations"], &samples)
					samples[3]["phase"] = json.RawMessage(`"recovery"`)
					report["observations"], _ = json.Marshal(samples)
					f["artifacts/kubernetes-report.json"], _ = json.Marshal(report)
					return
				}
				raw, e := obs.DecodeJournalArtifact(f["artifacts/witness-journal.json"])
				if e != nil {
					t.Fatal(e)
				}
				lines := bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'})
				if name == "reordered-chain" {
					lines[5], lines[6] = lines[6], lines[5]
				} else {
					var record obs.Record
					json.Unmarshal(lines[5], &record)
					record.Signature[0] ^= 1
					lines[5], _ = json.Marshal(record)
				}
				f["artifacts/witness-journal.json"], _ = obs.EncodeJournal(append(bytes.Join(lines, []byte{'\n'}), '\n'))
			})
			policy := witnessPolicy(t, "witness-healthy")
			finding := evidencesource.Corroborate(opened, &policy, time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC))
			if finding.Status == "OBSERVED_AND_CORRELATED" || opened.Result.Signature != "VALID" || opened.Result.PublisherTrust != "TRUSTED" || opened.Result.TrustedExecutionVerdict != "INCONCLUSIVE" {
				t.Fatal("publisher signature upgraded invalid witness", finding, opened.Result)
			}
			if name == "phase-disagreement" && finding.Status != "OBSERVATIONS_CONTRADICTORY" {
				t.Fatal(finding)
			}
		})
	}
}
