package evidencesource_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/evidencesource"
	"github.com/tamen25/themis/internal/kubeexperiment"
	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/postgres"
	"github.com/tamen25/themis/pkg/evidence"
	"github.com/tamen25/themis/pkg/evidenceverify"
)

func load(t *testing.T, name, engine string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	for _, a := range evidencesource.Inventory(engine) {
		b, e := os.ReadFile(filepath.Join("testdata", name, filepath.FromSlash(a.Path)))
		if e != nil {
			t.Fatal(e)
		}
		files[a.Path] = b
	}
	return files
}

func signed(t *testing.T, engine string, files map[string][]byte, change func(*evidence.Manifest, map[string][]byte)) (evidence.Opened, []byte) {
	t.Helper()
	s, _, e := evidencesource.Describe(engine, files)
	if e != nil {
		t.Fatal("initial fixture", e)
	}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	artifacts := []evidence.Artifact{}
	for _, a := range evidencesource.Inventory(engine) {
		if _, ok := files[a.Path]; ok {
			artifacts = append(artifacts, a)
		}
	}
	m := evidence.Manifest{Source: s, Publisher: evidence.Publisher{Name: "independent-test-publisher", KeyID: evidence.Fingerprint(pub), PublicKey: pub, Algorithm: evidence.Algorithm, Domain: evidence.Domain}, PublishedAt: "2026-10-18T00:00:00Z", Artifacts: artifacts}
	if change != nil {
		change(&m, files)
	}
	b, e := evidence.Sign(m, files, key)
	if e != nil {
		t.Fatal(e)
	}
	p := evidence.Policy{Version: evidence.PolicyVersion, Keys: []evidence.TrustedKey{{Publisher: m.Publisher.Name, KeyID: m.Publisher.KeyID, PublicKey: pub, Algorithm: evidence.Algorithm, Engines: []string{m.Source.Engine}, NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}}}
	o, e := evidenceverify.Verify(bytes.NewReader(b), int64(len(b)), &p, time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC))
	if e != nil {
		t.Fatal("cryptographic verification", e)
	}
	if o.Result.Signature != "VALID" || o.Result.PublisherTrust != "TRUSTED" || o.Result.TrustedExecutionVerdict != "INCONCLUSIVE" || o.Result.ExecutionAttestation != "NOT_INDEPENDENTLY_ATTESTED" {
		t.Fatal("signature was confused with execution truth", o.Result)
	}
	if output := os.Getenv("THEMIS_EVIDENCE_ADVERSARIAL_OUT"); output != "" {
		if e := os.MkdirAll(output, 0700); e != nil {
			t.Fatal(e)
		}
		name := strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
		if e := os.WriteFile(filepath.Join(output, name+".zip"), b, 0600); e != nil {
			t.Fatal(e)
		}
		r, _ := json.MarshalIndent(o.Result, "", "  ")
		if e := os.WriteFile(filepath.Join(output, name+".json"), r, 0600); e != nil {
			t.Fatal(e)
		}
	}
	return o, b
}

func TestCompletedPublicRunsPreserveOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name, engine, verdict, status string
		signatures                    int
	}{
		{"postgres-healthy", evidencesource.Postgres, "PASS", "PASSED", 21},
		{"postgres-fail", evidencesource.Postgres, "FAIL", "PASSED", 21},
		{"kubernetes-healthy", evidencesource.Kubernetes, "PASS", "PASSED", 29},
		{"kubernetes-fail", evidencesource.Kubernetes, "FAIL", "PASSED", 29},
		{"kubernetes-inconclusive", evidencesource.Kubernetes, "INCONCLUSIVE", "PASSED", 29},
		{"kubernetes-cleanup-pending", evidencesource.Kubernetes, "INCONCLUSIVE", "INCOMPLETE", 19},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, _ := signed(t, tc.engine, load(t, tc.name, tc.engine), nil)
			if o.Result.SourceChecks.Status != tc.status || o.Result.Source.CandidateVerdict != tc.verdict || o.Result.SourceChecks.VerifiedObservationSignatures != tc.signatures {
				t.Fatalf("unexpected source result: %+v", o.Result.SourceChecks)
			}
			if tc.name == "kubernetes-cleanup-pending" && o.Result.Source.Execution != "CLEANUP_PENDING" {
				t.Fatal("cleanup uncertainty erased")
			}
		})
	}
}

func TestArtifactVersionsMatchSourceHeaders(t *testing.T) {
	for _, tc := range []struct{ name, engine string }{{"postgres-healthy", evidencesource.Postgres}, {"kubernetes-healthy", evidencesource.Kubernetes}} {
		files := load(t, tc.name, tc.engine)
		s, _, err := evidencesource.Describe(tc.engine, files)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range evidencesource.Inventory(tc.engine) {
			data := files[a.Path]
			if strings.HasSuffix(a.Path, ".jsonl") {
				data = bytes.SplitN(data, []byte{'\n'}, 2)[0]
			}
			var headers []struct{ Version string }
			if bytes.HasPrefix(bytes.TrimSpace(data), []byte{'['}) {
				if err := json.Unmarshal(data, &headers); err != nil {
					t.Fatal(err)
				}
			} else {
				headers = make([]struct{ Version string }, 1)
				if err := json.Unmarshal(data, &headers[0]); err != nil {
					t.Fatal(err)
				}
			}
			for _, h := range headers {
				if h.Version != a.Version || !strings.Contains("\n"+strings.Join(s.Versions, "\n")+"\n", "\n"+a.Version+"\n") {
					t.Fatalf("%s descriptor %q differs from header %q or declared source versions", a.Path, a.Version, h.Version)
				}
			}
		}
	}
}

func TestTrustedSignatureDoesNotValidateForgedPostgresClaims(t *testing.T) {
	for _, name := range []string{"forged-verdict", "rehashed-fabricated-pass", "unknown-execution", "exact-loss-without-rows", "changed-preparation-contract", "forged-receipt", "replaced-observation-key", "invalid-plan-digest", "incorrect-cleanup", "wrong-run", "changed-measurements"} {
		t.Run(name, func(t *testing.T) {
			files := load(t, "postgres-fail", evidencesource.Postgres)
			o, _ := signed(t, evidencesource.Postgres, files, func(m *evidence.Manifest, f map[string][]byte) {
				var r postgres.ReplicationReport
				json.Unmarshal(f["artifacts/replication-report.json"], &r)
				switch name {
				case "changed-preparation-contract":
					previous := ""
					var b bytes.Buffer
					for _, line := range bytes.Split(bytes.TrimSpace(f["artifacts/replication-prepare.jsonl"]), []byte{'\n'}) {
						var e postgres.Event
						json.Unmarshal(line, &e)
						if e.Kind == "PREPARE_INTENT" {
							var detail map[string]json.RawMessage
							json.Unmarshal(e.Detail, &detail)
							var contract postgres.ReplicationContract
							json.Unmarshal(detail["contract"], &contract)
							contract.MaxFailoverMillis = 60000
							detail["contract"], _ = json.Marshal(contract)
							e.Detail, _ = json.Marshal(detail)
						}
						e.Previous = previous
						e.Hash = ""
						raw, _ := json.Marshal(e)
						e.Hash = evidence.Hash(append([]byte("themis.postgres.replication.event.v1\n"), raw...))
						previous = e.Hash
						json.NewEncoder(&b).Encode(e)
					}
					f["artifacts/replication-prepare.jsonl"] = b.Bytes()
				case "forged-verdict":
					r.Verdict = "PASS"
					m.Source.CandidateVerdict = "PASS"
				case "rehashed-fabricated-pass", "unknown-execution":
					if name == "unknown-execution" {
						r.Execution = "FUTURE_STATUS"
						m.Source.Execution = string(r.Execution)
					} else {
						r.Verdict = "PASS"
						m.Source.CandidateVerdict = "PASS"
					}
					previous := ""
					var b bytes.Buffer
					for _, line := range bytes.Split(bytes.TrimSpace(f["artifacts/replication-journal.jsonl"]), []byte{'\n'}) {
						var e postgres.Event
						json.Unmarshal(line, &e)
						if e.Kind == "FINAL" {
							e.Detail, _ = json.Marshal(map[string]string{"execution": string(r.Execution), "verdict": string(r.Verdict)})
						}
						e.Previous = previous
						e.Hash = ""
						raw, _ := json.Marshal(e)
						e.Hash = evidence.Hash(append([]byte("themis.postgres.replication.event.v1\n"), raw...))
						previous = e.Hash
						json.NewEncoder(&b).Encode(e)
					}
					f["artifacts/replication-journal.jsonl"] = b.Bytes()
				case "exact-loss-without-rows":
					r.Measurements.ReadWriteReady = false
					r.Measurements.Rows = nil
				case "forged-receipt":
					var rs []postgres.ReplicationReceipt
					json.Unmarshal(f["artifacts/replication-receipts.json"], &rs)
					rs[0].Payload = "fabricated"
					f["artifacts/replication-receipts.json"], _ = json.Marshal(rs)
				case "replaced-observation-key":
					var p postgres.PublicReplicationPlan
					json.Unmarshal(f["artifacts/replication-plan.json"], &p)
					pub, _, _ := ed25519.GenerateKey(rand.Reader)
					p.LedgerKey = pub
					p.Digest = ""
					raw, _ := json.Marshal(p)
					p.Digest = evidence.Hash(append([]byte(postgres.PublicReplicationVersion+"\n"), raw...))
					f["artifacts/replication-plan.json"], _ = json.Marshal(p)
				case "invalid-plan-digest":
					m.Source.PlanDigest = strings.Repeat("e", 64)
				case "incorrect-cleanup":
					r.Cleanup.Complete = false
				case "wrong-run":
					r.Run = strings.Repeat("f", 64)
				case "changed-measurements":
					r.Measurements.Timeline.ReadyNS++
				}
				f["artifacts/replication-report.json"], _ = json.Marshal(r)
			})
			if o.Result.SourceChecks.Status != "FAILED" {
				t.Fatal("trusted publisher forgery accepted", o.Result.SourceChecks)
			}
		})
	}
}

func TestKubernetesObservationAndPlanForgeries(t *testing.T) {
	for _, name := range []string{"corrupt-fixture-response", "missing-fixture-response", "replace-embedded-key", "invalid-plan", "cleanup-claim", "client-timing"} {
		t.Run(name, func(t *testing.T) {
			files := load(t, "kubernetes-healthy", evidencesource.Kubernetes)
			o, _ := signed(t, evidencesource.Kubernetes, files, func(_ *evidence.Manifest, f map[string][]byte) {
				events, e := kubeexperiment.ReadJournalBytes(f["artifacts/kubernetes-journal.jsonl"])
				if e != nil {
					t.Fatal(e)
				}
				switch name {
				case "replace-embedded-key":
					pub, _, _ := ed25519.GenerateKey(rand.Reader)
					events[0].Plan.Target.Fixture.EvidenceKey = hex.EncodeToString(pub)
					events[0].Authorization.PlanDigest = events[0].Plan.Digest()
				case "invalid-plan":
					events[0].Authorization.PlanDigest = "sha256:" + strings.Repeat("e", 64)
				case "cleanup-claim":
					var r kubeexperiment.Report
					json.Unmarshal(f["artifacts/kubernetes-report.json"], &r)
					r.Cleanup = "PENDING"
					f["artifacts/kubernetes-report.json"], _ = json.Marshal(r)
				default:
					for i := range events {
						if o := events[i].Observation; o != nil {
							switch name {
							case "corrupt-fixture-response":
								o.Probes[1].Response.Signature = "bad"
							case "missing-fixture-response":
								o.Probes[1].Response = nil
							case "client-timing":
								o.Probes[1].CompletedNS = -1
							}
							break
						}
					}
				}
				var b bytes.Buffer
				previous := ""
				for i := range events {
					events[i].Sequence = i
					events[i].Previous = previous
					events[i].Hash = ""
					events[i].Hash = kubefault.Digest(events[i].Version, events[i])
					previous = events[i].Hash
					json.NewEncoder(&b).Encode(events[i])
				}
				f["artifacts/kubernetes-journal.jsonl"] = b.Bytes()
			})
			if o.Result.SourceChecks.Status != "FAILED" {
				t.Fatal("fixture or unsigned timing forgery accepted", o.Result.SourceChecks)
			}
		})
	}
}

func TestPartialAndUnsupportedEvidenceAreExplicit(t *testing.T) {
	files := load(t, "postgres-healthy", evidencesource.Postgres)
	delete(files, "artifacts/replication-prepared.json")
	o, _ := signed(t, evidencesource.Postgres, files, nil)
	if o.Result.SourceChecks.Status != "INCOMPLETE" || len(o.Result.Source.Missing) == 0 {
		t.Fatal("partial evidence silently verified")
	}
	files = load(t, "postgres-healthy", evidencesource.Postgres)
	o, _ = signed(t, evidencesource.Postgres, files, func(m *evidence.Manifest, _ map[string][]byte) { m.Source.Mapping = "postgres-replication/v99" })
	if o.Result.SourceChecks.Status != "UNSUPPORTED" {
		t.Fatal("unknown version verified")
	}
	for _, version := range []string{"themis.run/v1alpha1", "themis.experiment/v1alpha1", "themis.experiment/v1alpha2", "themis.kubernetes-plan/v1alpha1", "themis.postgres-recovery/v1alpha1", "themis.postgres-durable/v1alpha1", "themis.postgres-pitr/v1alpha1"} {
		t.Run(version, func(t *testing.T) {
			files := load(t, "postgres-healthy", evidencesource.Postgres)
			o, _ := signed(t, evidencesource.Postgres, files, func(m *evidence.Manifest, _ map[string][]byte) {
				m.Source.Engine = "legacy-import"
				m.Source.Mapping = "legacy-import/v1"
				m.Source.Versions = []string{version}
				m.Source.Unsupported = []string{"legacy-source-checks"}
			})
			if o.Result.SourceChecks.Status != "UNSUPPORTED" {
				t.Fatal("older unsigned evidence silently verified")
			}
		})
	}
}

func TestOfflineInputCannotSelectInfrastructure(t *testing.T) {
	files := load(t, "postgres-healthy", evidencesource.Postgres)
	o, _ := signed(t, evidencesource.Postgres, files, func(m *evidence.Manifest, _ map[string][]byte) { m.Source.Experiment = "docker:/never-execute" })
	if o.Result.SourceChecks.Status != "FAILED" {
		t.Fatal("source selected an executable operation")
	}
	for _, a := range evidencesource.Inventory(evidencesource.Postgres) {
		b := files[a.Path]
		if bytes.Contains(b, []byte(`"Directory"`)) || bytes.Contains(b, []byte(`"Endpoint"`)) || bytes.Contains(b, []byte(`"Actor"`)) {
			t.Fatal("private original plan state exported")
		}
	}
}
