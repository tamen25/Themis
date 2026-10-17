package evidencesource_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/evidencesource"
	"github.com/tamen25/themis/internal/postgres"
	"github.com/tamen25/themis/internal/run"
	"github.com/tamen25/themis/pkg/evidence"
	"github.com/tamen25/themis/pkg/evidenceverify"
)

func TestActualOlderReportImportPreservesBytesAndUnsupportedStatus(t *testing.T) {
	for _, name := range []string{"healthy", "unhealthy"} {
		t.Run(name, func(t *testing.T) {
			data, e := os.ReadFile(filepath.Join("..", "run", "testdata", name+"-report.json"))
			if e != nil {
				t.Fatal(e)
			}
			var r run.Report
			if e = json.Unmarshal(data, &r); e != nil {
				t.Fatal(e)
			}
			pub, key, _ := ed25519.GenerateKey(rand.Reader)
			s := evidence.Source{Engine: "local-http", Mapping: "local-http/v1", Experiment: "status-probes", RunID: r.RunID, ContractDigest: strings.TrimPrefix(r.ContractDigest, "sha256:"), PlanDigest: strings.TrimPrefix(r.PlanDigest, "sha256:"), Versions: []string{r.SchemaVersion}, CandidateVerdict: string(r.Verdict), Execution: string(r.Execution.Status), Cleanup: "NOT_REQUIRED", Provenance: "RETROSPECTIVE_PUBLICATION", Missing: []string{}, Unsupported: []string{"legacy-source-checks"}}
			m := evidence.Manifest{Source: s, Publisher: evidence.Publisher{Name: "legacy-review", KeyID: evidence.Fingerprint(pub), PublicKey: pub, Algorithm: evidence.Algorithm, Domain: evidence.Domain}, PublishedAt: "2026-10-18T00:00:00Z", Artifacts: []evidence.Artifact{{Path: "artifacts/legacy-report.json", Role: "legacy-report", Version: r.SchemaVersion}}}
			b, e := evidence.Sign(m, map[string][]byte{"artifacts/legacy-report.json": data}, key)
			if e != nil {
				t.Fatal(e)
			}
			p := evidence.Policy{Version: evidence.PolicyVersion, Keys: []evidence.TrustedKey{{Publisher: m.Publisher.Name, KeyID: m.Publisher.KeyID, PublicKey: pub, Algorithm: evidence.Algorithm, Engines: []string{"local-http"}, NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}}}
			o, e := evidenceverify.Verify(bytes.NewReader(b), int64(len(b)), &p, time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC))
			if e != nil || o.Result.SourceChecks.Status != "UNSUPPORTED" || o.Result.TrustedExecutionVerdict != "INCONCLUSIVE" || o.Result.Source.CandidateVerdict != string(r.Verdict) || !bytes.Equal(o.Artifacts["artifacts/legacy-report.json"], data) {
				t.Fatal("older artifact import altered/upgraded history", e, o.Result)
			}
		})
	}
}

func TestPublisherSourceKeySeparation(t *testing.T) {
	files := load(t, "postgres-healthy", evidencesource.Postgres)
	s, _, e := evidencesource.Describe(evidencesource.Postgres, files)
	if e != nil {
		t.Fatal(e)
	}
	var p postgres.PublicReplicationPlan
	json.Unmarshal(files["artifacts/replication-plan.json"], &p)
	o := evidence.Opened{Manifest: evidence.Manifest{Source: s, Publisher: evidence.Publisher{KeyID: evidence.Fingerprint(p.LedgerKey), PublicKey: p.LedgerKey}, Artifacts: evidencesource.Inventory(evidencesource.Postgres)}, Artifacts: files}
	evidencesource.Check(&o)
	if o.Result.SourceChecks.Status != "FAILED" || !strings.Contains(strings.Join(o.Result.SourceChecks.Problems, " "), "PUBLISHER_REUSES_SOURCE_AUTHORITY_KEY") {
		t.Fatal("source authority accepted as independent publisher")
	}
}
