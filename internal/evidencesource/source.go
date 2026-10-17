// Package evidencesource contains two concrete, pure historical source mappings.
// It never invokes a runtime, discovers resources or reads paths from artifacts.
package evidencesource

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"

	"github.com/tamen25/themis/internal/kubeexperiment"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/postgres"
	"github.com/tamen25/themis/internal/result"
	"github.com/tamen25/themis/pkg/evidence"
)

const Postgres = "postgres-replication"
const Kubernetes = "kubernetes-synthetic"

func Inventory(engine string) []evidence.Artifact {
	var names []string
	version := ""
	switch engine {
	case Postgres:
		names = []string{"replication-journal.jsonl", "replication-plan.json", "replication-prepare.jsonl", "replication-prepared.json", "replication-receipts.json", "replication-report.json"}
		version = postgres.ReplicationVersion
	case Kubernetes:
		names = []string{"kubernetes-journal.jsonl", "kubernetes-proposal.json", "kubernetes-report.json"}
	}
	files := []evidence.Artifact{}
	for _, n := range names {
		artifactVersion := version
		if engine == Postgres && n == "replication-plan.json" {
			artifactVersion = postgres.PublicReplicationVersion
		}
		if engine == Kubernetes {
			switch n {
			case "kubernetes-journal.jsonl":
				artifactVersion = kubeexperiment.LifecycleJournalVersion
			case "kubernetes-proposal.json":
				artifactVersion = kubeexperiment.CoordinationProposalVersion
			case "kubernetes-report.json":
				artifactVersion = kubeexperiment.LifecycleReportVersion
			}
		}
		role := "source-observations"
		if strings.Contains(n, "plan") || strings.Contains(n, "proposal") {
			role = "source-plan"
		}
		if strings.Contains(n, "report") {
			role = "source-report"
		}
		files = append(files, evidence.Artifact{Path: "artifacts/" + n, Role: role, Version: artifactVersion})
	}
	return files
}

// Describe derives source claims from public artifacts instead of CLI-supplied
// verdicts. The original source bytes are retained; historical formats do not change.
func Describe(engine string, files map[string][]byte) (s evidence.Source, c evidence.SourceChecks, err error) {
	s = evidence.Source{Engine: engine, Mapping: engine + "/v1", Provenance: "RETROSPECTIVE_PUBLICATION", Missing: []string{}, Unsupported: []string{}}
	c = evidence.SourceChecks{Status: "FAILED", RecomputedCandidate: "INCONCLUSIVE", Checks: []string{}, Problems: []string{}}
	for _, a := range Inventory(engine) {
		if _, ok := files[a.Path]; !ok {
			s.Missing = append(s.Missing, a.Path)
		}
	}
	sort.Strings(s.Missing)
	switch engine {
	case Postgres:
		var v postgres.ReplicationEvidence
		v, err = postgres.CheckReplicationEvidence(files)
		if err != nil {
			return s, c, err
		}
		p, r := v.Plan, v.Report
		s.Unsupported = []string{"original-private-plan-recompilation"}
		contract, _ := json.Marshal(p.Contract)
		s.Experiment = p.Contract.Workflow
		s.RunID = r.Run
		s.ContractDigest = evidence.Hash(contract)
		s.PlanDigest = p.Digest
		s.ExecutionPlan = r.ExecutionPlan
		s.InvocationID = r.Measurements.Prepared.Invocation
		s.Versions = []string{postgres.ReplicationVersion, postgres.PublicReplicationVersion}
		sort.Strings(s.Versions)
		s.CandidateVerdict = string(r.Verdict)
		s.Execution = string(r.Execution)
		s.Cleanup = "PENDING"
		if r.Cleanup.Complete {
			s.Cleanup = "COMPLETE"
		}
		c.Complete = v.Complete
		c.RecomputedCandidate = string(v.Candidate)
		c.VerifiedObservationSignatures = v.Signatures
		c.Problems = v.Problems
		c.Checks = []string{"public-plan-projection-digest-and-original-plan-references", "preparation-seal-and-ledger-signatures-under-embedded-key", "preparation-and-execution-unsigned-journal-chains", "invocation-and-final-report-bindings", "receipt-row-data-loss-comparison-where-observed", "existing-source-assertion-recomputation", "historical-cleanup-consistency"}
	case Kubernetes:
		data, ok := files["artifacts/kubernetes-journal.jsonl"]
		if !ok {
			return s, c, errors.New("missing Kubernetes journal")
		}
		v, e := kubeexperiment.VerifyEvidenceBytes(data, "")
		if e != nil {
			return s, c, e
		}
		events, e := kubeexperiment.ReadJournalBytes(data)
		if e != nil {
			return s, c, e
		}
		p := *events[0].Plan
		if events[0].Version != kubeexperiment.LifecycleJournalVersion {
			return s, c, errors.New("unsupported Kubernetes source journal version")
		}
		versions := map[string]bool{events[0].Version: true, p.Version: true, p.Contract.Version: true, p.Target.Fixture.Version: true, events[0].Authorization.Version: true}
		var r kubeexperiment.Report
		if localstate.Unmarshal(files["artifacts/kubernetes-report.json"], &r) != nil {
			return s, c, errors.New("missing or invalid Kubernetes report")
		}
		if r.Version != kubeexperiment.LifecycleReportVersion || r.PlanDigest != p.Digest() || !reflect.DeepEqual(r.Plan, p) || !reflect.DeepEqual(r.Authorization, *events[0].Authorization) || !reflect.DeepEqual(r.Observations, v.Report.Observations) || !reflect.DeepEqual(r.Assertions, v.Report.Assertions) || r.CandidateVerdict != v.Report.CandidateVerdict || r.Execution != v.Report.Execution || r.Cleanup != v.Report.Cleanup || r.InterventionConfirmed != v.Report.InterventionConfirmed || r.RecoveryVerified != v.Report.RecoveryVerified || r.CancellationAccepted != v.Report.CancellationAccepted {
			return s, c, errors.New("Kubernetes report differs from independent journal assessment")
		}
		if r.Verdict != v.CandidateVerdict && !(r.Verdict == result.Inconclusive && v.CandidateVerdict == result.Pass && r.Execution != result.Succeeded) {
			return s, c, errors.New("forged historical Kubernetes verdict")
		}
		if b, ok := files["artifacts/kubernetes-proposal.json"]; ok {
			var proposal kubeexperiment.CoordinationProposal
			if localstate.Unmarshal(b, &proposal) != nil || proposal.Validate() != nil || !reflect.DeepEqual(proposal.Plan, p) {
				return s, c, errors.New("coordination proposal/preview/request/plan binding invalid")
			}
			versions[proposal.Version] = true
			versions[proposal.Preview.Plan.SchemaVersion] = true
		} else {
			c.Problems = append(c.Problems, "MISSING_COORDINATION_PROPOSAL")
		}
		if !v.BindingsValid || v.InvalidDataSignatures != 0 {
			return s, c, errors.New("invalid fixture signature, identity or lifecycle")
		}
		contract, _ := json.Marshal(p.Contract)
		s.Experiment = "http-response-latency"
		s.RunID = p.RunUID
		s.ContractDigest = evidence.Hash(contract)
		s.PlanDigest = strings.TrimPrefix(p.Digest(), "sha256:")
		s.ExecutionPlan = strings.TrimPrefix(p.PreviewDigest, "sha256:")
		s.InvocationID = events[0].Authorization.InvocationID
		versions[r.Version] = true
		for version := range versions {
			s.Versions = append(s.Versions, version)
		}
		sort.Strings(s.Versions)
		s.CandidateVerdict = string(r.Verdict)
		s.Execution = string(r.Execution)
		s.Cleanup = r.Cleanup
		c.Complete = v.JournalComplete && len(s.Missing) == 0 && v.MissingMeasurements == 0
		c.RecomputedCandidate = string(v.CandidateVerdict)
		c.VerifiedObservationSignatures = v.VerifiedDataSignatures + v.VerifiedStatusSignatures
		c.Problems = append(c.Problems, v.Problems...)
		c.Checks = []string{"original-execution-plan-digest", "coordination-preview-request-and-identity-bindings-where-present", "unsigned-journal-chain-and-lifecycle", "fixture-response-signatures-under-embedded-key", "paired-client-timing-predicates-with-unauthenticated-clock", "existing-source-assertion-recomputation", "historical-cleanup-consistency"}
	default:
		return s, evidence.SourceChecks{Status: "UNSUPPORTED", RecomputedCandidate: "INCONCLUSIVE", Checks: []string{}, Problems: []string{"UNSUPPORTED_SOURCE_ENGINE_OR_VERSION"}}, nil
	}
	c.Status = "PASSED"
	if !c.Complete {
		c.Status = "INCOMPLETE"
	}
	return s, c, nil
}

// Check binds the mapping-derived claims to the authenticated manifest. Source
// contradictions fail even when a trusted publisher deliberately signed them.
func Check(o *evidence.Opened) {
	if o.Manifest.Source.Mapping != o.Manifest.Source.Engine+"/v1" {
		o.Result.SourceChecks = evidence.SourceChecks{Status: "UNSUPPORTED", RecomputedCandidate: "INCONCLUSIVE", Checks: []string{}, Problems: []string{"UNSUPPORTED_SOURCE_MAPPING_VERSION"}}
		return
	}
	s, c, err := Describe(o.Manifest.Source.Engine, o.Artifacts)
	if err != nil {
		c.Status = "FAILED"
		c.Problems = append(c.Problems, err.Error())
		o.Result.SourceChecks = c
		return
	}
	if c.Status == "UNSUPPORTED" {
		o.Result.SourceChecks = c
		return
	}
	if !reflect.DeepEqual(s, o.Manifest.Source) {
		c.Status = "FAILED"
		c.Problems = append(c.Problems, "SIGNED_SOURCE_CLAIMS_DIFFER_FROM_ARTIFACTS")
	}
	want := map[string]evidence.Artifact{}
	for _, a := range Inventory(s.Engine) {
		want[a.Path] = a
	}
	for _, a := range o.Manifest.Artifacts {
		e, ok := want[a.Path]
		if !ok || e.Role != a.Role || e.Version != a.Version {
			c.Status = "FAILED"
			c.Problems = append(c.Problems, "UNDECLARED_SOURCE_MAPPING_ARTIFACT")
		}
	}
	// Publication authority must not be one of the fixture/setup keys it claims
	// to assess. No automatic promotion of an embedded observation trust root.
	if s.Engine == Postgres {
		var p postgres.PublicReplicationPlan
		if localstate.Unmarshal(o.Artifacts["artifacts/replication-plan.json"], &p) == nil {
			for _, key := range p.AuthorityKeyIDs {
				if key == o.Manifest.Publisher.KeyID {
					c.Status = "FAILED"
					c.Problems = append(c.Problems, "PUBLISHER_REUSES_SOURCE_AUTHORITY_KEY")
				}
			}
		}
	} else if s.Engine == Kubernetes {
		events, e := kubeexperiment.ReadJournalBytes(o.Artifacts["artifacts/kubernetes-journal.jsonl"])
		if e == nil {
			key, _ := hex.DecodeString(events[0].Plan.Target.Fixture.EvidenceKey)
			if bytes.Equal(key, o.Manifest.Publisher.PublicKey) {
				c.Status = "FAILED"
				c.Problems = append(c.Problems, "PUBLISHER_REUSES_FIXTURE_KEY")
			}
		}
		var proposal kubeexperiment.CoordinationProposal
		if localstate.Unmarshal(o.Artifacts["artifacts/kubernetes-proposal.json"], &proposal) == nil {
			key, _ := hex.DecodeString(proposal.ApproverKey)
			if bytes.Equal(key, o.Manifest.Publisher.PublicKey) {
				c.Status = "FAILED"
				c.Problems = append(c.Problems, "PUBLISHER_REUSES_APPROVAL_KEY")
			}
		}
	}
	o.Result.SourceChecks = c
}
