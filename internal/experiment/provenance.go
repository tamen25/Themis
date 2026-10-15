package experiment

import (
	"time"

	"github.com/tamen25/themis/internal/fixture"
	"github.com/tamen25/themis/internal/localpolicy"
)

type EvidenceSource string

const (
	LocallyCollected EvidenceSource = "LOCALLY_COLLECTED"
	UnsignedReplay   EvidenceSource = "UNSIGNED_LOCAL_REPLAY"
	ImportedEvidence EvidenceSource = "IMPORTED_EXTERNAL"
)

type Provenance struct {
	Source                EvidenceSource `json:"source"`
	FixtureResponses      string         `json:"fixtureResponses"`
	ClientTiming          string         `json:"clientTiming"`
	JournalAuthentication string         `json:"journalAuthentication"`
	ExecutionAttestation  string         `json:"executionAttestation"`
	Limitations           []string       `json:"limitations"`
}

type Deadlines struct {
	Experiment     time.Time  `json:"experiment"`
	Lease          time.Time  `json:"lease"`
	Fault          *time.Time `json:"fault,omitempty"`
	Fixture        time.Time  `json:"fixture"`
	CleanupLimitNS int64      `json:"cleanupLimitNS"`
}

func classifyProvenance(r Report, m Manifest, source EvidenceSource) *Provenance {
	p, _ := decodePlan(m.Plan)
	id := p.Snapshot().Target
	verified, total := 0, 0
	for _, o := range r.Observations {
		for _, p := range o.Probes {
			total++
			if p.Response != nil && p.StatusCode == p.Response.HTTPStatus && fixture.VerifyData(*p.Response, id, o.RequestID, p.Kind) {
				verified++
			}
		}
	}
	responses := "MISSING"
	if total > 0 {
		responses = "UNVERIFIED_OR_MISSING"
		if verified == total {
			responses = "SIGNED_FIXTURE_RESPONSES_VERIFIED"
		} else if verified > 0 {
			responses = "PARTIALLY_VERIFIED_FIXTURE_RESPONSES"
		}
	}
	timing := "MISSING"
	if total > 0 {
		timing = "UNAUTHENTICATED_CLIENT_TIMING"
	}
	return &Provenance{Source: source, FixtureResponses: responses, ClientTiming: timing, JournalAuthentication: "UNSIGNED", ExecutionAttestation: "UNVERIFIED", Limitations: []string{"Signatures authenticate fixture response bytes, not client timing or global network conditions.", "The complete journal and operator context have no cryptographic execution attestation.", "Same-user processes and administrators are trusted; imported evidence is not an authorized execution.", "These reports are not an authenticated remote release gate."}}
}

func deadlineSummary(m Manifest, events []Event) *Deadlines {
	p, err := decodePlan(m.Plan)
	if err != nil {
		return nil
	}
	budget, _ := time.ParseDuration(p.Snapshot().Contract.Spec.Execution.MaxDuration)
	d := &Deadlines{Experiment: m.StartedAt.Add(budget), Lease: m.Handle.ExpiresAt, Fixture: p.Snapshot().Target.ExpiresAt, CleanupLimitNS: int64(localpolicy.CleanupLimit)}
	for _, e := range events {
		if e.Receipt != nil {
			expiry := e.Receipt.FaultExpiresAt
			d.Fault = &expiry
		}
	}
	return d
}
