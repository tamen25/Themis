// Package liveobservation defines one bounded signed HTTP witness protocol.
// It has no execution authority or infrastructure clients.
package liveobservation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"time"

	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/pkg/evidence"
)

const (
	Version             = "themis.live-observation/v1alpha1"
	RegistrationVersion = "themis.live-observation-registration/v1alpha1"
	PolicyVersion       = "themis.live-observation-trust/v1alpha1"
	Domain              = "themis.live-observation.record.v1"
	RegistrationDomain  = "themis.live-observation.registration.v1"
	Engine              = "kubernetes-synthetic-witness"
	MaxRecords          = 128
	MaxRecord           = 32 << 10
	MaxJournal          = 2 << 20
	MaxSamples          = 100
	MaxDuration         = 12 * time.Second
)

type Registration struct {
	Version              string         `json:"version"`
	Witness              string         `json:"witness"`
	KeyID                string         `json:"keyId"`
	PublicKey            []byte         `json:"publicKey"`
	Algorithm            string         `json:"algorithm"`
	Session              string         `json:"session"`
	Plan                 kubefault.Plan `json:"plan"`
	InvocationID         string         `json:"invocationId"`
	ProposalDigest       string         `json:"proposalDigest"`
	NotBefore            string         `json:"notBefore"`
	NotAfter             string         `json:"notAfter"`
	MaxSamples           int            `json:"maxSamples"`
	IntervalMillis       int            `json:"intervalMillis"`
	MaxApplicationMillis int            `json:"maxApplicationMillis"`
	Provenance           string         `json:"provenance"`
	AuthorityKeyIDs      []string       `json:"authorityKeyIds"`
	Signature            []byte         `json:"signature"`
}
type Probe struct {
	Kind        string          `json:"kind"`
	StartedNS   int64           `json:"startedNS"`
	CompletedNS int64           `json:"completedNS"`
	HTTPCode    int             `json:"httpCode"`
	Outcome     string          `json:"outcome"`
	Response    *kubefault.Data `json:"response,omitempty"`
}
type Record struct {
	Version            string             `json:"version"`
	Domain             string             `json:"domain"`
	Witness            string             `json:"witness"`
	KeyID              string             `json:"keyId"`
	Session            string             `json:"session"`
	Process            string             `json:"process"`
	PID                int                `json:"pid"`
	RegistrationDigest string             `json:"registrationDigest"`
	RunID              string             `json:"runId"`
	PlanDigest         string             `json:"planDigest"`
	InvocationID       string             `json:"invocationId"`
	Target             kubefault.Identity `json:"target"`
	Sequence           int                `json:"sequence"`
	Previous           string             `json:"previous"`
	Type               string             `json:"type"`
	Phase              string             `json:"phase"`
	Nonce              string             `json:"nonce"`
	UTC                string             `json:"utc"`
	StartedNS          int64              `json:"startedNS"`
	CompletedNS        int64              `json:"completedNS"`
	Outcome            string             `json:"outcome"`
	Probes             []Probe            `json:"probes"`
	Hash               string             `json:"hash"`
	Signature          []byte             `json:"signature"`
}
type Scope struct {
	RunID        string `json:"runId"`
	PlanDigest   string `json:"planDigest"`
	InvocationID string `json:"invocationId"`
	Session      string `json:"session"`
}
type TrustedWitness struct {
	Witness   string  `json:"witness"`
	KeyID     string  `json:"keyId"`
	PublicKey []byte  `json:"publicKey"`
	Algorithm string  `json:"algorithm"`
	Source    string  `json:"source"`
	Scopes    []Scope `json:"scopes"`
	NotBefore string  `json:"notBefore"`
	NotAfter  string  `json:"notAfter"`
	Revoked   bool    `json:"revoked"`
}
type Policy struct {
	Version string           `json:"version"`
	Keys    []TrustedWitness `json:"keys"`
}
type Finding struct {
	Version                      string   `json:"version"`
	Status                       string   `json:"status"`
	WitnessTrust                 string   `json:"witnessTrust"`
	SignatureChain               string   `json:"signatureChain"`
	RunnerCorrelation            string   `json:"runnerCorrelation"`
	Complete                     bool     `json:"complete"`
	Baseline                     int      `json:"baselineSamples"`
	Intervention                 int      `json:"interventionSamples"`
	Recovery                     int      `json:"recoverySamples"`
	EffectSamples                int      `json:"effectSamples"`
	ApplicationFailures          int      `json:"applicationFailures"`
	TimingFailures               int      `json:"timingFailures"`
	BaselineApplicationMaxNS     int64    `json:"baselineApplicationMaxNS"`
	InterventionApplicationMaxNS int64    `json:"interventionApplicationMaxNS"`
	RecoveryApplicationMaxNS     int64    `json:"recoveryApplicationMaxNS"`
	ApplicationVerdict           string   `json:"candidateApplicationVerdict"`
	Problems                     []string `json:"problems"`
	Limitations                  []string `json:"limitations"`
}

// JournalArtifact preserves exact original JSONL bytes, including a torn final
// write, inside a bounded JSON archive artifact. It never invents a terminal.
type JournalArtifact struct {
	Version  string `json:"version"`
	Encoding string `json:"encoding"`
	Journal  []byte `json:"journal"`
}

func EncodeJournal(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > MaxJournal {
		return nil, errors.New("witness journal size")
	}
	return jsonBytes(JournalArtifact{Version, "base64-original-jsonl", raw}), nil
}
func DecodeJournalArtifact(data []byte) ([]byte, error) {
	var j JournalArtifact
	if len(data) > 3<<20 {
		return nil, errors.New("witness artifact size")
	}
	if e := evidence.Decode(data, &j); e != nil {
		return nil, e
	}
	if j.Version != Version || j.Encoding != "base64-original-jsonl" || len(j.Journal) == 0 || len(j.Journal) > MaxJournal || !bytes.Equal(data, jsonBytes(j)) {
		return nil, errors.New("unsupported witness journal artifact")
	}
	return j.Journal, nil
}

var hexID = regexp.MustCompile(`^[a-f0-9]{64}$`)
var name = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

func jsonBytes(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	return b
}
func UTC(s string) (time.Time, error) {
	t, e := time.Parse(time.RFC3339Nano, s)
	if e != nil || t.Location() != time.UTC || t.Format(time.RFC3339Nano) != s {
		return t, errors.New("invalid witness UTC assertion")
	}
	return t, nil
}
func RegistrationDigest(r Registration) string { return evidence.Hash(jsonBytes(r)) }
func SignRegistration(r Registration, key ed25519.PrivateKey) Registration {
	r.Signature = nil
	r.Signature = ed25519.Sign(key, append([]byte(RegistrationDomain+"\n"), jsonBytes(r)...))
	return r
}
func (r Registration) Validate() error {
	sig := r.Signature
	r.Signature = nil
	before, e := UTC(r.NotBefore)
	after, f := UTC(r.NotAfter)
	if r.Version != RegistrationVersion || !name.MatchString(r.Witness) || r.Algorithm != evidence.Algorithm || len(r.PublicKey) != 32 || r.KeyID != evidence.Fingerprint(r.PublicKey) || !hexID.MatchString(r.Session) || r.Plan.Validate() != nil || !hexID.MatchString(r.InvocationID) || !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(r.ProposalDigest) || r.Provenance != "LIVE_OBSERVER_REGISTRATION" || e != nil || f != nil || after.Sub(before) <= 0 || after.Sub(before) > 20*time.Second || r.MaxSamples < 12 || r.MaxSamples > MaxSamples || r.IntervalMillis < 100 || r.IntervalMillis > 250 || r.MaxApplicationMillis < 1 || r.MaxApplicationMillis > 500 || !ed25519.Verify(r.PublicKey, append([]byte(RegistrationDomain+"\n"), jsonBytes(r)...), sig) {
		return errors.New("invalid witness registration or signature")
	}
	if len(r.AuthorityKeyIDs) != 4 || !sort.StringsAreSorted(r.AuthorityKeyIDs) {
		return errors.New("four distinct source authority commitments required")
	}
	fixtureKey, _ := hex.DecodeString(r.Plan.Target.Fixture.EvidenceKey)
	fixtureFound := false
	for i, key := range r.AuthorityKeyIDs {
		if !hexID.MatchString(key) || key == r.KeyID || i > 0 && key == r.AuthorityKeyIDs[i-1] {
			return errors.New("witness reuses a declared authority key")
		}
		if key == evidence.Hash(fixtureKey) {
			fixtureFound = true
		}
	}
	if !fixtureFound {
		return errors.New("missing fixture authority commitment")
	}
	return nil
}
func Seal(r Record, key ed25519.PrivateKey) Record {
	r.Hash = ""
	r.Signature = nil
	r.Hash = evidence.Hash(append([]byte(Domain+"\n"), jsonBytes(r)...))
	r.Signature = ed25519.Sign(key, append([]byte(Domain+"\n"), jsonBytes(r)...))
	return r
}
func VerifyRecord(r Record, key ed25519.PublicKey) bool {
	if len(key) != ed25519.PublicKeySize {
		return false
	}
	sig := r.Signature
	r.Signature = nil
	if !ed25519.Verify(key, append([]byte(Domain+"\n"), jsonBytes(r)...), sig) {
		return false
	}
	hash := r.Hash
	r.Hash = ""
	return r.Version == Version && r.Domain == Domain && hash == evidence.Hash(append([]byte(Domain+"\n"), jsonBytes(r)...))
}
func Decode(b []byte, out any) error {
	if len(b) > MaxRecord {
		return errors.New("witness JSON record limit")
	}
	if e := evidence.Decode(b, out); e != nil {
		return e
	}
	if !bytes.Equal(b, jsonBytes(out)) {
		return errors.New("noncanonical witness JSON")
	}
	return nil
}
func ReadPolicy(b []byte) (Policy, error) {
	var p Policy
	if len(b) > 128<<10 {
		return p, errors.New("witness policy size")
	}
	if e := evidence.Decode(b, &p); e != nil {
		return p, e
	}
	var original, roundtrip any
	if json.Unmarshal(b, &original) != nil || json.Unmarshal(jsonBytes(p), &roundtrip) != nil || !bytes.Equal(jsonBytes(original), jsonBytes(roundtrip)) {
		return p, errors.New("exact witness policy fields required")
	}
	return p, p.Validate()
}
func (p Policy) Validate() error {
	if p.Version != PolicyVersion || p.Keys == nil || len(p.Keys) > 32 {
		return errors.New("unsupported witness policy")
	}
	seen := map[string]bool{}
	for _, k := range p.Keys {
		a, e := UTC(k.NotBefore)
		b, f := UTC(k.NotAfter)
		if !name.MatchString(k.Witness) || k.Algorithm != evidence.Algorithm || len(k.PublicKey) != 32 || k.KeyID != evidence.Fingerprint(k.PublicKey) || k.Source != Engine || e != nil || f != nil || !a.Before(b) || seen[k.Witness+"/"+k.KeyID] || len(k.Scopes) < 1 || len(k.Scopes) > 32 {
			return errors.New("invalid witness key or scope")
		}
		seen[k.Witness+"/"+k.KeyID] = true
		scopes := map[string]bool{}
		for _, s := range k.Scopes {
			key := string(jsonBytes(s))
			if !hexID.MatchString(s.InvocationID) || !hexID.MatchString(s.Session) || !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(s.PlanDigest) || s.RunID == "" || scopes[key] {
				return errors.New("invalid or repeated witness scope")
			}
			scopes[key] = true
		}
	}
	return nil
}
func Trusted(r Registration, p *Policy, now time.Time) bool {
	if p == nil || p.Validate() != nil {
		return false
	}
	for _, k := range p.Keys {
		a, _ := UTC(k.NotBefore)
		b, _ := UTC(k.NotAfter)
		if k.Witness != r.Witness || k.KeyID != r.KeyID || !bytes.Equal(k.PublicKey, r.PublicKey) || k.Revoked || now.Before(a) || !now.Before(b) {
			continue
		}
		for _, s := range k.Scopes {
			if s.RunID == r.Plan.RunUID && s.PlanDigest == r.Plan.Digest() && s.InvocationID == r.InvocationID && s.Session == r.Session {
				return true
			}
		}
	}
	return false
}
