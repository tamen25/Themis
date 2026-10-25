// Package nativeobservation defines the bounded native-dependency live witness.
// Verification uses public bytes only and never opens infrastructure or keys.
package nativeobservation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"time"

	wire "github.com/tamen25/themis/internal/dependencyhttp"
	"github.com/tamen25/themis/pkg/evidence"
)

const (
	Version                = "themis.native-observation/v1alpha1"
	RegistrationVersion    = "themis.native-observation-registration/v1alpha1"
	ApprovalVersion        = "themis.native-public-approval/v1alpha1"
	AdmissionVersion       = "themis.native-witness-admission/v1alpha1"
	RunnerStatementVersion = "themis.native-runner-statement/v1alpha1"
	PolicyVersion          = "themis.native-observation-trust/v1alpha1"
	Domain                 = "themis.native-observation.record.v1"
	Engine                 = "native-dependency-witness"
	MaxRecord              = 32 << 10
	MaxJournal             = 2 << 20
	MaxRecords             = 64
	MaxSamples             = 55
	Duration               = 6 * time.Second
	Interval               = 150 * time.Millisecond
)

var id = regexp.MustCompile(`^[a-f0-9]{64}$`)
var digest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var name = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// ApprovalReference is independently signed by the approver over PUBLIC
// commitments. It is neither the actuator grant nor an execution capability.
type ApprovalReference struct {
	Version        string    `json:"version"`
	Plan           wire.Plan `json:"plan"`
	PlanDigest     string    `json:"planDigest"`
	Invocation     string    `json:"invocation"`
	ApprovalDigest string    `json:"approvalDigest"`
	ApplyKeyID     string    `json:"applyKeyId"`
	CleanupKeyID   string    `json:"cleanupKeyId"`
	Issued         time.Time `json:"issued"`
	ApplyBefore    time.Time `json:"applyBefore"`
	CleanupBefore  time.Time `json:"cleanupBefore"`
	Signature      string    `json:"signature"`
}

func KeyID(key string) string { b, _ := hex.DecodeString(key); return evidence.Hash(b) }
func PublicApproval(g wire.Grant, approver string) (ApprovalReference, error) {
	r := ApprovalReference{Version: ApprovalVersion, Plan: g.Plan, PlanDigest: g.Digest, Invocation: g.Invocation, ApprovalDigest: wire.Hash(g), ApplyKeyID: KeyID(g.ApplyKey), CleanupKeyID: KeyID(g.CleanupKey), Issued: g.Issued, ApplyBefore: g.ApplyBefore, CleanupBefore: g.CleanupBefore}
	if wire.Public(approver) != g.Plan.Binding.ApproverKey || !g.Valid(g.Issued, true) {
		return r, wire.ErrDenied
	}
	r.Signature = wire.Sign(ApprovalVersion, r, approver)
	return r, r.Validate()
}
func (r ApprovalReference) Validate() error {
	sig := r.Signature
	r.Signature = ""
	if r.Version != ApprovalVersion || !r.Plan.Valid() || r.PlanDigest != r.Plan.Digest() || !id.MatchString(r.Invocation) || !digest.MatchString(r.ApprovalDigest) || !id.MatchString(r.ApplyKeyID) || !id.MatchString(r.CleanupKeyID) || r.ApplyKeyID == r.CleanupKeyID || r.Issued.IsZero() || r.ApplyBefore.Sub(r.Issued) != 20*time.Second || r.CleanupBefore.Sub(r.Issued) != 5*time.Minute || !wire.Verify(ApprovalVersion, r, sig, r.Plan.Binding.ApproverKey) {
		return errors.New("invalid native public approval")
	}
	for _, k := range SourceKeys(r.Plan) {
		if k == r.ApplyKeyID || k == r.CleanupKeyID {
			return errors.New("reused native authority")
		}
	}
	return nil
}
func SourceKeys(p wire.Plan) []string {
	b := p.Binding
	keys := []string{KeyID(b.ApproverKey), KeyID(b.InstallerKey), KeyID(b.Target.Application.Process.Key), KeyID(b.Target.Proxy.Process.Key), KeyID(b.Target.Dependency.Process.Key)}
	sort.Strings(keys)
	return keys
}
func Routes() []string {
	return []string{"application:/value", "dependency:/value", "proxy:/receipt/{invocation}", "proxy:/value"}
}

type Registration struct {
	Version    string            `json:"version"`
	Witness    string            `json:"witness"`
	KeyID      string            `json:"keyId"`
	PublicKey  []byte            `json:"publicKey"`
	Algorithm  string            `json:"algorithm"`
	Session    string            `json:"session"`
	Process    string            `json:"process"`
	Approval   ApprovalReference `json:"approval"`
	NotBefore  string            `json:"notBefore"`
	NotAfter   string            `json:"notAfter"`
	MaxSamples int               `json:"maxSamples"`
	IntervalMS int               `json:"intervalMS"`
	DurationMS int               `json:"durationMS"`
	Routes     []string          `json:"routes"`
	Provenance string            `json:"provenance"`
	Signature  []byte            `json:"signature"`
}

func UTC(s string) (time.Time, error) {
	t, e := time.Parse(time.RFC3339Nano, s)
	if e != nil || t.Location() != time.UTC || t.Format(time.RFC3339Nano) != s {
		return t, errors.New("noncanonical witness UTC")
	}
	return t, nil
}
func RegistrationDigest(r Registration) string { return wire.Hash(r) }
func SignRegistration(r Registration, k ed25519.PrivateKey) Registration {
	r.Signature = nil
	r.Signature = ed25519.Sign(k, append([]byte(RegistrationVersion+"\n"), wire.JSON(r)...))
	return r
}
func (r Registration) Validate() error {
	sig := r.Signature
	r.Signature = nil
	a, e := UTC(r.NotBefore)
	b, f := UTC(r.NotAfter)
	if r.Version != RegistrationVersion || !name.MatchString(r.Witness) || len(r.PublicKey) != 32 || r.KeyID != evidence.Fingerprint(r.PublicKey) || r.Algorithm != evidence.Algorithm || !id.MatchString(r.Session) || !id.MatchString(r.Process) || r.Approval.Validate() != nil || e != nil || f != nil || b.Sub(a) != 20*time.Second || a.Before(r.Approval.Issued) || !a.Before(r.Approval.ApplyBefore) || r.MaxSamples != MaxSamples || r.IntervalMS != int(Interval/time.Millisecond) || r.DurationMS != int(Duration/time.Millisecond) || !bytes.Equal(wire.JSON(r.Routes), wire.JSON(Routes())) || r.Provenance != "LIVE_NATIVE_OBSERVER_REGISTRATION" || !ed25519.Verify(r.PublicKey, append([]byte(RegistrationVersion+"\n"), wire.JSON(r)...), sig) {
		return errors.New("invalid native witness registration")
	}
	for _, key := range append(SourceKeys(r.Approval.Plan), r.Approval.ApplyKeyID, r.Approval.CleanupKeyID) {
		if key == r.KeyID {
			return errors.New("witness key reuses source authority")
		}
	}
	return nil
}

type Probe struct {
	Kind        string                 `json:"kind"`
	Nonce       string                 `json:"nonce"`
	StartedNS   int64                  `json:"startedNS"`
	CompletedNS int64                  `json:"completedNS"`
	HTTPCode    int                    `json:"httpCode"`
	Outcome     string                 `json:"outcome"`
	Response    *wire.Reply            `json:"response,omitempty"`
	Authority   *wire.AuthorityReceipt `json:"authority,omitempty"`
}
type Record struct {
	Version            string  `json:"version"`
	Domain             string  `json:"domain"`
	RegistrationDigest string  `json:"registrationDigest"`
	Session            string  `json:"session"`
	Process            string  `json:"process"`
	PID                int     `json:"pid"`
	KeyID              string  `json:"keyId"`
	PlanDigest         string  `json:"planDigest"`
	Invocation         string  `json:"invocation"`
	TargetDigest       string  `json:"targetDigest"`
	Sequence           int     `json:"sequence"`
	Previous           string  `json:"previous"`
	Type               string  `json:"type"`
	UTC                string  `json:"utc"`
	StartedNS          int64   `json:"startedNS"`
	CompletedNS        int64   `json:"completedNS"`
	Identity           string  `json:"identity"`
	Probes             []Probe `json:"probes"`
	Hash               string  `json:"hash"`
	Signature          []byte  `json:"signature"`
}

func Seal(r Record, k ed25519.PrivateKey) Record {
	r.Hash = ""
	r.Signature = nil
	r.Hash = wire.Hash(struct {
		Domain string
		Record Record
	}{Domain, r})
	r.Signature = ed25519.Sign(k, append([]byte(Domain+"\n"), wire.JSON(r)...))
	return r
}
func VerifyRecord(r Record, k ed25519.PublicKey) bool {
	if len(k) != 32 {
		return false
	}
	sig := r.Signature
	r.Signature = nil
	if !ed25519.Verify(k, append([]byte(Domain+"\n"), wire.JSON(r)...), sig) {
		return false
	}
	h := r.Hash
	r.Hash = ""
	return r.Version == Version && r.Domain == Domain && h == wire.Hash(struct {
		Domain string
		Record Record
	}{Domain, r})
}
func Decode(b []byte, v any) error {
	if len(b) > MaxRecord {
		return errors.New("native witness record bound")
	}
	if e := evidence.Decode(b, v); e != nil {
		return e
	}
	if !bytes.Equal(b, wire.JSON(v)) {
		return errors.New("noncanonical native witness JSON")
	}
	return nil
}

type JournalArtifact struct {
	Version  string `json:"version"`
	Encoding string `json:"encoding"`
	Journal  []byte `json:"journal"`
}

func EncodeJournal(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > MaxJournal {
		return nil, errors.New("native journal bound")
	}
	return wire.JSON(JournalArtifact{Version, "base64-original-jsonl", raw}), nil
}
func DecodeJournal(b []byte) ([]byte, error) {
	var j JournalArtifact
	if len(b) > 3<<20 || evidence.Decode(b, &j) != nil || !bytes.Equal(b, wire.JSON(j)) || j.Version != Version || j.Encoding != "base64-original-jsonl" || len(j.Journal) == 0 || len(j.Journal) > MaxJournal {
		return nil, errors.New("invalid native journal wrapper")
	}
	return j.Journal, nil
}

type Admission struct {
	Version            string `json:"version"`
	RegistrationDigest string `json:"registrationDigest"`
	ApprovalDigest     string `json:"approvalDigest"`
	ReadyHash          string `json:"readyHash"`
	ApplyNonce         string `json:"applyNonce"`
	IntentDigest       string `json:"intentDigest"`
}

func ApplyNonce(reg Registration, ready Record) string {
	return evidence.Hash([]byte(AdmissionVersion + "\n" + RegistrationDigest(reg) + "\n" + ready.Hash + "\n" + reg.Approval.ApprovalDigest))
}
func NewAdmission(reg Registration, ready Record) Admission {
	return Admission{Version: AdmissionVersion, RegistrationDigest: RegistrationDigest(reg), ApprovalDigest: reg.Approval.ApprovalDigest, ReadyHash: ready.Hash, ApplyNonce: ApplyNonce(reg, ready)}
}

// RunnerStatement authenticates only this authority holder's own assertions.
// It is not code, machine, execution or infrastructure attestation.
type RunnerStatement struct {
	Version         string `json:"version"`
	Kind            string `json:"kind"`
	Key             string `json:"key"`
	PlanDigest      string `json:"planDigest"`
	Invocation      string `json:"invocation"`
	ApprovalDigest  string `json:"approvalDigest"`
	ReadyCommitment string `json:"readyCommitment"`
	IntentDigest    string `json:"intentDigest"`
	JournalDigest   string `json:"journalDigest"`
	ReportDigest    string `json:"reportDigest"`
	Execution       string `json:"execution"`
	Candidate       string `json:"candidate"`
	Cleanup         string `json:"cleanup"`
	Signature       string `json:"signature"`
}

func SignRunner(s RunnerStatement, key string) RunnerStatement {
	s.Signature = ""
	s.Signature = wire.Sign(RunnerStatementVersion, s, key)
	return s
}
func (s RunnerStatement) Validate(ref ApprovalReference) error {
	sig := s.Signature
	s.Signature = ""
	if s.Version != RunnerStatementVersion || (s.Kind != "INTENT" && s.Kind != "FINAL") || !id.MatchString(s.Key) || KeyID(s.Key) != ref.ApplyKeyID || s.PlanDigest != ref.PlanDigest || s.Invocation != ref.Invocation || s.ApprovalDigest != ref.ApprovalDigest || !id.MatchString(s.ReadyCommitment) || !wire.Verify(RunnerStatementVersion, s, sig, s.Key) {
		return errors.New("invalid native runner statement")
	}
	if s.Kind == "INTENT" && (s.IntentDigest != "" || s.JournalDigest != "" || s.ReportDigest != "" || s.Execution != "INTENT" || s.Candidate != "INCONCLUSIVE" || s.Cleanup != "UNKNOWN") {
		return errors.New("invalid native runner intent")
	}
	if s.Kind == "FINAL" && (!digest.MatchString(s.IntentDigest) || !id.MatchString(s.JournalDigest) || !id.MatchString(s.ReportDigest) || (s.Candidate != "PASS" && s.Candidate != "FAIL" && s.Candidate != "INCONCLUSIVE") || (s.Cleanup != "COMPLETE" && s.Cleanup != "PENDING" && s.Cleanup != "UNKNOWN")) {
		return errors.New("invalid native runner final statement")
	}
	return nil
}
func BindIntent(a Admission, intent RunnerStatement) Admission {
	a.IntentDigest = wire.Hash(intent)
	a.ApplyNonce = evidence.Hash([]byte(RunnerStatementVersion + "\n" + a.ApplyNonce + "\n" + a.IntentDigest))
	return a
}

type Scope struct {
	Run                string   `json:"run"`
	PlanDigest         string   `json:"planDigest"`
	Invocation         string   `json:"invocation"`
	Session            string   `json:"session"`
	RegistrationDigest string   `json:"registrationDigest"`
	TargetDigest       string   `json:"targetDigest"`
	Routes             []string `json:"routes"`
}

func ExactScope(r Registration) Scope {
	return Scope{r.Approval.Plan.Run, r.Approval.PlanDigest, r.Approval.Invocation, r.Session, RegistrationDigest(r), wire.Hash(r.Approval.Plan.Binding.Target), Routes()}
}

type TrustedWitness struct {
	Witness        string  `json:"witness"`
	KeyID          string  `json:"keyId"`
	PublicKey      []byte  `json:"publicKey"`
	Algorithm      string  `json:"algorithm"`
	Engine         string  `json:"engine"`
	Publisher      string  `json:"publisher"`
	PublisherKeyID string  `json:"publisherKeyId"`
	Scopes         []Scope `json:"scopes"`
	NotBefore      string  `json:"notBefore"`
	NotAfter       string  `json:"notAfter"`
	Revoked        bool    `json:"revoked"`
}
type Policy struct {
	Version string           `json:"version"`
	Keys    []TrustedWitness `json:"keys"`
}

func (p Policy) Validate() error {
	if p.Version != PolicyVersion || p.Keys == nil || len(p.Keys) > 32 {
		return errors.New("native witness policy bound/version")
	}
	seen := map[string]bool{}
	for _, k := range p.Keys {
		a, e := UTC(k.NotBefore)
		b, f := UTC(k.NotAfter)
		if !name.MatchString(k.Witness) || !name.MatchString(k.Publisher) || !id.MatchString(k.PublisherKeyID) || len(k.PublicKey) != 32 || k.KeyID != evidence.Fingerprint(k.PublicKey) || k.KeyID == k.PublisherKeyID || k.Algorithm != evidence.Algorithm || k.Engine != Engine || e != nil || f != nil || !a.Before(b) || len(k.Scopes) == 0 || len(k.Scopes) > 32 || seen[k.Witness+"/"+k.KeyID] {
			return errors.New("invalid native witness trust key")
		}
		seen[k.Witness+"/"+k.KeyID] = true
		sessions := map[string]bool{}
		for _, s := range k.Scopes {
			if !id.MatchString(s.Run) || !digest.MatchString(s.PlanDigest) || !id.MatchString(s.Invocation) || !id.MatchString(s.Session) || !digest.MatchString(s.RegistrationDigest) || !digest.MatchString(s.TargetDigest) || !bytes.Equal(wire.JSON(s.Routes), wire.JSON(Routes())) || sessions[s.Session] {
				return errors.New("invalid native witness trust scope")
			}
			sessions[s.Session] = true
		}
	}
	return nil
}
func ReadPolicy(b []byte) (Policy, error) {
	var p Policy
	if len(b) > 128<<10 {
		return p, errors.New("native policy bound")
	}
	if e := evidence.Decode(b, &p); e != nil {
		return p, e
	}
	var value any
	var round any
	// Policies allow formatting, but never case aliases, missing fields or nulls.
	if e := evidence.Decode(b, &value); e != nil {
		return p, e
	}
	if e := evidence.Decode(wire.JSON(p), &round); e != nil {
		return p, e
	}
	if !bytes.Equal(wire.JSON(value), wire.JSON(round)) {
		return p, errors.New("exact native policy fields required")
	}
	return p, p.Validate()
}
func Trusted(r Registration, p *Policy, publisher evidence.Publisher, now time.Time) bool {
	if p == nil || p.Validate() != nil {
		return false
	}
	ra, _ := UTC(r.NotBefore)
	rb, _ := UTC(r.NotAfter)
	for _, k := range p.Keys {
		a, _ := UTC(k.NotBefore)
		b, _ := UTC(k.NotAfter)
		if k.Witness != r.Witness || k.KeyID != r.KeyID || !bytes.Equal(k.PublicKey, r.PublicKey) || k.Publisher != publisher.Name || k.PublisherKeyID != publisher.KeyID || k.Revoked || now.Before(a) || !now.Before(b) || ra.Before(a) || rb.After(b) {
			continue
		}
		for _, s := range k.Scopes {
			if bytes.Equal(wire.JSON(s), wire.JSON(ExactScope(r))) {
				return true
			}
		}
	}
	return false
}
