// Package evidence implements bounded signed artifact integrity and external
// publisher trust. It cannot establish that an infrastructure experiment occurred.
package evidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"time"
)

const (
	Version       = "themis.evidence-bundle/v1alpha1"
	PolicyVersion = "themis.evidence-trust/v1alpha1"
	ResultVersion = "themis.evidence-verification/v1alpha1"
	Algorithm     = "Ed25519"
	Domain        = "themis.evidence-bundle.signature.v1"
	MaxArtifacts  = 64
	MaxFile       = 8 << 20
	MaxTotal      = 32 << 20
	MaxManifest   = 128 << 10
	MaxSignature  = 4 << 10
	MaxArchive    = 34 << 20
)

type Publisher struct {
	Name      string `json:"name"`
	KeyID     string `json:"keyId"`
	PublicKey []byte `json:"publicKey"`
	Algorithm string `json:"algorithm"`
	Domain    string `json:"domain"`
}

type Source struct {
	Engine           string   `json:"engine"`
	Mapping          string   `json:"mapping"`
	Experiment       string   `json:"experiment"`
	RunID            string   `json:"runId"`
	ContractDigest   string   `json:"contractDigest"`
	PlanDigest       string   `json:"planDigest"`
	ExecutionPlan    string   `json:"executionPlan"`
	InvocationID     string   `json:"invocationId"`
	Versions         []string `json:"versions"`
	CandidateVerdict string   `json:"candidateVerdict"`
	Execution        string   `json:"execution"`
	Cleanup          string   `json:"cleanup"`
	Provenance       string   `json:"provenance"`
	Missing          []string `json:"missing"`
	Unsupported      []string `json:"unsupported"`
}

type Artifact struct {
	Path    string `json:"path"`
	Role    string `json:"role"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Bytes   int64  `json:"bytes"`
}

type Manifest struct {
	Version       string     `json:"version"`
	Serialization string     `json:"serialization"`
	BundleID      string     `json:"bundleId"`
	Source        Source     `json:"source"`
	Publisher     Publisher  `json:"publisher"`
	PublishedAt   string     `json:"publishedAt"`
	Artifacts     []Artifact `json:"artifacts"`
}

type Signature struct {
	Version   string `json:"version"`
	Algorithm string `json:"algorithm"`
	Domain    string `json:"domain"`
	Publisher string `json:"publisher"`
	KeyID     string `json:"keyId"`
	Signature []byte `json:"signature"`
}

type TrustedKey struct {
	Publisher string   `json:"publisher"`
	KeyID     string   `json:"keyId"`
	PublicKey []byte   `json:"publicKey"`
	Algorithm string   `json:"algorithm"`
	Engines   []string `json:"engines"`
	NotBefore string   `json:"notBefore"`
	NotAfter  string   `json:"notAfter"`
	Revoked   bool     `json:"revoked"`
}

type Policy struct {
	Version string       `json:"version"`
	Keys    []TrustedKey `json:"keys"`
}

type SourceChecks struct {
	Status                        string   `json:"status"`
	Complete                      bool     `json:"complete"`
	RecomputedCandidate           string   `json:"recomputedCandidate"`
	VerifiedObservationSignatures int      `json:"verifiedObservationSignatures"`
	Checks                        []string `json:"checks"`
	Problems                      []string `json:"problems"`
}

type Result struct {
	Version                         string       `json:"version"`
	BundleID                        string       `json:"bundleId"`
	ArtifactIntegrity               string       `json:"artifactIntegrity"`
	Signature                       string       `json:"signature"`
	PublisherTrust                  string       `json:"publisherTrust"`
	TrustReason                     string       `json:"trustReason"`
	ArtifactComplete                bool         `json:"artifactComplete"`
	Source                          Source       `json:"source"`
	SourceChecks                    SourceChecks `json:"sourceChecks"`
	AuthenticatedPublisherAssertion bool         `json:"authenticatedPublisherAssertion"`
	ExecutionAttestation            string       `json:"executionAttestation"`
	TrustedExecutionVerdict         string       `json:"trustedExecutionVerdict"`
	RemainingUncertainty            []string     `json:"remainingUncertainty"`
}

// Opened owns its in-memory artifact snapshot. It contains no filesystem paths
// that the verifier will open and no infrastructure clients or execution hooks.
type Opened struct {
	Manifest  Manifest
	Artifacts map[string][]byte
	Result    Result
}

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,191}$`)
var pathPattern = regexp.MustCompile(`^artifacts/[a-z][a-z0-9-]{0,62}\.(json|jsonl)$`)
var hexDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

func Hash(data []byte) string                  { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func Fingerprint(key ed25519.PublicKey) string { return Hash(key) }

func canonical(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic("evidence: nonserializable internal value")
	}
	return b
}
func bundleID(m Manifest) string { m.BundleID = ""; return Hash(canonical(m)) }
func message(m []byte) []byte    { return append([]byte(Domain+"\n"), m...) }
func validTime(s string) bool {
	t, e := time.Parse(time.RFC3339, s)
	return e == nil && t.Location() == time.UTC && t.Format(time.RFC3339) == s
}
func sortedStrings(s []string) bool {
	if s == nil || len(s) > 64 || !sort.StringsAreSorted(s) {
		return false
	}
	for i, v := range s {
		if !identifier.MatchString(v) || i > 0 && v == s[i-1] {
			return false
		}
	}
	return true
}

func (m Manifest) validate() error {
	s, p := m.Source, m.Publisher
	if m.Version != Version || m.Serialization != "go-json-struct-v1" || !hexDigest.MatchString(m.BundleID) || m.BundleID != bundleID(m) || !validTime(m.PublishedAt) || p.Algorithm != Algorithm || p.Domain != Domain || !identifier.MatchString(p.Name) || len(p.PublicKey) != ed25519.PublicKeySize || p.KeyID != Fingerprint(p.PublicKey) {
		return errors.New("invalid manifest version, identity, serialization or signature parameters")
	}
	if !identifier.MatchString(s.Engine) || !identifier.MatchString(s.Mapping) || !identifier.MatchString(s.Experiment) || !identifier.MatchString(s.RunID) || !hexDigest.MatchString(s.PlanDigest) || !hexDigest.MatchString(s.ContractDigest) || (s.ExecutionPlan != "" && !hexDigest.MatchString(s.ExecutionPlan)) || (s.InvocationID != "" && !hexDigest.MatchString(s.InvocationID)) || !sortedStrings(s.Versions) || len(s.Versions) == 0 || !sortedStrings(s.Missing) || !sortedStrings(s.Unsupported) || s.Provenance != "RETROSPECTIVE_PUBLICATION" {
		return errors.New("invalid source metadata or provenance")
	}
	switch s.CandidateVerdict {
	case "PASS", "FAIL", "INCONCLUSIVE", "NOT_RUN":
	default:
		return errors.New("invalid candidate verdict")
	}
	if !identifier.MatchString(s.Execution) || !identifier.MatchString(s.Cleanup) || len(m.Artifacts) == 0 || len(m.Artifacts) > MaxArtifacts {
		return errors.New("invalid source disposition or artifact count")
	}
	var total int64
	for n, a := range m.Artifacts {
		if !pathPattern.MatchString(a.Path) || !identifier.MatchString(a.Role) || !identifier.MatchString(a.Version) || !hexDigest.MatchString(a.SHA256) || a.Bytes < 1 || a.Bytes > MaxFile || n > 0 && a.Path <= m.Artifacts[n-1].Path {
			return errors.New("invalid or duplicate artifact descriptor")
		}
		total += a.Bytes
		if total > MaxTotal {
			return errors.New("artifact byte budget exhausted")
		}
	}
	return nil
}

func (p Policy) Validate() error {
	if p.Version != PolicyVersion || p.Keys == nil || len(p.Keys) > 32 {
		return errors.New("invalid trust policy version or key budget")
	}
	seen := map[string]bool{}
	for _, k := range p.Keys {
		if !identifier.MatchString(k.Publisher) || k.Algorithm != Algorithm || len(k.PublicKey) != 32 || k.KeyID != Fingerprint(k.PublicKey) || seen[k.Publisher+"/"+k.KeyID] || !sortedStrings(k.Engines) || len(k.Engines) == 0 || !validTime(k.NotBefore) || !validTime(k.NotAfter) || k.NotBefore >= k.NotAfter {
			return errors.New("invalid, duplicate or ambiguous trusted key")
		}
		seen[k.Publisher+"/"+k.KeyID] = true
	}
	return nil
}

func publisherTrust(m Manifest, p *Policy, now time.Time) (string, string) {
	if p == nil {
		return "UNTRUSTED", "NO_EXTERNAL_POLICY"
	}
	for _, k := range p.Keys {
		if k.Publisher != m.Publisher.Name || k.KeyID != m.Publisher.KeyID {
			continue
		}
		if k.Revoked {
			return "UNTRUSTED", "REVOKED"
		}
		a, _ := time.Parse(time.RFC3339, k.NotBefore)
		b, _ := time.Parse(time.RFC3339, k.NotAfter)
		if now.Before(a) || !now.Before(b) {
			return "UNTRUSTED", "POLICY_NOT_CURRENT"
		}
		for _, e := range k.Engines {
			if e == m.Source.Engine {
				return "TRUSTED", "EXTERNAL_KEY_AND_SCOPE_MATCH"
			}
		}
		return "UNTRUSTED", "ENGINE_SCOPE_DENIED"
	}
	return "UNTRUSTED", "UNKNOWN_PUBLISHER_OR_KEY"
}
