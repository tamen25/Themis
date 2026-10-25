package liveobservation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/pkg/evidence"
)

// These are fabricated cryptographic conformance inputs, not live experiment
// evidence. Real HTTP/Kind observations are tested separately in test/liveobservation.
func protocolFixture(t testing.TB) (Registration, []Record, Policy, ed25519.PrivateKey) {
	t.Helper()
	data, e := os.ReadFile(filepath.Join("..", "..", "internal", "evidencesource", "testdata", "kubernetes-healthy", "artifacts", "kubernetes-report.json"))
	if e != nil {
		t.Fatal(e)
	}
	var report struct {
		Plan kubefault.Plan `json:"plan"`
	}
	if e = json.Unmarshal(data, &report); e != nil {
		t.Fatal(e)
	}
	fixturePublic, fixtureKey, _ := ed25519.GenerateKey(rand.Reader)
	witnessPublic, witnessKey, _ := ed25519.GenerateKey(rand.Reader)
	p := report.Plan
	p.Target.Fixture.EvidenceKey = hex.EncodeToString(fixturePublic)
	ids := []string{evidence.Hash(fixturePublic), strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64)}
	sort.Strings(ids)
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	reg := Registration{Version: RegistrationVersion, Witness: "test-witness", KeyID: evidence.Fingerprint(witnessPublic), PublicKey: witnessPublic, Algorithm: evidence.Algorithm, Session: kubefault.RandomID(), Plan: p, InvocationID: kubefault.RandomID(), ProposalDigest: "sha256:" + strings.Repeat("d", 64), NotBefore: now.Format(time.RFC3339Nano), NotAfter: now.Add(20 * time.Second).Format(time.RFC3339Nano), MaxSamples: 100, IntervalMillis: 100, MaxApplicationMillis: 150, Provenance: "LIVE_OBSERVER_REGISTRATION", AuthorityKeyIDs: ids}
	reg = SignRegistration(reg, witnessKey)
	records := []Record{}
	offset := int64(0)
	appendRecord := func(kind, phase string) {
		r := Record{Version: Version, Domain: Domain, Witness: reg.Witness, KeyID: reg.KeyID, Session: reg.Session, Process: strings.Repeat("a", 64), PID: 1234, RegistrationDigest: RegistrationDigest(reg), RunID: p.RunUID, PlanDigest: p.Digest(), InvocationID: reg.InvocationID, Target: p.Target.Fixture, Sequence: len(records), Type: kind, Phase: phase, Nonce: kubefault.RandomID(), UTC: now.Add(time.Duration(offset)).Format(time.RFC3339Nano), StartedNS: offset, CompletedNS: offset, Probes: []Probe{}}
		if len(records) > 0 {
			r.Previous = records[len(records)-1].Hash
		}
		switch kind {
		case "START":
			r.Outcome = "LIVE_SESSION_STARTED"
		case "READY":
			r.Outcome = "REGISTERED_BEFORE_INTERVENTION"
		case "END":
			r.Outcome = "COMPLETED"
		case "SAMPLE":
			r.Outcome = "MEASURED"
			for _, kind := range []string{"direct", "proxy", "application"} {
				d := kubefault.Data{Identity: p.Target.Fixture, RequestID: r.Nonce, Kind: kind, HTTPCode: 200}
				duration := int64(10 * time.Millisecond)
				if phase == "intervention" && kind != "direct" {
					d.InvocationID = reg.InvocationID
					if kind == "proxy" {
						duration = int64(time.Duration(p.Fault.DelayMS)*time.Millisecond) + int64(10*time.Millisecond)
						d.ProxyDelayNS = int64(time.Duration(p.Fault.DelayMS) * time.Millisecond)
					} else {
						duration = int64(75 * time.Millisecond)
						d.Degraded = true
					}
				}
				d.Signature = kubefault.Sign("themis.kubernetes-data/v1alpha1", d, fixtureKey)
				r.Probes = append(r.Probes, Probe{Kind: kind, StartedNS: offset, CompletedNS: offset + duration, HTTPCode: 200, Outcome: "MEASURED", Response: &d})
				if offset+duration > r.CompletedNS {
					r.CompletedNS = offset + duration
				}
			}
		}
		r = Seal(r, witnessKey)
		records = append(records, r)
		offset = r.CompletedNS + int64(100*time.Millisecond)
	}
	appendRecord("START", "")
	for i := 0; i < 3; i++ {
		appendRecord("SAMPLE", "baseline")
	}
	appendRecord("READY", "baseline")
	for i := 0; i < 3; i++ {
		appendRecord("SAMPLE", "intervention")
	}
	for i := 0; i < 3; i++ {
		appendRecord("SAMPLE", "recovery")
	}
	appendRecord("END", "")
	policy := Policy{Version: PolicyVersion, Keys: []TrustedWitness{{Witness: reg.Witness, KeyID: reg.KeyID, PublicKey: witnessPublic, Algorithm: evidence.Algorithm, Source: Engine, Scopes: []Scope{{RunID: p.RunUID, PlanDigest: p.Digest(), InvocationID: reg.InvocationID, Session: reg.Session}}, NotBefore: now.Add(-time.Hour).Format(time.RFC3339), NotAfter: now.Add(time.Hour).Format(time.RFC3339)}}}
	return reg, records, policy, witnessKey
}
func stream(records []Record) []byte {
	var b bytes.Buffer
	for _, r := range records {
		_ = json.NewEncoder(&b).Encode(r)
	}
	return b.Bytes()
}
func reseal(records []Record, key ed25519.PrivateKey) []Record {
	previous := ""
	for i := range records {
		records[i].Sequence = i
		records[i].Previous = previous
		records[i] = Seal(records[i], key)
		previous = records[i].Hash
	}
	return records
}
func TestSignedProtocolAndExternalTrust(t *testing.T) {
	r, records, p, _ := protocolFixture(t)
	now, _ := UTC(r.NotBefore)
	f, _ := Analyze(r, stream(records), &p, now)
	if f.Status != "OBSERVED_AND_CORRELATED" || f.ApplicationVerdict != "PASS" || !f.Complete {
		t.Fatal(f)
	}
	untrusted, _ := Analyze(r, stream(records), nil, now)
	if untrusted.Status != "WITNESS_IDENTITY_UNTRUSTED" {
		t.Fatal(untrusted)
	}
	wrapped, e := EncodeJournal(stream(records))
	if e != nil {
		t.Fatal(e)
	}
	raw, e := DecodeJournalArtifact(wrapped)
	if e != nil || !bytes.Equal(raw, stream(records)) {
		t.Fatal("journal changed")
	}
}
func TestWitnessTrustNegativesAndRotation(t *testing.T) {
	for _, name := range []string{"wrong-key", "unknown", "revoked", "expired", "future", "scope-plan", "scope-run", "scope-session", "scope-invocation", "algorithm", "source", "duplicate-scope"} {
		t.Run(name, func(t *testing.T) {
			r, records, p, _ := protocolFixture(t)
			now, _ := UTC(r.NotBefore)
			k := &p.Keys[0]
			switch name {
			case "wrong-key":
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				k.PublicKey = pub
				k.KeyID = evidence.Fingerprint(pub)
			case "unknown":
				k.Witness = "unknown"
			case "revoked":
				k.Revoked = true
			case "expired":
				k.NotAfter = now.Format(time.RFC3339)
			case "future":
				k.NotBefore = now.Add(time.Second).Format(time.RFC3339)
			case "scope-plan":
				k.Scopes[0].PlanDigest = "sha256:" + strings.Repeat("f", 64)
			case "scope-run":
				k.Scopes[0].RunID = "other"
			case "scope-session":
				k.Scopes[0].Session = strings.Repeat("f", 64)
			case "scope-invocation":
				k.Scopes[0].InvocationID = strings.Repeat("f", 64)
			case "algorithm":
				k.Algorithm = "RSA"
			case "source":
				k.Source = "postgres-replication"
			case "duplicate-scope":
				k.Scopes = append(k.Scopes, k.Scopes[0])
			}
			f, _ := Analyze(r, stream(records), &p, now)
			if f.Status != "WITNESS_IDENTITY_UNTRUSTED" {
				t.Fatal(f)
			}
		})
	}
	r, records, p, _ := protocolFixture(t)
	now, _ := UTC(r.NotBefore)
	old := p.Keys[0]
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	next := old
	next.KeyID = evidence.Fingerprint(pub)
	next.PublicKey = pub
	p.Keys = []TrustedWitness{next}
	f, _ := Analyze(r, stream(records), &p, now)
	if f.WitnessTrust == "TRUSTED" {
		t.Fatal("embedded key trusted after rotation")
	}
	p.Keys = append(p.Keys, old)
	f, _ = Analyze(r, stream(records), &p, now)
	if f.WitnessTrust != "TRUSTED" {
		t.Fatal("explicit retained current old key rejected")
	}
}
func TestSignedObservationAdversaries(t *testing.T) {
	for _, name := range []string{"cluster", "pod", "boot", "plan", "session", "run", "process", "duplicate", "drop", "reorder", "nonce", "body", "signature", "late-start", "phase", "timing", "missing-start", "missing-end", "resume-after-end", "domain", "version", "retrospective"} {
		t.Run(name, func(t *testing.T) {
			r, records, p, key := protocolFixture(t)
			now, _ := UTC(r.NotBefore)
			resign := true
			switch name {
			case "cluster":
				records[5].Target.ClusterUID = "other"
			case "pod":
				records[5].Target.PodUID = "other"
			case "boot":
				records[5].Target.InstanceID = strings.Repeat("f", 64)
			case "plan":
				records[5].PlanDigest = "sha256:" + strings.Repeat("f", 64)
			case "session":
				records[5].Session = strings.Repeat("f", 64)
			case "run":
				records[5].RunID = "other"
			case "process":
				records[5].Process = strings.Repeat("b", 64)
			case "duplicate":
				records = append(records[:6], append([]Record{records[5]}, records[6:]...)...)
			case "drop":
				records = append(records[:5], records[6:]...)
				resign = false
			case "reorder":
				records[5], records[6] = records[6], records[5]
				resign = false
			case "nonce":
				records[5].Nonce = records[1].Nonce
			case "body":
				records[5].Probes[2].Response.HTTPCode = 503
			case "signature":
				records[5].Signature[0] ^= 1
				resign = false
			case "late-start":
				records[4].Type = "END"
				records[4].Phase = ""
				records[4].Outcome = "COMPLETED"
			case "phase":
				records[5].Phase = "baseline"
			case "timing":
				records[5].Probes[2].CompletedNS = records[5].Probes[2].StartedNS - 1
			case "missing-start":
				records = records[1:]
				resign = false
			case "missing-end":
				records = records[:len(records)-1]
			case "resume-after-end":
				records = append(records, records[len(records)-1])
			case "domain":
				records[5].Domain = "other"
			case "version":
				records[5].Version = "themis.live-observation/v2"
			case "retrospective":
				r.Provenance = "RETROSPECTIVE"
				r = SignRegistration(r, key)
			}
			if resign {
				records = reseal(records, key)
			}
			f, _ := Analyze(r, stream(records), &p, now)
			if f.Status == "OBSERVED_AND_CORRELATED" {
				t.Fatal("adversary corroborated", name, f)
			}
		})
	}
}
func TestTornAndInterruptedEvidenceNeverFillsCoverage(t *testing.T) {
	r, records, p, key := protocolFixture(t)
	now, _ := UTC(r.NotBefore)
	complete := stream(records)
	for _, raw := range [][]byte{complete[:len(complete)-8], stream(records[:6]), []byte("{torn")} {
		f, _ := Analyze(r, raw, &p, now)
		if f.Complete || f.Status == "OBSERVED_AND_CORRELATED" {
			t.Fatal(f)
		}
	}
	records = records[:6]
	records = append(records, Record{})
	records[6] = records[4]
	records[6].Type = "INTERRUPTED"
	records[6].Phase = ""
	records[6].Outcome = "CANCELLED"
	records[6].StartedNS = records[5].CompletedNS
	records[6].CompletedNS = records[5].CompletedNS
	records[6].Nonce = kubefault.RandomID()
	records = reseal(records, key)
	f, _ := Analyze(r, stream(records), &p, now)
	if f.Complete || f.Status == "OBSERVED_AND_CORRELATED" {
		t.Fatal(f)
	}
}
func TestRegistrationAuthoritySeparationAndStrictFields(t *testing.T) {
	r, _, _, key := protocolFixture(t)
	r.AuthorityKeyIDs[0] = r.KeyID
	sort.Strings(r.AuthorityKeyIDs)
	r = SignRegistration(r, key)
	if r.Validate() == nil {
		t.Fatal("authority key reuse accepted")
	}
	r, _, _, _ = protocolFixture(t)
	raw := jsonBytes(r)
	for _, bad := range [][]byte{append([]byte(`{"unexpected":1,`), raw[1:]...), bytes.Replace(raw, []byte(`"version":`), []byte(`"Version":`), 1), bytes.Replace(raw, []byte(`"version":`), []byte(`"version":"duplicate","version":`), 1)} {
		var out Registration
		if Decode(bad, &out) == nil {
			t.Fatal("ambiguous registration accepted")
		}
	}
}
func FuzzSignedObservationJournal(f *testing.F) {
	reg, records, _, _ := protocolFixture(f)
	now, _ := UTC(reg.NotBefore)
	type publicInput struct {
		Registration Registration `json:"registration"`
		Journal      []byte       `json:"journal"`
	}
	f.Add(jsonBytes(publicInput{reg, stream(records)}))
	f.Add([]byte("{}\n"))
	f.Add([]byte("{torn"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxJournal {
			return
		}
		var out Record
		_ = Decode(b, &out)
		_ = VerifyRecord(out, ed25519.PublicKey(make([]byte, 32)))
		var input publicInput
		if evidence.Decode(b, &input) == nil && len(input.Journal) <= MaxJournal {
			finding, _ := Analyze(input.Registration, input.Journal, nil, now)
			if finding.Status == "OBSERVED_AND_CORRELATED" {
				t.Fatal("untrusted embedded witness became corroboration")
			}
		}
	})
}

func TestInvalidPublicKeyLengthCannotPanicVerifier(t *testing.T) {
	for _, size := range []int{0, 1, 31, 33, 64} {
		if VerifyRecord(Record{}, make([]byte, size)) {
			t.Fatal("invalid witness key length accepted")
		}
	}
}
func FuzzWitnessPolicy(f *testing.F) {
	_, _, policy, _ := protocolFixture(f)
	f.Add(jsonBytes(policy))
	f.Add([]byte(`{"version":"unknown","keys":[]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 128<<10 {
			return
		}
		_, _ = ReadPolicy(b)
	})
}
