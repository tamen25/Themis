package nativeobservation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	adapter "github.com/tamen25/themis/internal/dependencyexperiment"
	wire "github.com/tamen25/themis/internal/dependencyhttp"
	"github.com/tamen25/themis/pkg/evidence"
)

// These are controlled cryptographic/timing fixtures, not live execution claims.
type fixture struct {
	reg     Registration
	key     ed25519.PrivateKey
	keys    map[string]string
	pub     evidence.Publisher
	policy  Policy
	records []Record
	now     time.Time
}

func makeFixture(t testing.TB, ceiling int) fixture {
	t.Helper()
	raw, e := os.ReadFile("../../internal/dependencyexperiment/testdata/A-pass.json")
	if e != nil {
		t.Fatal(e)
	}
	var old adapter.Report
	if json.Unmarshal(raw, &old) != nil {
		t.Fatal("public target fixture")
	}
	p := old.Plan
	p.Run = wire.ID()
	p.MaxApplicationMS = ceiling
	keys := map[string]string{}
	next := func(role string) string {
		pub, key, e := wire.NewKey()
		if e != nil {
			t.Fatal(e)
		}
		keys[role] = key
		return pub
	}
	p.Binding.Target.Application.Process.Key = next("application")
	p.Binding.Target.Proxy.Process.Key = next("proxy")
	p.Binding.Target.Dependency.Process.Key = next("dependency")
	p.Binding.ApproverKey = next("approver")
	p.Binding.InstallerKey = next("installer")
	p.Binding.Signature = ""
	p.Binding.Signature = wire.Sign(wire.BindingVersion, p.Binding, keys["installer"])
	now := time.Date(2026, 10, 18, 14, 0, 0, 0, time.UTC)
	authority, e := wire.Approve(p, p.Digest(), keys["approver"], now)
	if e != nil {
		t.Fatal(e)
	}
	ref, e := PublicApproval(authority.Grant, keys["approver"])
	if e != nil {
		t.Fatal(e)
	}
	keys["apply"] = authority.ApplyPrivate
	keys["cleanup"] = authority.CleanupPrivate
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	r := Registration{Version: RegistrationVersion, Witness: "controlled-unit-witness", KeyID: evidence.Fingerprint(pub), PublicKey: pub, Algorithm: evidence.Algorithm, Session: wire.ID(), Process: wire.ID(), Approval: ref, NotBefore: now.Format(time.RFC3339Nano), NotAfter: now.Add(20 * time.Second).Format(time.RFC3339Nano), MaxSamples: MaxSamples, IntervalMS: 150, DurationMS: 6000, Routes: Routes(), Provenance: "LIVE_NATIVE_OBSERVER_REGISTRATION"}
	r = SignRegistration(r, key)
	if e = r.Validate(); e != nil {
		t.Fatal(e)
	}
	pp, _, _ := ed25519.GenerateKey(rand.Reader)
	publisher := evidence.Publisher{Name: "controlled-unit-publisher", KeyID: evidence.Fingerprint(pp), PublicKey: pp, Algorithm: evidence.Algorithm, Domain: evidence.Domain}
	policy := Policy{PolicyVersion, []TrustedWitness{{Witness: r.Witness, KeyID: r.KeyID, PublicKey: pub, Algorithm: evidence.Algorithm, Engine: Engine, Publisher: publisher.Name, PublisherKeyID: publisher.KeyID, Scopes: []Scope{ExactScope(r)}, NotBefore: now.Add(-time.Hour).Format(time.RFC3339Nano), NotAfter: now.Add(time.Hour).Format(time.RFC3339Nano)}}}
	f := fixture{reg: r, key: key, keys: keys, pub: publisher, policy: policy, now: now}
	appendRecord := func(kind string, start, end int64, probes []Probe) {
		rec := Record{Version: Version, Domain: Domain, RegistrationDigest: RegistrationDigest(r), Session: r.Session, Process: r.Process, PID: 123, KeyID: r.KeyID, PlanDigest: p.Digest(), Invocation: ref.Invocation, TargetDigest: wire.Hash(p.Binding.Target), Sequence: len(f.records), Type: kind, UTC: now.Add(time.Duration(end)).Format(time.RFC3339Nano), StartedNS: start, CompletedNS: end, Identity: "CONFIRMED", Probes: probes}
		if probes == nil {
			rec.Probes = []Probe{}
		}
		if len(f.records) > 0 {
			rec.Previous = f.records[len(f.records)-1].Hash
		}
		rec = Seal(rec, key)
		f.records = append(f.records, rec)
	}
	appendRecord("START", 0, 0, nil)
	for i := 0; i < 11; i++ {
		start := int64(time.Millisecond) + int64(i)*int64(200*time.Millisecond)
		active := i >= 3 && i < 7
		probes := make([]Probe, 4)
		sign := func(r wire.Reply, role string) *wire.Reply {
			r.Version = wire.Version
			r.Identity = map[string]wire.Process{"application": p.Binding.Target.Application.Process, "proxy": p.Binding.Target.Proxy.Process, "dependency": p.Binding.Target.Dependency.Process}[role]
			r.Signature = ""
			r.Signature = wire.Sign(wire.Version, r, keys[role])
			return &r
		}
		for j, kind := range []string{"direct", "proxy", "application", "state"} {
			nonce := wire.ID()
			if kind == "state" {
				r := wire.AuthorityReceipt{Version: wire.AuthorityReceiptVersion, Identity: p.Binding.Target.Proxy.Process, Nonce: nonce, Invocation: ref.Invocation, Code: 404}
				if i >= 3 {
					r.Code = 200
					r.PlanDigest = p.Digest()
					r.GrantDigest = ref.ApprovalDigest
					r.ApplyKeyID = ref.ApplyKeyID
					r.CleanupKeyID = ref.CleanupKeyID
					r.State = wire.State{Invocation: ref.Invocation, Applied: true, ApplyCount: 1, Active: active, StartedNS: 100, DeadlineNS: 100 + int64(1500*time.Millisecond), Reason: "active"}
					if !active {
						r.State.Reason = "expired"
					}
				}
				r.Signature = wire.Sign(wire.AuthorityReceiptVersion, r, keys["proxy"])
				probes[j] = Probe{Kind: kind, Nonce: nonce, StartedNS: start, CompletedNS: start + int64(time.Millisecond), HTTPCode: r.Code, Outcome: "MEASURED", Authority: &r}
				continue
			}
			delay := time.Millisecond
			role := "dependency"
			route := "value"
			state := wire.State{}
			if active {
				state = wire.State{Invocation: ref.Invocation, Applied: true, ApplyCount: 1, Active: true, StartedNS: 100, DeadlineNS: 100 + int64(1500*time.Millisecond), Reason: "active"}
			}
			dep := func() *wire.Reply {
				return sign(wire.Reply{Nonce: nonce, Kind: "value", Code: 200, Value: "synthetic-dependency-v1"}, "dependency")
			}
			proxy := func() *wire.Reply {
				reply := wire.Reply{Nonce: nonce, Kind: "value", Code: 200, Value: "synthetic-dependency-v1", Dependency: dep(), State: state}
				if active {
					reply.PlanDigest = p.Digest()
					reply.HoldNS = int64(150 * time.Millisecond)
				}
				return sign(reply, "proxy")
			}
			reply := dep()
			if kind == "proxy" {
				role = "proxy"
				delay = 2 * time.Millisecond
				if active {
					delay = 151 * time.Millisecond
				}
				reply = proxy()
			}
			if kind == "application" {
				role = "application"
				delay = 5 * time.Millisecond
				if active {
					delay = 154 * time.Millisecond
				}
				reply = sign(wire.Reply{Nonce: nonce, Kind: "value", Code: 200, Value: "synthetic-dependency-v1", Proxy: proxy()}, role)
			}
			if kind == "state" {
				route = "state"
				reply = sign(wire.Reply{Nonce: nonce, Kind: route, Code: 200, State: state}, "proxy")
			}
			probes[j] = Probe{Kind: kind, Nonce: nonce, StartedNS: start, CompletedNS: start + int64(delay), HTTPCode: 200, Outcome: "MEASURED", Response: reply}
		}
		end := start + int64(5*time.Millisecond)
		if active {
			end = start + int64(154*time.Millisecond)
		}
		appendRecord("SAMPLE", start, end, probes)
		if i == 2 {
			appendRecord("READY", end+1, end+1, nil)
		}
	}
	last := f.records[len(f.records)-1].CompletedNS
	appendRecord("END", last+1, last+1, nil)
	return f
}
func (f fixture) raw() []byte {
	var raw bytes.Buffer
	for _, r := range f.records {
		raw.Write(wire.JSON(r))
		raw.WriteByte('\n')
	}
	return raw.Bytes()
}
func (f *fixture) reseal() {
	for i := range f.records {
		f.records[i].Sequence = i
		f.records[i].Previous = ""
		if i > 0 {
			f.records[i].Previous = f.records[i-1].Hash
		}
		f.records[i] = Seal(f.records[i], f.key)
	}
}
func TestControlledNativeWitnessPredicates(t *testing.T) {
	for _, ceiling := range []int{500, 50, 154} {
		f := makeFixture(t, ceiling)
		got, _ := Analyze(f.reg, f.raw(), &f.policy, f.pub, f.now)
		want := "PASS"
		if ceiling == 50 {
			want = "FAIL"
		}
		if got.Status != "OBSERVATIONS_CORROBORATED" || got.ApplicationVerdict != want || got.Effects != 4 || got.Recovery != 4 || got.TrustedExecutionVerdict != "INCONCLUSIVE" {
			t.Fatal(ceiling, got)
		}
	}
	// The inclusive ceiling passes exactly; one nanosecond above it is a violation.
	f := makeFixture(t, 154)
	for i := range f.records {
		if f.records[i].Type == "SAMPLE" && f.records[i].Probes[1].Response.State.Active {
			f.records[i].Probes[2].CompletedNS++
			f.records[i].CompletedNS++
		}
	}
	f.reseal()
	got, _ := Analyze(f.reg, f.raw(), &f.policy, f.pub, f.now)
	if got.ApplicationVerdict != "FAIL" || got.Violations != 4 {
		t.Fatal(got)
	}
}
func TestNativeWitnessSignatureIdentityAndSequenceAdversaries(t *testing.T) {
	for _, kind := range []string{"signature", "nonce-replay", "plan", "invocation", "session", "target", "process", "reorder", "drop", "rate", "reverse-clock", "readiness-late", "deadline-renewal", "response-status", "wrong-boot", "forged-recovery", "source-phase-order"} {
		t.Run(kind, func(t *testing.T) {
			f := makeFixture(t, 500)
			i := 5
			switch kind {
			case "signature":
				f.records[i].Signature[0] ^= 1
			case "nonce-replay":
				f.records[i].Probes[0].Nonce = f.records[3].Probes[0].Nonce
			case "plan":
				f.records[i].PlanDigest = wire.Hash("different")
			case "invocation":
				f.records[i].Invocation = wire.ID()
			case "session":
				f.records[i].Session = wire.ID()
			case "target":
				f.records[i].TargetDigest = wire.Hash("replacement")
			case "process":
				f.records[i].Process = wire.ID()
			case "reorder":
				f.records[i], f.records[i+1] = f.records[i+1], f.records[i]
			case "drop":
				f.records = append(f.records[:i], f.records[i+1:]...)
			case "rate":
				f.records[i].StartedNS = f.records[i-1].StartedNS
			case "reverse-clock":
				f.records[i].CompletedNS = f.records[i].StartedNS - 1
			case "readiness-late":
				f.records[4].Type = "SAMPLE"
				f.records[4].Probes = f.records[5].Probes
			case "deadline-renewal":
				f.records[i].Probes[1].Response.State.DeadlineNS++
			case "response-status":
				f.records[i].Probes[2].HTTPCode = 201
			case "wrong-boot":
				f.records[i].Probes[1].Response.Identity.Boot = wire.ID()
			case "forged-recovery":
				f.records[i].Probes[1].Response.State.Active = false
			case "source-phase-order":
				f.records[4].Type = "END"
			}
			// A malicious signing witness still cannot make inconsistent clocks, fixture
			// bodies or identities pass. Pure signature/hash corruption remains unsealed.
			if kind != "signature" && kind != "drop" {
				f.reseal()
			}
			got, _ := Analyze(f.reg, f.raw(), &f.policy, f.pub, f.now)
			if got.Status != "WITNESS_SIGNATURE_INVALID" && got.Status != "OBSERVATIONS_CONTRADICTORY" {
				t.Fatal(kind, got)
			}
		})
	}
}
func TestNativeExternalTrustAndKeySeparation(t *testing.T) {
	for _, kind := range []string{"absent", "unknown-key", "publisher", "engine", "scope", "routes", "registration", "expired", "revoked", "publisher-is-witness"} {
		t.Run(kind, func(t *testing.T) {
			f := makeFixture(t, 500)
			policy := &f.policy
			switch kind {
			case "absent":
				policy = nil
			case "unknown-key":
				p, _, _ := ed25519.GenerateKey(rand.Reader)
				policy.Keys[0].PublicKey = p
				policy.Keys[0].KeyID = evidence.Fingerprint(p)
			case "publisher":
				policy.Keys[0].Publisher = "another"
			case "engine":
				policy.Keys[0].Engine = "kubernetes-synthetic-witness"
			case "scope":
				policy.Keys[0].Scopes[0].Invocation = wire.ID()
			case "routes":
				policy.Keys[0].Scopes[0].Routes = []string{"proxy:/arbitrary"}
			case "registration":
				policy.Keys[0].Scopes[0].RegistrationDigest = wire.Hash("different")
			case "expired":
				policy.Keys[0].NotAfter = f.now.Format(time.RFC3339Nano)
			case "revoked":
				policy.Keys[0].Revoked = true
			case "publisher-is-witness":
				f.pub.KeyID = f.reg.KeyID
			}
			got, _ := Analyze(f.reg, f.raw(), policy, f.pub, f.now)
			if got.WitnessTrust == "TRUSTED" && got.Status != "WITNESS_IDENTITY_UNTRUSTED" {
				t.Fatal(kind, got)
			}
			if got.TrustedExecutionVerdict != "INCONCLUSIVE" {
				t.Fatal("execution trust upgraded")
			}
		})
	}
	f := makeFixture(t, 500)
	for _, key := range append(SourceKeys(f.reg.Approval.Plan), f.reg.Approval.ApplyKeyID, f.reg.Approval.CleanupKeyID) {
		copy := f.reg
		copy.KeyID = key
		copy = SignRegistration(copy, f.key)
		if copy.Validate() == nil {
			t.Fatal("authority reused as witness")
		}
	}
}
func TestNativeSignedPrefixesNeverInventRecovery(t *testing.T) {
	f := makeFixture(t, 500)
	raw := f.raw()
	last := bytes.LastIndex(raw[:len(raw)-1], []byte{'\n'})
	prefix := raw[:last+1]
	for _, b := range [][]byte{prefix, append(append([]byte{}, prefix...), []byte(`{"version":`)...)} {
		got, records := Analyze(f.reg, b, &f.policy, f.pub, f.now)
		if got.Complete || got.ApplicationVerdict == "PASS" || got.SignatureChain != "VALID" || len(records) == 0 {
			t.Fatal(got)
		}
	}
}

func TestSignedActuatorAuthorityCannotBeReboundByAnotherSignature(t *testing.T) {
	for _, kind := range []string{"grant-digest", "apply-key", "cleanup-key", "invocation", "plan", "proxy-epoch"} {
		t.Run(kind, func(t *testing.T) {
			f := makeFixture(t, 500)
			receipt := f.records[6].Probes[3].Authority
			switch kind {
			case "grant-digest":
				receipt.GrantDigest = wire.Hash("substituted")
			case "apply-key":
				receipt.ApplyKeyID = wire.ID()
			case "cleanup-key":
				receipt.CleanupKeyID = wire.ID()
			case "invocation":
				receipt.Invocation = wire.ID()
			case "plan":
				receipt.PlanDigest = wire.Hash("another plan")
			case "proxy-epoch":
				receipt.State.DeadlineNS--
			}
			receipt.Signature = ""
			receipt.Signature = wire.Sign(wire.AuthorityReceiptVersion, *receipt, f.keys["proxy"])
			f.reseal()
			got, _ := Analyze(f.reg, f.raw(), &f.policy, f.pub, f.now)
			if got.Status != "OBSERVATIONS_CONTRADICTORY" {
				t.Fatal("signed but inconsistent authority accepted", kind, got)
			}
		})
	}
}

func TestNativeRegistrationRejectsActualAuthorityKeysAndRetrospectiveStart(t *testing.T) {
	f := makeFixture(t, 500)
	for _, role := range []string{"application", "proxy", "dependency", "installer", "approver", "apply", "cleanup"} {
		keyBytes, e := hex.DecodeString(f.keys[role])
		if e != nil {
			t.Fatal(e)
		}
		key := ed25519.PrivateKey(keyBytes)
		reg := f.reg
		reg.PublicKey = key.Public().(ed25519.PublicKey)
		reg.KeyID = evidence.Fingerprint(reg.PublicKey)
		reg = SignRegistration(reg, key)
		if reg.Validate() == nil {
			t.Fatal("actual source/authority key used as witness", role)
		}
	}
	late := f.reg
	late.NotBefore = late.Approval.ApplyBefore.Format(time.RFC3339Nano)
	late.NotAfter = late.Approval.ApplyBefore.Add(20 * time.Second).Format(time.RFC3339Nano)
	late = SignRegistration(late, f.key)
	if late.Validate() == nil {
		t.Fatal("retrospective registration admitted")
	}
}

func TestNativeWitnessRejectsAmbiguousCanonicalRecordsAndPolicies(t *testing.T) {
	f := makeFixture(t, 500)
	raw := wire.JSON(f.records[0])
	for _, bad := range [][]byte{append([]byte(" "), raw...), bytes.Replace(raw, []byte(`"version":`), []byte(`"Version":`), 1), bytes.Replace(raw, []byte(`"probes":[]`), []byte(`"probes":null`), 1), bytes.Replace(raw, []byte(`"sequence":0`), []byte(`"sequence":0,"Sequence":0`), 1)} {
		var r Record
		if Decode(bad, &r) == nil {
			t.Fatal("noncanonical or ambiguous witness record admitted")
		}
	}
	policy := wire.JSON(f.policy)
	for _, bad := range [][]byte{bytes.Replace(policy, []byte(`"version":`), []byte(`"Version":`), 1), bytes.Replace(policy, []byte(`"keys":[`), []byte(`"keys":null,"Keys":[`), 1)} {
		if _, e := ReadPolicy(bad); e == nil {
			t.Fatal("ambiguous witness policy admitted")
		}
	}
}
func TestRunnerAssertionsBindReadinessAndCannotHideCancellation(t *testing.T) {
	f := makeFixture(t, 500)
	ready := f.records[4]
	base := NewAdmission(f.reg, ready)
	intent := RunnerStatement{Version: RunnerStatementVersion, Kind: "INTENT", Key: wire.Public(f.keys["apply"]), PlanDigest: f.reg.Approval.PlanDigest, Invocation: f.reg.Approval.Invocation, ApprovalDigest: f.reg.Approval.ApprovalDigest, ReadyCommitment: base.ApplyNonce, Execution: "INTENT", Candidate: "INCONCLUSIVE", Cleanup: "UNKNOWN"}
	intent = SignRunner(intent, f.keys["apply"])
	if intent.Validate(f.reg.Approval) != nil {
		t.Fatal("valid authority-holder intent denied")
	}
	admission := BindIntent(base, intent)
	if admission.ApplyNonce == base.ApplyNonce || admission.IntentDigest != wire.Hash(intent) {
		t.Fatal("Apply nonce failed to bind signed intent")
	}
	final := intent
	final.Kind = "FINAL"
	final.IntentDigest = wire.Hash(intent)
	final.JournalDigest = evidence.Hash([]byte("original complete journal"))
	final.ReportDigest = evidence.Hash([]byte("original canceled report"))
	final.Execution = "CANCELLED"
	final.Candidate = "INCONCLUSIVE"
	final.Cleanup = "COMPLETE"
	final = SignRunner(final, f.keys["apply"])
	if final.Validate(f.reg.Approval) != nil {
		t.Fatal("valid canceled assertion denied")
	}
	for _, kind := range []string{"execution", "verdict", "journal", "report", "ready", "intent", "key", "invocation"} {
		changed := final
		switch kind {
		case "execution":
			changed.Execution = "SUCCEEDED"
		case "verdict":
			changed.Candidate = "PASS"
		case "journal":
			changed.JournalDigest = evidence.Hash([]byte("reordered"))
		case "report":
			changed.ReportDigest = evidence.Hash([]byte("fabricated PASS"))
		case "ready":
			changed.ReadyCommitment = wire.ID()
		case "intent":
			changed.IntentDigest = wire.Hash("late intent")
		case "key":
			changed.Key = wire.Public(f.keys["cleanup"])
		case "invocation":
			changed.Invocation = wire.ID()
		}
		if changed.Validate(f.reg.Approval) == nil {
			t.Fatal("altered original runner assertion accepted", kind)
		}
	}
	wrong := intent
	wrong.Key = wire.Public(f.keys["cleanup"])
	wrong = SignRunner(wrong, f.keys["cleanup"])
	if wrong.Validate(f.reg.Approval) == nil {
		t.Fatal("cleanup key impersonated Apply authority holder")
	}
}

func FuzzNativeSignedJournal(f *testing.F) {
	fixture := makeFixture(f, 500)
	f.Add(fixture.raw())
	f.Add([]byte("{}\n"))
	f.Add([]byte("{"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxJournal {
			return
		}
		got, _ := Analyze(fixture.reg, raw, &fixture.policy, fixture.pub, fixture.now)
		if got.TrustedExecutionVerdict != "INCONCLUSIVE" {
			t.Fatal("untrusted execution upgrade")
		}
		var record Record
		_ = Decode(raw, &record)
	})
}
func FuzzNativeWitnessPolicy(f *testing.F) {
	f.Add([]byte(`{"version":"themis.native-observation-trust/v1alpha1","keys":[]}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ReadPolicy(b) })
}
