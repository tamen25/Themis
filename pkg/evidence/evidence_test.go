package evidence

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fixture(t testing.TB) (Manifest, map[string][]byte, ed25519.PrivateKey, Policy) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := Manifest{Source: Source{Engine: "test-engine", Mapping: "test/v1", Experiment: "synthetic", RunID: "run-1", ContractDigest: Hash([]byte("contract")), PlanDigest: Hash([]byte("plan")), Versions: []string{"test/v1"}, CandidateVerdict: "PASS", Execution: "SUCCEEDED", Cleanup: "COMPLETE", Provenance: "RETROSPECTIVE_PUBLICATION", Missing: []string{}, Unsupported: []string{}}, Publisher: Publisher{"operator", Fingerprint(pub), pub, Algorithm, Domain}, PublishedAt: "2026-10-18T00:00:00Z", Artifacts: []Artifact{{Path: "artifacts/report.json", Role: "source-report", Version: "test/v1"}}}
	p := Policy{PolicyVersion, []TrustedKey{{Publisher: "operator", KeyID: Fingerprint(pub), PublicKey: pub, Algorithm: Algorithm, Engines: []string{"test-engine"}, NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}}}
	return m, map[string][]byte{"artifacts/report.json": []byte(`{"verdict":"PASS"}`)}, key, p
}

func verifyTest(b []byte, p *Policy) (Opened, error) {
	return Verify(bytes.NewReader(b), int64(len(b)), p, time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC))
}

func TestTrustDimensionsAndDeterminism(t *testing.T) {
	m, f, k, p := fixture(t)
	a, err := Sign(m, f, k)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Sign(m, f, k)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("nondeterministic signed archive", err)
	}
	o, err := verifyTest(a, &p)
	if err != nil || o.Result.Signature != "VALID" || o.Result.PublisherTrust != "TRUSTED" || !o.Result.AuthenticatedPublisherAssertion || o.Result.SourceChecks.Status != "NOT_CHECKED" || o.Result.TrustedExecutionVerdict != "INCONCLUSIVE" {
		t.Fatalf("conflated trust dimensions: %+v %v", o.Result, err)
	}
	o, err = verifyTest(a, nil)
	if err != nil || o.Result.PublisherTrust != "UNTRUSTED" || o.Result.Signature != "VALID" || o.Result.AuthenticatedPublisherAssertion {
		t.Fatal("self trust", err)
	}
	for _, verdict := range []string{"FAIL", "INCONCLUSIVE", "NOT_RUN"} {
		m.Source.CandidateVerdict = verdict
		b, err = Sign(m, f, k)
		if err != nil {
			t.Fatal(err)
		}
		o, err = verifyTest(b, &p)
		if err != nil || o.Result.Source.CandidateVerdict != verdict || o.Result.TrustedExecutionVerdict != "INCONCLUSIVE" {
			t.Fatal("source outcome upgraded", err)
		}
	}
}

func TestTrustPolicyNegativesAndRotation(t *testing.T) {
	m, f, k, p := fixture(t)
	b, e := Sign(m, f, k)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name, reason string
		change       func(*Policy)
	}{
		{"unknown", "UNKNOWN_PUBLISHER_OR_KEY", func(p *Policy) { p.Keys[0].Publisher = "other" }},
		{"revoked", "REVOKED", func(p *Policy) { p.Keys[0].Revoked = true }},
		{"expired", "POLICY_NOT_CURRENT", func(p *Policy) { p.Keys[0].NotAfter = "2026-10-18T00:00:00Z" }},
		{"future", "POLICY_NOT_CURRENT", func(p *Policy) { p.Keys[0].NotBefore = "2026-10-19T00:00:00Z" }},
		{"scope", "ENGINE_SCOPE_DENIED", func(p *Policy) { p.Keys[0].Engines = []string{"other"} }},
		{"wrong-key", "UNKNOWN_PUBLISHER_OR_KEY", func(p *Policy) {
			pub, _, _ := ed25519.GenerateKey(rand.Reader)
			p.Keys[0].PublicKey = pub
			p.Keys[0].KeyID = Fingerprint(pub)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(p)
			var q Policy
			json.Unmarshal(raw, &q)
			tc.change(&q)
			o, e := verifyTest(b, &q)
			if e != nil || o.Result.TrustReason != tc.reason || o.Result.PublisherTrust != "UNTRUSTED" {
				t.Fatal(o.Result.TrustReason, e)
			}
		})
	}
	pub, newKey, _ := ed25519.GenerateKey(rand.Reader)
	old := p.Keys[0]
	next := old
	next.PublicKey = pub
	next.KeyID = Fingerprint(pub)
	p.Keys = []TrustedKey{next}
	if o, e := verifyTest(b, &p); e != nil || o.Result.PublisherTrust != "UNTRUSTED" {
		t.Fatal("old key implicitly trusted")
	}
	p.Keys = append(p.Keys, old)
	if o, e := verifyTest(b, &p); e != nil || o.Result.PublisherTrust != "TRUSTED" {
		t.Fatal("explicit old-key retention failed", e)
	}
	m.Publisher.PublicKey = pub
	m.Publisher.KeyID = Fingerprint(pub)
	rotated, e := Sign(m, f, newKey)
	if e != nil {
		t.Fatal(e)
	}
	if o, e := verifyTest(rotated, &p); e != nil || o.Result.PublisherTrust != "TRUSTED" {
		t.Fatal("new key failed", e)
	}
	m.Publisher.Name = "copied-name"
	copied, e := Sign(m, f, newKey)
	if e != nil {
		t.Fatal(e)
	}
	if o, e := verifyTest(copied, &p); e != nil || o.Result.PublisherTrust != "UNTRUSTED" {
		t.Fatal("copied signer identity trusted")
	}
}

func unpack(t testing.TB, b []byte) (map[string][]byte, []byte, []byte) {
	t.Helper()
	o, e := verifyTest(b, nil)
	if e != nil {
		t.Fatal(e)
	}
	z, e := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if e != nil {
		t.Fatal(e)
	}
	var mb, sb []byte
	for _, f := range z.File {
		r, e := f.Open()
		if e != nil {
			t.Fatal(e)
		}
		var v bytes.Buffer
		v.ReadFrom(r)
		r.Close()
		if f.Name == "manifest.json" {
			mb = v.Bytes()
		}
		if f.Name == "signature.json" {
			sb = v.Bytes()
		}
	}
	return o.Artifacts, mb, sb
}

func TestTamperInventoryManifestAndSignature(t *testing.T) {
	m, f, k, _ := fixture(t)
	b, e := Sign(m, f, k)
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"edit", "remove", "replace", "extra", "manifest", "signature", "algorithm", "domain"} {
		t.Run(name, func(t *testing.T) {
			files, mb, sb := unpack(t, b)
			switch name {
			case "edit", "replace":
				files["artifacts/report.json"] = []byte(`{"verdict":"FAIL"}`)
			case "remove":
				delete(files, "artifacts/report.json")
			case "extra":
				files["artifacts/extra.json"] = []byte(`{}`)
			case "manifest":
				mb = bytes.Replace(mb, []byte(`"operator"`), []byte(`"attacker"`), 1)
			case "signature":
				var s Signature
				json.Unmarshal(sb, &s)
				s.Signature[0] ^= 1
				sb = canonical(s)
			case "algorithm":
				sb = bytes.Replace(sb, []byte(`Ed25519`), []byte(`Ed25519ph`), 1)
			case "domain":
				sb = bytes.Replace(sb, []byte(Domain), []byte("other-domain"), 1)
			}
			bad, e := archiveBytes(mb, sb, files)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = verifyTest(bad, nil); e == nil {
				t.Fatal("accepted tampering")
			}
		})
	}
}

func TestUnsafeZIP(t *testing.T) {
	m, f, k, _ := fixture(t)
	b, e := Sign(m, f, k)
	if e != nil {
		t.Fatal(e)
	}
	files, mb, sb := unpack(t, b)
	for _, name := range []string{"../outside.json", "/absolute.json", `artifacts\backslash.json`, "artifacts/.hidden.json", "artifacts/caf\u00e9.json", "artifacts/report.json", "artifacts/symlink.json", "artifacts/device.json", "artifacts/compressed.json", "artifacts/huge.json"} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			w := zip.NewWriter(&buf)
			for _, n := range []string{"manifest.json", "signature.json", "artifacts/report.json"} {
				q, _ := w.Create(n)
				v := files[n]
				if n == "manifest.json" {
					v = mb
				}
				if n == "signature.json" {
					v = sb
				}
				q.Write(v)
			}
			h := zip.FileHeader{Name: name, Method: zip.Store}
			h.SetMode(0444)
			switch name {
			case "artifacts/symlink.json":
				h.SetMode(os.ModeSymlink | 0777)
			case "artifacts/device.json":
				h.SetMode(os.ModeDevice | 0600)
			case "artifacts/compressed.json":
				h.Method = zip.Deflate
			}
			q, e := w.CreateHeader(&h)
			if e != nil {
				t.Fatal(e)
			}
			if name == "artifacts/huge.json" {
				q.Write(bytes.Repeat([]byte{'x'}, MaxFile+1))
			} else {
				q.Write([]byte(`{}`))
			}
			w.Close()
			if _, e = verifyTest(buf.Bytes(), nil); e == nil {
				t.Fatal("unsafe ZIP accepted")
			}
		})
	}
	for _, bad := range [][]byte{append(append([]byte{}, b...), 0), append([]byte("prefix"), b...), b[:len(b)/2]} {
		if _, e = verifyTest(bad, nil); e == nil {
			t.Fatal("noncanonical/truncated ZIP accepted")
		}
	}
	if _, e = Verify(bytes.NewReader(nil), MaxArchive+1, nil, time.Now()); e == nil {
		t.Fatal("archive budget ignored")
	}
}

func TestStrictEnvelopeJSONAndPolicy(t *testing.T) {
	for _, b := range []string{`{"version":"x","Version":"y"}`, `{"version":"x","version":"y"}`, `{"version":null}`, `{} {}`, `{"unknown":1}`} {
		var m Manifest
		if e := decodeCanonical([]byte(b), &m); e == nil {
			t.Fatal("ambiguous manifest accepted", b)
		}
	}
	m, f, k, p := fixture(t)
	m.Publisher.Algorithm = "Ed25519ph"
	if _, e := Sign(m, f, k); e == nil {
		t.Fatal("algorithm substitution")
	}
	p.Keys = append(p.Keys, p.Keys[0])
	if p.Validate() == nil {
		t.Fatal("duplicate trust roots")
	}
	_, _, _, p = fixture(t)
	raw := canonical(p)
	if _, e := ReadPolicy(raw); e != nil {
		t.Fatal(e)
	}
	raw = bytes.Replace(raw, []byte(`"revoked":false`), []byte(`"Revoked":false`), 1)
	if _, e := ReadPolicy(raw); e == nil {
		t.Fatal("case-mismatched policy")
	}
}

func TestPublicationRaceInterruptionAndExclusiveOutput(t *testing.T) {
	m, files, k, _ := fixture(t)
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "artifacts"), 0700)
	path := filepath.Join(dir, "artifacts", "report.json")
	os.WriteFile(path, files["artifacts/report.json"], 0600)
	if _, e := snapshot(dir, m.Artifacts, func() { os.WriteFile(path, []byte(`{"verdict":"FAIL"}`), 0600) }); e == nil {
		t.Fatal("source race ignored")
	}
	os.WriteFile(path, files["artifacts/report.json"], 0600)
	out := filepath.Join(t.TempDir(), "bundle.zip")
	if e := Publish(dir, out, m, k); e != nil {
		t.Fatal(e)
	}
	old, _ := os.ReadFile(out)
	if e := Publish(dir, out, m, k); e == nil {
		t.Fatal("overwrote publication")
	}
	after, _ := os.ReadFile(out)
	if !bytes.Equal(old, after) {
		t.Fatal("existing publication changed")
	}
	if e := Publish(dir, filepath.Join(dir, "bundle.zip"), m, k); e == nil {
		t.Fatal("historical source write allowed")
	}
	partial := filepath.Join(t.TempDir(), "bundle.zip")
	badKey := ed25519.NewKeyFromSeed(make([]byte, 32))
	if e := Publish(dir, partial, m, badKey); e == nil {
		t.Fatal("unexpected signing success")
	}
	if _, e := os.Stat(partial); !os.IsNotExist(e) {
		t.Fatal("failed publication left final artifact")
	}
	for _, secret := range []string{`{"password":"sensitive"}`, `{"invocationPrivateKey":"sensitive"}`, `{"nested":{"replicationPassword":"sensitive"}}`} {
		if e := CheckPublicArtifact("artifacts/report.json", []byte(secret)); e == nil {
			t.Fatal("operational secret admitted")
		}
	}
}

func FuzzManifest(f *testing.F) {
	m, files, k, _ := fixture(f)
	b, e := Sign(m, files, k)
	if e != nil {
		f.Fatal(e)
	}
	_, mb, _ := unpack(f, b)
	f.Add(mb)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxManifest {
			return
		}
		var m Manifest
		if decodeCanonical(b, &m) == nil {
			_ = m.validate()
		}
	})
}
func FuzzArchive(f *testing.F) {
	m, files, k, _ := fixture(f)
	b, e := Sign(m, files, k)
	if e != nil {
		f.Fatal(e)
	}
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxArchive {
			return
		}
		o, _ := verifyTest(b, nil)
		if o.Result.PublisherTrust == "TRUSTED" || o.Result.TrustedExecutionVerdict != "INCONCLUSIVE" {
			t.Fatal("untrusted input created authority")
		}
	})
}
func FuzzSignature(f *testing.F) {
	m, files, k, _ := fixture(f)
	b, e := Sign(m, files, k)
	if e != nil {
		f.Fatal(e)
	}
	_, _, sb := unpack(f, b)
	f.Add(sb)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxSignature {
			return
		}
		var s Signature
		_ = decodeCanonical(b, &s)
	})
}
