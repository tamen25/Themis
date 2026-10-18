package nativewitness_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/evidencesource"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/pkg/evidence"
	"github.com/tamen25/themis/pkg/evidenceverify"
	obs "github.com/tamen25/themis/pkg/nativeobservation"
)

func (h *harness) adversePolicies(label string, p prepared, bundle string) {
	h.t.Helper()
	raw, e := os.ReadFile(p.policy)
	if e != nil {
		h.t.Fatal(e)
	}
	for _, kind := range []string{"absent", "unknown", "revoked", "expired", "wrong-invocation", "wrong-session", "wrong-boot-scope", "wrong-publisher"} {
		args := []string{"verify", "--bundle", bundle, "--trust-policy", h.publisherPolicy}
		if kind != "absent" {
			var policy obs.Policy
			if json.Unmarshal(raw, &policy) != nil {
				h.t.Fatal("policy")
			}
			switch kind {
			case "unknown":
				policy.Keys[0].Witness = "another-witness"
			case "revoked":
				policy.Keys[0].Revoked = true
			case "expired":
				policy.Keys[0].NotAfter = time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
			case "wrong-invocation":
				policy.Keys[0].Scopes[0].Invocation = string(bytes.Repeat([]byte{'a'}, 64))
			case "wrong-session":
				policy.Keys[0].Scopes[0].Session = string(bytes.Repeat([]byte{'b'}, 64))
			case "wrong-boot-scope":
				policy.Keys[0].Scopes[0].TargetDigest = "sha256:" + string(bytes.Repeat([]byte{'c'}, 64))
			case "wrong-publisher":
				policy.Keys[0].Publisher = "another-publisher"
			}
			path := h.save(label+"-policy-"+kind+".json", policy)
			args = append(args, "--witness-policy", path)
		}
		h.call(label+"-external-trust-denial-"+kind, "themis-evidence", 5, args...)
	}
}

// A malicious publisher can bypass the normal curated-source checks and sign a
// fabricated public claim. This operates on actual B evidence; original witness
// records, signatures, fixture receipts and private source history stay unchanged.
func (h *harness) fabricatedSource(p prepared, bundle string) {
	h.t.Helper()
	b, e := os.ReadFile(bundle)
	if e != nil {
		h.t.Fatal(e)
	}
	var policy evidence.Policy
	raw, e := os.ReadFile(h.publisherPolicy)
	if e != nil || json.Unmarshal(raw, &policy) != nil {
		h.t.Fatal("publisher policy")
	}
	original, e := evidence.Verify(bytes.NewReader(b), int64(len(b)), &policy, time.Now())
	if e != nil {
		h.t.Fatal(e)
	}
	files := map[string][]byte{}
	for name, data := range original.Artifacts {
		files[name] = append([]byte{}, data...)
	}
	var result evidencesource.NativeResult
	if json.Unmarshal(files["artifacts/native-result.json"], &result) != nil || result.Report == nil || result.Report.Verdict != "FAIL" {
		h.t.Fatal("actual B source is not a measured FAIL")
	}
	result.Report.Verdict = "PASS"
	files["artifacts/native-result.json"], _ = json.Marshal(result)
	export := filepath.Join(h.public, "H-fabricated-public-export")
	if os.MkdirAll(filepath.Join(export, "artifacts"), 0700) != nil {
		h.t.Fatal("new public adversarial export")
	}
	for name, data := range files {
		if os.WriteFile(filepath.Join(export, filepath.FromSlash(name)), data, 0600) != nil {
			h.t.Fatal("public adversarial write")
		}
	}
	h.call("H-normal-publisher-refuses-fabricated-source", "themis-evidence", 6, "bundle", "--engine", obs.Engine, "--source", export, "--out", filepath.Join(h.public, "H-refused.zip"), "--key-dir", h.publisherDir, "--publisher", h.publisher.Name)
	var signer struct {
		Version    string `json:"version"`
		Publisher  string `json:"publisher"`
		PrivateKey []byte `json:"privateKey"`
	}
	if localstate.Read(filepath.Join(h.publisherDir, "signer-key.json"), &signer) != nil {
		h.t.Fatal("test publisher key unavailable")
	}
	manifest := original.Manifest
	manifest.Source.CandidateVerdict = "PASS"
	manifest.PublishedAt = time.Now().UTC().Format(time.RFC3339)
	forged, e := evidence.Sign(manifest, files, ed25519.PrivateKey(signer.PrivateKey))
	if e != nil {
		h.t.Fatal(e)
	}
	path := filepath.Join(h.public, "H-publisher-signed-fabricated-source.zip")
	if e = os.WriteFile(path, forged, 0600); e != nil {
		h.t.Fatal(e)
	}
	raw = h.call("H-offline-detects-valid-signed-fabrication", "themis-evidence", 9, "verify", "--bundle", path, "--trust-policy", h.publisherPolicy, "--witness-policy", p.policy)
	var check evidenceverify.NativeObservedResult
	if json.Unmarshal(raw, &check) != nil || check.Evidence.Signature != "VALID" || check.Evidence.ArtifactIntegrity != "VALID" || check.Evidence.PublisherTrust != "TRUSTED" || check.NativeObservationCorroboration.SignatureChain != "VALID" || check.NativeObservationCorroboration.WitnessTrust != "TRUSTED" || check.NativeObservationCorroboration.Status != "OBSERVATIONS_CONTRADICTORY" || check.Evidence.TrustedExecutionVerdict != "INCONCLUSIVE" {
		h.t.Fatal("publisher signature authenticated fabricated infrastructure result", check)
	}
	if !bytes.Equal(files["artifacts/native-witness-journal.json"], original.Artifacts["artifacts/native-witness-journal.json"]) {
		h.t.Fatal("adversary changed witness evidence")
	}
	h.save("H-contradiction-verification.json", check)
	h.t.Log("REAL PUBLICATION actual B witness signatures retained; new trusted publisher signature over fabricated source PASS rejected as contradiction")
}

func (h *harness) denyCopiedSession(label string, p prepared) {
	h.t.Helper()
	copyDir, e := localstate.CreateDirectory(filepath.Join(h.private, "copied-session-"+p.registration.Session[:12]))
	if e != nil {
		h.t.Fatal(e)
	}
	if e = localstate.WriteNew(filepath.Join(copyDir, "registration.json"), p.registration); e != nil {
		h.t.Fatal(e)
	}
	h.call(label+"-copied-session-cannot-restart", "themis-native-witness", 6, "observe", "--state", filepath.Join(h.state, "witness"), "--session", copyDir, "--key-dir", p.keyDir)
	if _, e = os.Stat(filepath.Join(copyDir, "observations.jsonl")); !os.IsNotExist(e) {
		h.t.Fatal("reused session created another signed observation history")
	}
}

func TestOwnedKindSignedWitnessCancellationPreservesSource(t *testing.T) {
	h := newHarness(t)
	p := h.prepare("cancel", "delay", 500)
	runner := h.runner("cancel-original-runner", p)
	conn := h.proxy()
	h.active(p, conn)
	h.effect(p, 3)
	h.call("cancel-independent-stop", "themis-dependency", 0, "cancel", "--state", filepath.Join(h.state, "runner"), "--directory", p.directory)
	raw, code := h.wait(runner)
	if code != 9 {
		t.Fatal("cancellation did not remain canceled", code, string(raw))
	}
	_, _ = h.wait(p.observer)
	_, _ = h.wait(p.witness)
	check, _ := h.publish("cancel", p, "", 8)
	if check.Evidence.Source.Execution != "CANCELLED" || check.Evidence.Source.CandidateVerdict != "INCONCLUSIVE" || check.NativeObservationCorroboration.Status != "OBSERVATIONS_INCOMPLETE" {
		t.Fatal("signed healthy recovery upgraded canceled source", check)
	}
	t.Log("REAL KIND canceled original execution remains INCONCLUSIVE despite independently signed effect/recovery")
}
