package liveobservation_test

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/evidencesource"
	"github.com/tamen25/themis/internal/kubeexperiment"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/pkg/evidence"
	"github.com/tamen25/themis/pkg/evidenceverify"
	obs "github.com/tamen25/themis/pkg/liveobservation"
)

func TestOwnedKindWitnessRunnerDisagreement(t *testing.T) {
	h := newHarness(t)
	h.experiment("E-disagreement", "healthy", 150, false)
	bundlePath := filepath.Join(h.output, "E-disagreement.zip")
	archive, e := os.Open(bundlePath)
	if e != nil {
		t.Fatal(e)
	}
	defer archive.Close()
	info, _ := archive.Stat()
	opened, e := evidenceverify.Verify(archive, info.Size(), nil, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	// Controlled adversarial PUBLIC copy only. The actual runner and its saved
	// history are unchanged; no witness/fixture signature is forged or rewritten.
	var report kubeexperiment.Report
	if json.Unmarshal(opened.Artifacts["artifacts/kubernetes-report.json"], &report) != nil {
		t.Fatal("public report")
	}
	report.Observations[3].Phase = "recovery"
	opened.Artifacts["artifacts/kubernetes-report.json"], e = json.Marshal(report)
	if e != nil {
		t.Fatal(e)
	}
	var key struct {
		Version    string `json:"version"`
		Publisher  string `json:"publisher"`
		PrivateKey []byte `json:"privateKey"`
	}
	if e = localstate.Read(filepath.Join(h.publisherDir, "signer-key.json"), &key); e != nil {
		t.Fatal(e)
	}
	malicious, e := evidence.Sign(opened.Manifest, opened.Artifacts, ed25519.PrivateKey(key.PrivateKey))
	if e != nil {
		t.Fatal(e)
	}
	badPath := filepath.Join(h.output, "E-controlled-phase-disagreement.zip")
	if e = evidence.PublishBytes(badPath, malicious); e != nil {
		t.Fatal(e)
	}
	verified := h.evidenceCall("E-independent-disagreement-verification", 9, "verify", "--bundle", badPath, "--trust-policy", h.publisherPolicy, "--witness-policy", filepath.Join(h.output, "E-disagreement-witness-policy.json"))
	var result evidenceverify.ObservedResult
	if json.Unmarshal(verified, &result) != nil || result.Evidence.PublisherTrust != "TRUSTED" || result.Evidence.Signature != "VALID" || result.ObservationCorroboration.Status != "OBSERVATIONS_CONTRADICTORY" || result.ObservationCorroboration.WitnessTrust != "TRUSTED" || result.ObservationCorroboration.SignatureChain != "VALID" || result.Evidence.TrustedExecutionVerdict != "INCONCLUSIVE" {
		t.Fatal("signed disagreement escaped detection", string(verified))
	}
	h.save("E-controlled-disagreement-verification.json", result)
	// Keep explicit expected mapping metadata in the evidence manifest.
	if len(evidencesource.Inventory(obs.Engine)) != 5 {
		t.Fatal("witness artifact inventory")
	}
	t.Log("REAL KIND samples followed by controlled unsigned public report phase change: publisher and witness signatures valid, correlation CONTRADICTORY; original history unchanged")
}
