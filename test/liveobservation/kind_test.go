package liveobservation_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/kubeexperiment"
	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/pkg/evidence"
	"github.com/tamen25/themis/pkg/evidenceverify"
	obs "github.com/tamen25/themis/pkg/liveobservation"
)

type command struct {
	Label     string   `json:"label"`
	Program   string   `json:"program"`
	Arguments []string `json:"arguments"`
	Exit      int      `json:"exit"`
	Stdout    string   `json:"stdout"`
	Stderr    string   `json:"stderr"`
	Millis    int64    `json:"millis"`
}
type harness struct {
	t                                                                         *testing.T
	ctx                                                                       context.Context
	repository, state, witnessState, output, private, runner, witness, keyDir string
	commands                                                                  []command
	evidenceBinary, publisherDir, publisherPolicy                             string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	if os.Getenv("THEMIS_LIVE_WITNESS") != "1" {
		t.Skip("NOT EXECUTED: explicit new owned T4.1 Kind witness opt-in required")
	}
	repository, e := filepath.Abs(filepath.Join("..", ".."))
	if e != nil {
		t.Fatal(e)
	}
	h := &harness{t: t, repository: repository, state: os.Getenv("THEMIS_WITNESS_RUNNER_STATE"), witnessState: os.Getenv("THEMIS_WITNESS_STATE"), runner: os.Getenv("THEMIS_WITNESS_RUNNER_BINARY"), witness: os.Getenv("THEMIS_WITNESS_BINARY")}
	if h.state == "" || h.witnessState == "" || h.runner == "" || h.witness == "" {
		t.Fatal("explicit owned state and binaries required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	h.ctx = ctx
	var owner kubeexperiment.Ownership
	if localstate.Read(filepath.Join(h.state, "execution-owner.json"), &owner) != nil || owner.Version != "themis.kind-ownership/t4.1-v1" {
		t.Fatal("fresh T4.1 installer ownership required")
	}
	cluster, e := kubeexperiment.Open(ctx, h.state)
	if e != nil || cluster.CheckEnvironment(ctx) != nil {
		t.Fatal("original owned cluster identity unavailable", e)
	}
	h.private, e = localstate.CreateDirectory(filepath.Join(h.witnessState, "test-"+localstate.RandomID()[:12]))
	if e != nil {
		t.Fatal(e)
	}
	h.output = filepath.Join(os.Getenv("THEMIS_WITNESS_EVIDENCE"), t.Name())
	if e = os.MkdirAll(h.output, 0700); e != nil {
		t.Fatal(e)
	}
	h.keyDir = filepath.Join(h.private, "key")
	t.Cleanup(func() { h.save("commands.json", h.commands) })
	h.witnessCall("witness-keygen", 0, "keygen", "--key-dir", h.keyDir, "--witness", "independent-kind-witness")
	h.evidenceBinary = os.Getenv("THEMIS_WITNESS_EVIDENCE_BINARY")
	if h.evidenceBinary == "" {
		t.Fatal("explicit evidence CLI binary required")
	}
	h.publisherDir = filepath.Join(h.private, "publisher")
	var publisher evidence.Publisher
	if e = json.Unmarshal(h.evidenceCall("publisher-keygen", 0, "keygen", "--key-dir", h.publisherDir, "--publisher", "kind-review-publisher"), &publisher); e != nil {
		t.Fatal(e)
	}
	policy := evidence.Policy{Version: evidence.PolicyVersion, Keys: []evidence.TrustedKey{{Publisher: publisher.Name, KeyID: publisher.KeyID, PublicKey: publisher.PublicKey, Algorithm: evidence.Algorithm, Engines: []string{obs.Engine}, NotBefore: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), NotAfter: time.Now().Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339)}}}
	h.publisherPolicy = filepath.Join(h.output, "publisher-policy.json")
	h.save("publisher-policy.json", policy)
	var binaries []map[string]any
	for _, path := range []string{h.runner, h.witness, h.evidenceBinary} {
		file, e := os.Open(path)
		if e != nil {
			t.Fatal(e)
		}
		hash := sha256.New()
		n, e := io.Copy(hash, file)
		file.Close()
		if e != nil {
			t.Fatal(e)
		}
		binaries = append(binaries, map[string]any{"program": path, "bytes": n, "sha256": hex.EncodeToString(hash.Sum(nil))})
	}
	h.save("binary-identities.json", binaries)
	return h
}
func (h *harness) evidenceCall(label string, want int, args ...string) []byte {
	h.t.Helper()
	binary := h.runner
	h.runner = h.evidenceBinary
	defer func() { h.runner = binary }()
	return h.call(label, want, args...)
}
func (h *harness) witnessCall(label string, want int, args ...string) []byte {
	h.t.Helper()
	binary := h.runner
	h.runner = h.witness
	defer func() { h.runner = binary }()
	return h.call(label, want, args...)
}
func (h *harness) save(name string, v any) {
	h.t.Helper()
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		h.t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(h.output, name), append(b, '\n'), 0600); e != nil {
		h.t.Fatal(e)
	}
}
func (h *harness) call(label string, want int, args ...string) []byte {
	h.t.Helper()
	start := time.Now()
	cmd := exec.CommandContext(h.ctx, h.runner, args...)
	cmd.Dir = h.repository
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	e := cmd.Run()
	code := exitCode(e)
	h.commands = append(h.commands, command{label, h.runner, args, code, stdout.String(), stderr.String(), time.Since(start).Milliseconds()})
	if code != want {
		h.t.Fatalf("%s exit=%d want=%d: %s", label, code, want, stderr.String())
	}
	return stdout.Bytes()
}
func exitCode(e error) int {
	if e == nil {
		return 0
	}
	var child *exec.ExitError
	if errors.As(e, &child) {
		return child.ExitCode()
	}
	return -1
}
func (h *harness) experiment(label, scenario string, maxApp int, killWitness bool) (kubeexperiment.CoordinationRecord, obs.Registration, []byte) {
	h.t.Helper()
	directory := filepath.Join(h.state, "witness-"+label+"-"+localstate.RandomID()[:12])
	b := h.call(label+"-prepare", 0, "coordinate", "prepare", "--state", h.state, "--directory", directory, "--scenario", scenario)
	record, e := kubeexperiment.DecodeCoordinationRecord(b)
	if e != nil {
		h.t.Fatal(e)
	}
	b = h.call(label+"-approve", 0, "coordinate", "approve", "--directory", directory, "--approve-digest", record.Proposal.PlanDigest)
	record, e = kubeexperiment.DecodeCoordinationRecord(b)
	if e != nil {
		h.t.Fatal(e)
	}
	var a kubefault.Authorization
	if e = localstate.Read(filepath.Join(directory, "authorization.json"), &a); e != nil {
		h.t.Fatal(e)
	}
	runnerKey, _ := hex.DecodeString(a.Grant.InvocationKey)
	cleanupKey, _ := hex.DecodeString(a.Grant.CleanupKey)
	session := filepath.Join(h.private, label)
	h.save(label+"-approved-public-record.json", record)
	var reg obs.Registration
	regBytes := h.witnessCall(label+"-explicit-registration", 0, "register", "--record", filepath.Join(h.output, label+"-approved-public-record.json"), "--key-dir", h.keyDir, "--session", session, "--approve-digest", record.Proposal.PlanDigest, "--runner-key-id", evidence.Hash(runnerKey), "--cleanup-key-id", evidence.Hash(cleanupKey), "--max-application-ms", strconv.Itoa(maxApp))
	if e = json.Unmarshal(regBytes, &reg); e != nil {
		h.t.Fatal(e)
	}
	h.save(label+"-registration.json", reg)
	cmd := exec.CommandContext(h.ctx, h.witness, "observe", "--state", h.witnessState, "--session", session, "--key-dir", h.keyDir)
	cmd.Dir = h.repository
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	started := time.Now()
	if e = cmd.Start(); e != nil {
		h.t.Fatal(e)
	}
	waited := false
	h.t.Cleanup(func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	ready := false
	for limit := time.Now().Add(6 * time.Second); time.Now().Before(limit); time.Sleep(10 * time.Millisecond) {
		var r obs.Record
		if localstate.Read(filepath.Join(session, "ready.json"), &r) == nil && r.Type == "READY" && r.RegistrationDigest == obs.RegistrationDigest(reg) && obs.VerifyRecord(r, reg.PublicKey) {
			ready = true
			break
		}
	}
	if !ready {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		waited = true
		h.t.Fatalf("witness never registered healthy baseline: %s %s", stdout.String(), stderr.String())
	}
	// A handle to this exact child process is the only process termination used.
	if killWitness {
		go func() {
			for limit := time.Now().Add(3 * time.Second); time.Now().Before(limit); time.Sleep(5 * time.Millisecond) {
				raw, _ := os.ReadFile(filepath.Join(session, "observations.jsonl"))
				if bytes.Contains(raw, []byte(`"phase":"intervention"`)) {
					_ = cmd.Process.Kill()
					return
				}
			}
		}()
	}
	want := 0
	switch scenario {
	case "buggy":
		want = 2
	case "noop":
		want = 3
	case "cleanup-denied":
		want = 7
	}
	resultBytes := h.call(label+"-run", want, "coordinate", "start", "--directory", directory)
	result, e := kubeexperiment.DecodeCoordinationRecord(resultBytes)
	if e != nil || result.LiveResult == nil {
		h.t.Fatal("actual runner result unavailable", e)
	}
	e = cmd.Wait()
	waited = true
	code := exitCode(e)
	h.commands = append(h.commands, command{label + "-witness", h.witness, cmd.Args[1:], code, stdout.String(), stderr.String(), time.Since(started).Milliseconds()})
	if !killWitness && code != 0 && code != 8 {
		h.t.Fatalf("witness failed: exit=%d %s %s", code, stdout.String(), stderr.String())
	}
	if killWitness && code == 0 {
		h.t.Fatal("witness interruption did not kill a live process")
	}
	raw, e := os.ReadFile(filepath.Join(session, "observations.jsonl"))
	if e != nil {
		h.t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(h.output, label+"-witness.jsonl"), raw, 0600); e != nil {
		h.t.Fatal(e)
	}
	policy := obs.Policy{Version: obs.PolicyVersion, Keys: []obs.TrustedWitness{{Witness: reg.Witness, KeyID: reg.KeyID, PublicKey: reg.PublicKey, Algorithm: evidence.Algorithm, Source: obs.Engine, Scopes: []obs.Scope{{RunID: reg.Plan.RunUID, PlanDigest: reg.Plan.Digest(), InvocationID: reg.InvocationID, Session: reg.Session}}, NotBefore: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), NotAfter: time.Now().Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339)}}}
	finding, _ := obs.Analyze(reg, raw, &policy, time.Now())
	h.save(label+"-finding.json", finding)
	h.save(label+"-witness-policy.json", policy)
	h.save(label+"-coordination.json", result)
	events, e := os.ReadFile(filepath.Join(directory, filepath.FromSlash(result.References.RunDirectory), "events.jsonl"))
	if e != nil {
		h.t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(h.output, label+"-runner.jsonl"), events, 0600); e != nil {
		h.t.Fatal(e)
	}
	public := filepath.Join(h.output, label+"-public")
	h.evidenceCall(label+"-public-export", 0, "export", "--engine", obs.Engine, "--record", filepath.Join(h.output, label+"-coordination.json"), "--journal", filepath.Join(h.output, label+"-runner.jsonl"), "--witness-session", session, "--out", public)
	bundle := filepath.Join(h.output, label+".zip")
	h.evidenceCall(label+"-publisher-sign", 0, "bundle", "--engine", obs.Engine, "--source", public, "--key-dir", h.publisherDir, "--publisher", "kind-review-publisher", "--out", bundle)
	verifyExit := 0
	if killWitness || scenario == "noop" || scenario == "cleanup-denied" {
		verifyExit = 8
	}
	verified := h.evidenceCall(label+"-independent-bundle-verify", verifyExit, "verify", "--bundle", bundle, "--trust-policy", h.publisherPolicy, "--witness-policy", filepath.Join(h.output, label+"-witness-policy.json"))
	var verification evidenceverify.ObservedResult
	if json.Unmarshal(verified, &verification) != nil || verification.Evidence.Signature != "VALID" || verification.Evidence.PublisherTrust != "TRUSTED" || verification.ObservationCorroboration.WitnessTrust != "TRUSTED" || verification.Evidence.TrustedExecutionVerdict != "INCONCLUSIVE" || verification.Evidence.ExecutionAttestation != "NOT_INDEPENDENTLY_ATTESTED" {
		h.t.Fatal("bundle trust distinctions failed", string(verified))
	}
	h.save(label+"-bundle-verification.json", verification)
	if label == "A-healthy" {
		h.witnessCall("A-session-resumption-denied", 3, "observe", "--state", h.witnessState, "--session", session, "--key-dir", h.keyDir)
		after, e := os.ReadFile(filepath.Join(session, "observations.jsonl"))
		if e != nil || !bytes.Equal(raw, after) {
			h.t.Fatal("denied resumption changed historical witness bytes")
		}
	}
	if killWitness {
		if finding.Complete || finding.Status != "OBSERVATIONS_INCOMPLETE" || result.LiveResult.Cleanup != "COMPLETE" {
			h.t.Fatal("dead witness affected cleanup or gained completeness", finding)
		}
	} else if scenario == "noop" {
		if finding.Status == "OBSERVED_AND_CORRELATED" || finding.ApplicationVerdict == "PASS" {
			h.t.Fatal("no-op corroborated", finding)
		}
	} else if scenario != "cleanup-denied" && finding.Status != "OBSERVED_AND_CORRELATED" {
		h.t.Fatal("real signed correlation incomplete", finding)
	}
	if scenario == "buggy" && (finding.ApplicationFailures < 1 || finding.TimingFailures < 1 || result.LiveResult.Verdict != "FAIL") {
		h.t.Fatal("real application failure/timing violation missing", finding)
	}
	if scenario == "cleanup-denied" {
		before := append([]byte{}, events...)
		time.Sleep(3 * time.Second)
		h.call(label+"-expiry-reconcile", 0, "coordinate", "reconcile", "--directory", directory)
		after, _ := os.ReadFile(filepath.Join(directory, filepath.FromSlash(result.References.RunDirectory), "events.jsonl"))
		if !bytes.Equal(before, after) || result.LiveResult.Execution != "CLEANUP_PENDING" {
			h.t.Fatal("later cleanup erased historical uncertainty")
		}
	}
	h.t.Logf("REAL KIND %s source=%s witness=%s effect=%d baseline=%d active=%d recovery=%d cleanup=%s", label, result.LiveResult.Verdict, finding.Status, finding.EffectSamples, finding.Baseline, finding.Intervention, finding.Recovery, result.LiveResult.Cleanup)
	return result, reg, raw
}
func TestOwnedKindWitnessedOutcomes(t *testing.T) {
	h := newHarness(t)
	h.experiment("A-healthy", "healthy", 150, false)
	h.experiment("B-fail", "buggy", 50, false)
	h.experiment("C-noop", "noop", 150, false)
	h.experiment("D-witness-death", "healthy", 150, true)
	h.experiment("F-cleanup-pending", "cleanup-denied", 150, false)
}
