package nativewitness_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	adapter "github.com/tamen25/themis/internal/dependencyexperiment"
	wire "github.com/tamen25/themis/internal/dependencyhttp"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/pkg/evidence"
	"github.com/tamen25/themis/pkg/evidenceverify"
	obs "github.com/tamen25/themis/pkg/nativeobservation"
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
type process struct {
	cmd            *exec.Cmd
	stdout, stderr bytes.Buffer
	program, label string
	args           []string
	started        time.Time
	waited         bool
}
type harness struct {
	t                                                                *testing.T
	state, repo, bin, public, private, publisherDir, publisherPolicy string
	publisher                                                        evidence.Publisher
	commands                                                         []command
}
type prepared struct {
	directory, observations, session, policy, keyDir string
	plan                                             wire.Plan
	registration                                     obs.Registration
	authorization                                    wire.Authorization
	observer, witness                                *process
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	if os.Getenv("THEMIS_NATIVE_WITNESS") != "1" {
		t.Skip("NOT EXECUTED: explicit fresh owned native witness Kind required")
	}
	h := &harness{t: t, state: os.Getenv("THEMIS_NATIVE_WITNESS_STATE"), bin: os.Getenv("THEMIS_NATIVE_WITNESS_BIN")}
	evidenceDir := os.Getenv("THEMIS_NATIVE_WITNESS_EVIDENCE")
	if h.state == "" || h.bin == "" || evidenceDir == "" {
		t.Fatal("explicit newly owned state/binaries/evidence required")
	}
	h.repo = filepath.Dir(filepath.Dir(h.state))
	h.public = filepath.Join(evidenceDir, t.Name())
	if e := os.MkdirAll(h.public, 0700); e != nil {
		t.Fatal(e)
	}
	var e error
	h.private, e = localstate.CreateDirectory(filepath.Join(h.state, "t43-test-"+wire.ID()[:12]))
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, e = adapter.Open(ctx, filepath.Join(h.state, "witness"), "witness"); e != nil {
		t.Fatal("dedicated witness principal denied", e)
	}
	for _, binary := range []string{"themis-dependency", "themis-native-witness", "themis-evidence"} {
		path := h.binary(binary)
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(b)
		h.save(binary+"-binary.json", struct{ Path, SHA256 string }{path, hex.EncodeToString(sum[:])})
	}
	h.publisherDir = filepath.Join(h.private, "publisher-key")
	raw := h.call("publisher-keygen", "themis-evidence", 0, "keygen", "--key-dir", h.publisherDir, "--publisher", "native-t43-publisher")
	if json.Unmarshal(raw, &h.publisher) != nil {
		t.Fatal("publisher identity")
	}
	now := time.Now().UTC()
	policy := evidence.Policy{Version: evidence.PolicyVersion, Keys: []evidence.TrustedKey{{Publisher: h.publisher.Name, KeyID: h.publisher.KeyID, PublicKey: h.publisher.PublicKey, Algorithm: evidence.Algorithm, Engines: []string{obs.Engine}, NotBefore: now.Add(-time.Hour).Format(time.RFC3339), NotAfter: now.Add(24 * time.Hour).Format(time.RFC3339)}}}
	h.publisherPolicy = h.save("publisher-policy.json", policy)
	return h
}
func (h *harness) binary(name string) string {
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(h.bin, name)
}
func (h *harness) save(name string, v any) string {
	h.t.Helper()
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		h.t.Fatal(e)
	}
	path := filepath.Join(h.public, name)
	if e = os.WriteFile(path, append(b, '\n'), 0600); e != nil {
		h.t.Fatal(e)
	}
	return path
}
func (h *harness) start(label, binary string, args ...string) *process {
	h.t.Helper()
	p := &process{program: h.binary(binary), label: label, args: args, started: time.Now()}
	p.cmd = exec.Command(p.program, args...)
	p.cmd.Env = append(os.Environ(), "DEBUG=", "GOMAXPROCS=4")
	p.cmd.Stdout = &p.stdout
	p.cmd.Stderr = &p.stderr
	if e := p.cmd.Start(); e != nil {
		h.t.Fatal(e)
	}
	h.t.Cleanup(func() {
		if !p.waited {
			_ = p.cmd.Process.Kill()
			_, _ = h.wait(p)
		}
	})
	return p
}
func (h *harness) wait(p *process) ([]byte, int) {
	h.t.Helper()
	if p.waited {
		h.t.Fatal("child waited twice")
	}
	p.waited = true
	e := p.cmd.Wait()
	code := 0
	if e != nil {
		code = p.cmd.ProcessState.ExitCode()
	}
	h.commands = append(h.commands, command{p.label, p.program, p.args, code, p.stdout.String(), p.stderr.String(), time.Since(p.started).Milliseconds()})
	h.save("commands.json", h.commands)
	return p.stdout.Bytes(), code
}
func (h *harness) call(label, binary string, want int, args ...string) []byte {
	h.t.Helper()
	p := h.start(label, binary, args...)
	raw, code := h.wait(p)
	if code != want {
		h.t.Fatalf("%s actual child exit %d wanted %d; full output in %s", label, code, want, h.public)
	}
	return raw
}
func (h *harness) ready(path string) {
	h.t.Helper()
	for start := time.Now(); time.Since(start) < 5*time.Second; {
		if _, e := os.Stat(path); e == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.t.Fatal("actual independent observer/witness readiness missing", path)
}
func (h *harness) prepare(label, scenario string, ceiling int) prepared {
	h.t.Helper()
	base, e := localstate.CreateDirectory(filepath.Join(h.private, "run-"+wire.ID()[:12]))
	if e != nil {
		h.t.Fatal(e)
	}
	p := prepared{directory: filepath.Join(base, "runner"), observations: filepath.Join(base, "unsigned-observer"), session: filepath.Join(base, "signed-session"), keyDir: filepath.Join(base, "witness-key")}
	h.call(label+"-dedicated-witness-key", "themis-native-witness", 0, "keygen", "--key-dir", p.keyDir, "--witness", "native-t43-witness")
	h.call(label+"-plan", "themis-dependency", 0, "plan", "--state", filepath.Join(h.state, "runner"), "--directory", p.directory, "--scenario", scenario, "--max-application-ms", fmt.Sprint(ceiling))
	if localstate.Read(filepath.Join(p.directory, "plan.json"), &p.plan) != nil {
		h.t.Fatal("actual native plan missing")
	}
	p.observer = h.start(label+"-original-separate-observer", "themis-dependency", "observe", "--state", filepath.Join(h.state, "observer"), "--plan", filepath.Join(p.directory, "plan.json"), "--observations", p.observations)
	h.ready(filepath.Join(p.observations, "ready.json"))
	h.call(label+"-exact-independent-approval", "themis-dependency", 0, "approve-witnessed", "--directory", p.directory, "--keys", filepath.Join(h.state, "keys"), "--approve-digest", p.plan.Digest())
	if localstate.Read(filepath.Join(p.directory, "authorization.json"), &p.authorization) != nil {
		h.t.Fatal("test operator authority missing")
	}
	raw := h.call(label+"-register-before-Apply", "themis-native-witness", 0, "register", "--key-dir", p.keyDir, "--approval", filepath.Join(p.directory, "public-approval.json"), "--session", p.session, "--approve-digest", p.plan.Digest())
	if json.Unmarshal(raw, &p.registration) != nil || p.registration.Validate() != nil {
		h.t.Fatal("native registration invalid")
	}
	now := time.Now().UTC()
	policy := obs.Policy{Version: obs.PolicyVersion, Keys: []obs.TrustedWitness{{Witness: p.registration.Witness, KeyID: p.registration.KeyID, PublicKey: p.registration.PublicKey, Algorithm: evidence.Algorithm, Engine: obs.Engine, Publisher: h.publisher.Name, PublisherKeyID: h.publisher.KeyID, Scopes: []obs.Scope{obs.ExactScope(p.registration)}, NotBefore: now.Add(-time.Hour).Format(time.RFC3339Nano), NotAfter: now.Add(24 * time.Hour).Format(time.RFC3339Nano)}}}
	p.policy = h.save(label+"-witness-policy.json", policy)
	h.save(label+"-registration.json", p.registration)
	p.witness = h.start(label+"-actual-independent-witness", "themis-native-witness", "observe", "--state", filepath.Join(h.state, "witness"), "--session", p.session, "--key-dir", p.keyDir)
	h.ready(filepath.Join(p.session, "ready.json"))
	return p
}
func (h *harness) runner(label string, p prepared) *process {
	return h.start(label, "themis-dependency", "run-witnessed", "--state", filepath.Join(h.state, "runner"), "--directory", p.directory, "--observations", p.observations, "--witness-session", p.session, "--witness-policy", p.policy)
}
func (h *harness) copyPublic(name, path string) {
	h.t.Helper()
	raw, e := os.ReadFile(path)
	if e != nil {
		h.t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(h.public, name), raw, 0600); e != nil {
		h.t.Fatal(e)
	}
}
func (h *harness) publish(label string, p prepared, reconciliation string, want int) (evidenceverify.NativeObservedResult, string) {
	h.t.Helper()
	export := filepath.Join(h.public, label+"-export")
	args := []string{"export", "--engine", obs.Engine, "--state", p.directory, "--witness-session", p.session, "--out", export}
	if reconciliation != "" {
		args = append(args, "--reconciliation", reconciliation)
	}
	h.call(label+"-public-export", "themis-evidence", 0, args...)
	bundle := filepath.Join(h.public, label+"-bundle.zip")
	h.call(label+"-retrospective-publication", "themis-evidence", 0, "bundle", "--engine", obs.Engine, "--source", export, "--out", bundle, "--key-dir", h.publisherDir, "--publisher", h.publisher.Name)
	raw := h.call(label+"-offline-public-verification", "themis-evidence", want, "verify", "--bundle", bundle, "--trust-policy", h.publisherPolicy, "--witness-policy", p.policy)
	var result evidenceverify.NativeObservedResult
	if json.Unmarshal(raw, &result) != nil || result.Evidence.TrustedExecutionVerdict != "INCONCLUSIVE" || result.NativeObservationCorroboration.TrustedExecutionVerdict != "INCONCLUSIVE" {
		h.t.Fatal("invalid or upgraded whole-execution result")
	}
	h.save(label+"-verification.json", result)
	h.copyPublic(label+"-original-runner.jsonl", filepath.Join(p.directory, "events.jsonl"))
	h.copyPublic(label+"-signed-witness.jsonl", filepath.Join(p.session, "observations.jsonl"))
	if _, e := os.Stat(filepath.Join(p.directory, "report.json")); e == nil {
		h.copyPublic(label+"-original-report.json", filepath.Join(p.directory, "report.json"))
	}
	return result, bundle
}
func TestOwnedKindWitnessedNativeVerdicts(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct {
		label, scenario, verdict     string
		ceiling, runExit, verifyExit int
	}{{"A-pass", "delay", "PASS", 500, 0, 0}, {"B-fail", "delay", "FAIL", 50, 4, 0}, {"C-no-effect", "no-effect", "INCONCLUSIVE", 500, 8, 8}, {"I-cleanup-pending", "cleanup-unconfirmed", "INCONCLUSIVE", 500, 7, 8}} {
		p := h.prepare(tc.label, tc.scenario, tc.ceiling)
		runner := h.runner(tc.label+"-actual-runner", p)
		raw, code := h.wait(runner)
		if code != tc.runExit {
			t.Fatal("actual native run exit", tc.label, code)
		}
		if _, code = h.wait(p.observer); code != 0 {
			t.Fatal("original separate observer failed")
		}
		_, witnessExit := h.wait(p.witness)
		if witnessExit != 0 && (tc.scenario != "cleanup-unconfirmed" || witnessExit != 8) {
			t.Fatal("independent actual witness failed", witnessExit)
		}
		var report adapter.Report
		if json.Unmarshal(raw, &report) != nil || report.Verdict != tc.verdict {
			t.Fatal("wrong original native verdict")
		}
		reconciliation := ""
		if tc.scenario == "cleanup-unconfirmed" {
			before, _ := os.ReadFile(filepath.Join(p.directory, "report.json"))
			journal, _ := os.ReadFile(filepath.Join(p.directory, "events.jsonl"))
			receipt := h.call("I-later-independent-reconciliation", "themis-dependency", 0, "reconcile", "--state", filepath.Join(h.state, "runner"), "--directory", p.directory)
			reconciliation = filepath.Join(h.public, "I-later-reconciliation.json")
			if os.WriteFile(reconciliation, receipt, 0600) != nil {
				t.Fatal("reconciliation output")
			}
			after, _ := os.ReadFile(filepath.Join(p.directory, "report.json"))
			later, _ := os.ReadFile(filepath.Join(p.directory, "events.jsonl"))
			if !bytes.Equal(before, after) || !bytes.Equal(journal, later) {
				t.Fatal("later cleanup rewrote history")
			}
		}
		result, bundle := h.publish(tc.label, p, reconciliation, tc.verifyExit)
		f := result.NativeObservationCorroboration
		if result.Evidence.Source.CandidateVerdict != tc.verdict || f.WitnessTrust != "TRUSTED" || f.SignatureChain != "VALID" {
			t.Fatal("source/witness trust classification", result)
		}
		if tc.verdict != "INCONCLUSIVE" && (f.ApplicationVerdict != tc.verdict || f.Effects < 3 || f.Recovery < 3) {
			t.Fatal("independently signed real measurement did not corroborate", f)
		}
		if tc.scenario == "no-effect" && f.Effects != 0 {
			t.Fatal("no-op became effect")
		}
		if tc.scenario == "cleanup-unconfirmed" && (result.Evidence.Source.Cleanup != "PENDING" || f.Status != "OBSERVATIONS_INCOMPLETE") {
			t.Fatal("witness recovery erased original cleanup uncertainty")
		}
		if tc.label == "A-pass" {
			h.adversePolicies("A", p, bundle)
			h.denyCopiedSession("A", p)
		}
		if tc.label == "B-fail" {
			h.fabricatedSource(p, bundle)
		}
		t.Logf("REAL KIND %s source=%s witness=%s baseline=%d active=%d effect=%d recovery=%d violations=%d max_app_ms=%.3f cleanup=%s", tc.label, tc.verdict, f.ApplicationVerdict, f.Baseline, f.Active, f.Effects, f.Recovery, f.Violations, f.MaxApplicationMS, result.Evidence.Source.Cleanup)
	}
}
