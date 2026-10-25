package nativedependency_test

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
	"github.com/tamen25/themis/internal/postgres"
	"github.com/tamen25/themis/test/ownedtask"
)

type commandRecord struct {
	Program   string   `json:"program"`
	Label     string   `json:"label"`
	Arguments []string `json:"arguments"`
	Exit      int      `json:"exit"`
	Stdout    string   `json:"stdout"`
	Stderr    string   `json:"stderr"`
	Millis    int64    `json:"millis"`
}

func externalCommand(program string, args ...string) *exec.Cmd {
	if proxy := os.Getenv("THEMIS_TEST_COMMAND_PROXY"); proxy != "" {
		return exec.Command(proxy, append([]string{"proxy", program}, args...)...)
	}
	return exec.Command(program, args...)
}

func powershellProgram() string {
	if runtime.GOOS == "windows" {
		return "powershell"
	}
	return "pwsh"
}

func refreshArgs(script, cluster string) []string {
	args := []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, "-Action", "refresh", "-ClusterName", cluster}
	if proxy := os.Getenv("THEMIS_TEST_COMMAND_PROXY"); proxy != "" {
		args = append(args, "-CommandProxy", proxy)
	}
	return args
}

type harness struct {
	tasks              *ownedtask.Controller
	taskPins           map[string]bool
	t                  *testing.T
	state, bin, public string
	root               string
	records            []commandRecord
}
type process struct {
	cmd            *exec.Cmd
	stdout, stderr bytes.Buffer
	args           []string
	label          string
	started        time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	if os.Getenv("THEMIS_NATIVE_DEPENDENCY") != "1" {
		t.Skip("NOT EXECUTED: explicit newly owned T4.2 opt-in required")
	}
	if os.Getenv("DOCKER_CONTEXT") != "" {
		t.Fatal("DOCKER_CONTEXT must be empty; it overrides the explicit local Docker endpoint")
	}
	if err := postgres.ValidateEndpoint(os.Getenv("DOCKER_HOST")); err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, state: os.Getenv("THEMIS_NATIVE_DEPENDENCY_STATE"), bin: os.Getenv("THEMIS_NATIVE_DEPENDENCY_BINARY")}
	h.root = filepath.Dir(filepath.Dir(h.state))
	if h.state == "" || h.bin == "" || os.Getenv("THEMIS_NATIVE_DEPENDENCY_EVIDENCE") == "" {
		t.Fatal("explicit owned state, executable and public evidence required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, e := adapter.Open(ctx, filepath.Join(h.state, "installer"), "installer"); e != nil {
		t.Fatal("original owned cluster denied", e)
	}
	h.public = filepath.Join(os.Getenv("THEMIS_NATIVE_DEPENDENCY_EVIDENCE"), t.Name())
	if e := os.MkdirAll(h.public, 0700); e != nil {
		t.Fatal(e)
	}
	binary, e := os.ReadFile(h.bin)
	if e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256(binary)
	h.save("binary-identity.json", struct{ Path, SHA256 string }{h.bin, hex.EncodeToString(hash[:])})
	return h
}
func (h *harness) save(name string, v any) {
	h.t.Helper()
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		h.t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(h.public, name), append(b, '\n'), 0600); e != nil {
		h.t.Fatal(e)
	}
}
func (h *harness) start(label string, args ...string) *process {
	h.t.Helper()
	p := &process{args: args, label: label, started: time.Now()}
	// Direct child handles are required for real process termination. No shell
	// or wrapper process may be mistaken for the runner being tested.
	p.cmd = exec.Command(h.bin, args...)
	p.cmd.Env = append(os.Environ(), "DEBUG=", "GOMAXPROCS=4")
	p.cmd.Stdout = &p.stdout
	p.cmd.Stderr = &p.stderr
	if e := p.cmd.Start(); e != nil {
		h.t.Fatal(e)
	}
	h.t.Cleanup(func() {
		if p.cmd.ProcessState == nil {
			_ = p.cmd.Process.Kill()
			_, _ = h.wait(p)
		}
	})
	return p
}
func (h *harness) wait(p *process) ([]byte, int) {
	h.t.Helper()
	e := p.cmd.Wait()
	code := 0
	if e != nil {
		if p.cmd.ProcessState != nil {
			code = p.cmd.ProcessState.ExitCode()
		} else {
			code = -1
		}
	}
	h.records = append(h.records, commandRecord{h.bin, p.label, p.args, code, p.stdout.String(), p.stderr.String(), time.Since(p.started).Milliseconds()})
	h.save("commands.json", h.records)
	return p.stdout.Bytes(), code
}
func (h *harness) call(label string, want int, args ...string) []byte {
	h.t.Helper()
	p := h.start(label, args...)
	b, code := h.wait(p)
	if code != want {
		h.t.Fatalf("%s actual child exit %d, want %d; diagnostics retained in %s", label, code, want, h.public)
	}
	return b
}

type prepared struct {
	directory, observations string
	plan                    wire.Plan
	authorization           wire.Authorization
	observer                *process
}

func (h *harness) prepare(label, scenario string, ceiling int) prepared {
	h.t.Helper()
	base, e := localstate.CreateDirectory(filepath.Join(h.state, "test-"+wire.ID()[:12]))
	if e != nil {
		h.t.Fatal(e)
	}
	p := prepared{directory: filepath.Join(base, "run"), observations: filepath.Join(base, "observations")}
	raw := h.call(label+"-plan", 0, "plan", "--state", filepath.Join(h.state, "runner"), "--directory", p.directory, "--scenario", scenario, "--max-application-ms", fmt.Sprint(ceiling))
	var plan struct {
		Plan   wire.Plan `json:"plan"`
		Digest string    `json:"digest"`
	}
	if json.Unmarshal(raw, &plan) != nil || !plan.Plan.Valid() || plan.Digest != plan.Plan.Digest() {
		h.t.Fatal("actual frozen plan invalid")
	}
	p.plan = plan.Plan
	p.observer = h.start(label+"-observer", "observe", "--state", filepath.Join(h.state, "observer"), "--plan", filepath.Join(p.directory, "plan.json"), "--observations", p.observations)
	h.t.Cleanup(func() {
		if p.observer.cmd.ProcessState == nil {
			_ = p.observer.cmd.Process.Kill()
		}
	})
	ready := false
	for start := time.Now(); time.Since(start) < 5*time.Second; {
		if _, e = os.Stat(filepath.Join(p.observations, "ready.json")); e == nil {
			ready = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		h.wait(p.observer)
		h.t.Fatal("separate real observer never reached baseline readiness")
	}
	h.call(label+"-approve", 0, "approve", "--directory", p.directory, "--keys", filepath.Join(h.state, "keys"), "--approve-digest", p.plan.Digest())
	if e = localstate.Read(filepath.Join(p.directory, "authorization.json"), &p.authorization); e != nil {
		h.t.Fatal(e)
	}
	h.save(label+"-plan.json", p.plan)
	return p
}
func (h *harness) publish(label string, p prepared, r adapter.Report) {
	h.t.Helper()
	h.save(label+"-report.json", r)
	for _, item := range []struct{ source, dest string }{{filepath.Join(p.directory, "events.jsonl"), label + "-events.jsonl"}, {filepath.Join(p.observations, "observations.jsonl"), label + "-observations.jsonl"}, {filepath.Join(p.observations, "observations.json"), label + "-observations.json"}} {
		b, e := os.ReadFile(item.source)
		if e != nil {
			h.t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(h.public, item.dest), b, 0600); e != nil {
			h.t.Fatal(e)
		}
	}
}
func TestOwnedKindRealDependencyVerdictsAndHistoricalCleanup(t *testing.T) {
	h := newHarness(t)
	for _, scenario := range []struct {
		label, mode, verdict, cleanup string
		ceiling, exit                 int
	}{{"A-pass", "delay", "PASS", "COMPLETE", 500, 0}, {"B-fail", "delay", "FAIL", "COMPLETE", 50, 4}, {"C-no-effect", "no-effect", "INCONCLUSIVE", "COMPLETE", 500, 8}, {"D-cleanup-pending", "cleanup-unconfirmed", "INCONCLUSIVE", "PENDING", 500, 7}} {
		p := h.prepare(scenario.label, scenario.mode, scenario.ceiling)
		raw := h.call(scenario.label+"-run", scenario.exit, "run", "--state", filepath.Join(h.state, "runner"), "--directory", p.directory, "--observations", p.observations)
		if _, code := h.wait(p.observer); code != 0 {
			t.Fatal("actual independent observer failed")
		}
		var report adapter.Report
		if json.Unmarshal(raw, &report) != nil || report.Verdict != scenario.verdict || report.Cleanup != scenario.cleanup || report.TrustedExecutionVerdict != "INCONCLUSIVE" {
			t.Fatal("wrong measured result")
		}
		if scenario.mode != "no-effect" && report.Evaluation.Effects < 3 {
			t.Fatal("missing independently measured application effect")
		}
		if scenario.mode == "no-effect" && report.Evaluation.Effects != 0 {
			t.Fatal("no-op manufactured effect")
		}
		h.publish(scenario.label, p, report)
		if scenario.label == "D-cleanup-pending" {
			before, e := os.ReadFile(filepath.Join(p.directory, "report.json"))
			if e != nil {
				t.Fatal(e)
			}
			h.call("D-later-reconciliation", 0, "reconcile", "--state", filepath.Join(h.state, "runner"), "--directory", p.directory)
			after, e := os.ReadFile(filepath.Join(p.directory, "report.json"))
			if e != nil || !bytes.Equal(before, after) {
				t.Fatal("reconciliation rewrote original report")
			}
		}
		t.Logf("REAL KIND %s verdict=%s cleanup=%s baseline=%d active=%d effect=%d recovery=%d max_application_ms=%.3f", scenario.label, report.Verdict, report.Cleanup, report.Evaluation.Baseline, report.Evaluation.Active, report.Evaluation.Effects, report.Evaluation.Recovery, report.Evaluation.MaxApplicationMS)
	}
}
