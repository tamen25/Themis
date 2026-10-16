package kubernetesexperiment_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/kubeexperiment"
	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
	appsv1 "k8s.io/api/apps/v1"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type harness struct {
	t                                   *testing.T
	ctx                                 context.Context
	cluster                             *kubeexperiment.Cluster
	state, binary, evidence, repository string
	commands                            []any
}

func (h *harness) save(name string, value any) {
	h.t.Helper()
	if h.evidence == "" {
		return
	}
	if err := os.MkdirAll(h.evidence, 0700); err != nil {
		h.t.Fatal(err)
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		h.t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(h.evidence, name+".json"), data, 0600); err != nil {
		h.t.Fatal(err)
	}
}
func (h *harness) copy(name, path string) {
	h.t.Helper()
	if h.evidence == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		h.t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(h.evidence, name), data, 0600); err != nil {
		h.t.Fatal(err)
	}
}
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var e *exec.ExitError
	if errors.As(err, &e) {
		return e.ExitCode()
	}
	return -99
}
func (h *harness) command(label string, want int, args ...string) []byte {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(h.ctx, 30*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, h.binary, args...)
	c.Dir = h.repository
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr
	start := time.Now()
	err := c.Run()
	code := exitCode(err)
	h.commands = append(h.commands, map[string]any{"label": label, "program": h.binary, "arguments": args, "exitCode": code, "elapsedMS": time.Since(start).Milliseconds(), "stdout": stdout.String(), "stderr": stderr.String()})
	if code != want {
		h.save("commands", h.commands)
		h.t.Fatalf("%s exit=%d want=%d: %s", label, code, want, stderr.String())
	}
	return stdout.Bytes()
}

type prepared struct {
	plan                             kubefault.Plan
	auth                             kubefault.Authorization
	planFile, authFile, root, runDir string
}

func (h *harness) prepare(label, scenario string) prepared {
	h.t.Helper()
	root, err := localstate.CreateDirectory(filepath.Join(h.state, "case-"+label+"-"+kubefault.RandomID()[:12]))
	if err != nil {
		h.t.Fatal(err)
	}
	output := h.command(label+"-plan", 0, "plan", "--state", h.state, "--run", "latency-request", "--scenario", scenario)
	var envelope struct {
		Digest string         `json:"digest"`
		Plan   kubefault.Plan `json:"plan"`
	}
	if kubefault.Decode(output, &envelope) != nil || envelope.Plan.Validate() != nil || envelope.Digest != envelope.Plan.Digest() {
		h.t.Fatal("invalid live CLI plan")
	}
	planFile, authFile := filepath.Join(root, "plan.json"), filepath.Join(root, "authorization.json")
	if err = localstate.WriteNew(planFile, envelope); err != nil {
		h.t.Fatal(err)
	}
	h.command(label+"-approve", 0, "approve", "--state", h.state, "-f", planFile, "--approve-digest", envelope.Digest, "--out", authFile)
	var auth kubefault.Authorization
	if err = localstate.Read(authFile, &auth); err != nil {
		h.t.Fatal(err)
	}
	return prepared{envelope.Plan, auth, planFile, authFile, root, filepath.Join(root, "run-"+auth.Grant.InvocationID)}
}

// Explicit opt-in. No ambient config, pod deletion, target patch or Job is used.
// The sole fault is an authenticated <=3s application-path delay in the installed
// fixture. Only the owned controller is restarted during the interruption test.
func TestOwnedKindExperiments(t *testing.T) {
	state := os.Getenv("THEMIS_KIND_EXPERIMENT_STATE")
	if state == "" {
		t.Skip("NOT EXECUTED: dedicated owned Kind experiment state required")
	}
	binary := os.Getenv("THEMIS_KUBE_RUNNER_BINARY")
	if binary == "" {
		t.Fatal("explicit actual runner executable required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	c, err := kubeexperiment.Open(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, ctx: ctx, cluster: c, state: state, binary: binary, evidence: os.Getenv("THEMIS_KIND_EXPERIMENT_EVIDENCE"), repository: filepath.Dir(filepath.Dir(state))}
	defer func() { h.save("commands", h.commands) }()
	original := &appsv1.Deployment{}
	if err = c.Reader.Get(ctx, client.ObjectKey{Namespace: "themis-test", Name: "latency-fixture"}, original); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		name, mode string
		exit       int
		verdict    result.Verdict
	}{{"A-PASS", "healthy", 0, result.Pass}, {"B-FAIL", "buggy", 2, result.Fail}, {"C-INCONCLUSIVE", "noop", 3, result.Inconclusive}, {"D-CLEANUP_PENDING", "cleanup-denied", 7, result.Inconclusive}} {
		p := h.prepare(scenario.name, scenario.mode)
		output := h.command(scenario.name+"-run", scenario.exit, "run", "--state", state, "-f", p.planFile, "--authorization", p.authFile, "--runs", p.root)
		var completed struct {
			Directory string                `json:"directory"`
			Report    kubeexperiment.Report `json:"report"`
		}
		if json.Unmarshal(output, &completed) != nil || completed.Directory != p.runDir || completed.Report.Verdict != scenario.verdict || !completed.Report.Authorized {
			t.Fatalf("%s invalid actual report", scenario.name)
		}
		r := completed.Report
		if scenario.mode != "noop" && !r.InterventionConfirmed {
			t.Fatal("acknowledgement substituted for observed intervention")
		}
		if scenario.mode == "noop" && r.InterventionConfirmed {
			t.Fatal("ineffective proxy produced false intervention proof")
		}
		if scenario.mode != "cleanup-denied" && (!r.RecoveryVerified || r.Cleanup != "COMPLETE") {
			t.Fatal("missing actual recovery/cleanup")
		}
		h.save(scenario.name+"-report", r)
		h.copy(scenario.name+"-events.jsonl", filepath.Join(p.runDir, "events.jsonl"))
		replay, err := kubeexperiment.Replay(filepath.Join(p.runDir, "events.jsonl"))
		if err != nil || replay.Verdict == result.Pass || replay.Authorized {
			t.Fatal("unsigned replay established trusted PASS", err)
		}
		h.save(scenario.name+"-unsigned-replay", replay)
		if scenario.mode == "healthy" {
			s, err := c.Connect(ctx, p.plan)
			if err != nil {
				t.Fatal(err)
			}
			status, err := s.Client.Control(ctx, p.auth, "apply")
			s.Close()
			if err != nil || status.Active || status.ApplyCount != 1 {
				t.Fatal("duplicate Apply recreated the removed effect", err)
			}
			h.save("duplicate-apply-retained-receipt", status)
		}
		if scenario.mode == "cleanup-denied" {
			before, err := os.ReadFile(filepath.Join(p.runDir, "events.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			time.Sleep(3 * time.Second)
			receipt, err := c.Reconcile(ctx, p.runDir)
			if err != nil || receipt.CurrentState != "INACTIVE" || !receipt.RecoveryVerified {
				t.Fatal("independent expiry and later cleanup not established", err)
			}
			again, err := c.Reconcile(ctx, p.runDir)
			if err != nil || again.CurrentState != "INACTIVE" {
				t.Fatal("repeated cleanup failed", err)
			}
			after, _ := os.ReadFile(filepath.Join(p.runDir, "events.jsonl"))
			if !bytes.Equal(before, after) {
				t.Fatal("reconciliation rewrote historical verdict/journal")
			}
			var recorded kubeexperiment.Report
			if localstate.Read(filepath.Join(p.runDir, "report.json"), &recorded) != nil || recorded.Execution != result.CleanupPending || recorded.Verdict != scenario.verdict {
				t.Fatal("cleanup reconciliation changed historical unsafe outcome")
			}
			h.save("D-independent-expiry-reconciliation", receipt)
			h.save("D-repeated-cleanup", again)
		}
		t.Logf("REAL KIND %s: exit=%d verdict=%s intervention=%v recovery=%v cleanup=%s PodUID=%s", scenario.name, scenario.exit, r.Verdict, r.InterventionConfirmed, r.RecoveryVerified, r.Cleanup, p.plan.Target.Fixture.PodUID)
	}
	h.runnerDeath()
	h.negatives()
	h.checkRBAC()
	current := &appsv1.Deployment{}
	if err = c.Reader.Get(ctx, client.ObjectKeyFromObject(original), current); err != nil {
		t.Fatal(err)
	}
	if current.UID != original.UID || current.Generation != original.Generation || !reflect.DeepEqual(current.Spec, original.Spec) || !reflect.DeepEqual(current.Labels, original.Labels) || !reflect.DeepEqual(current.Annotations, original.Annotations) || !reflect.DeepEqual(current.OwnerReferences, original.OwnerReferences) {
		t.Fatal("experiments changed the target Kubernetes workload")
	}
	t.Log("REAL KIND target Deployment UID/generation/spec/metadata unchanged; no Kubernetes fault resource was created")
}

func (h *harness) runnerDeath() {
	t := h.t
	t.Helper()
	p := h.prepare("runner-death", "healthy")
	args := []string{"run", "--state", h.state, "-f", p.planFile, "--authorization", p.authFile, "--runs", p.root}
	cmd := exec.CommandContext(h.ctx, h.binary, args...)
	cmd.Dir = h.repository
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	terminated := false
	defer func() {
		if !terminated {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	var applied *kubefault.Status
	for start := time.Now(); time.Since(start) < 10*time.Second; {
		events, err := kubeexperiment.ReadJournal(filepath.Join(p.runDir, "events.jsonl"))
		if err == nil {
			for _, e := range events {
				if e.Type == "APPLIED" {
					applied = e.Status
				}
			}
		}
		if applied != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if applied == nil || !applied.Active {
		t.Fatal("actual child runner did not reach a durable active Apply")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err := cmd.Wait()
	terminated = true
	code := exitCode(err)
	if code == 0 {
		t.Fatal("terminated runner unexpectedly succeeded")
	}
	h.commands = append(h.commands, map[string]any{"label": "runner-process-termination", "program": h.binary, "arguments": args, "exitCode": code, "killedAfterDurableApply": true, "stdout": stdout.String(), "stderr": stderr.String()})
	// Restart only the owned controller through the setup's UID guard. The dead
	// runner cannot remove its fault, and the controller has no fixture authority.
	program := "powershell"
	if goruntime.GOOS != "windows" {
		program = "pwsh"
	}
	restartArgs := []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", filepath.Join(h.repository, "scripts/kind-experiment.ps1"), "-Action", "restart-controller"}
	if proxy := os.Getenv("THEMIS_TEST_COMMAND_PROXY"); proxy != "" {
		restartArgs = append(restartArgs, "-CommandProxy", proxy)
	}
	restart := exec.CommandContext(h.ctx, program, restartArgs...)
	restart.Dir = h.repository
	restarted, err := restart.CombinedOutput()
	h.commands = append(h.commands, map[string]any{"label": "owned-controller-restart-after-runner-death", "program": program, "arguments": restart.Args[1:], "exitCode": exitCode(err), "output": string(restarted)})
	if err != nil {
		t.Fatal("owned controller restart failed", err)
	}
	if wait := time.Until(applied.ExpiresAt) + 100*time.Millisecond; wait > 0 {
		time.Sleep(wait)
	}
	s, err := h.cluster.Connect(h.ctx, p.plan)
	if err != nil {
		t.Fatal(err)
	}
	status, err := s.Client.Control(h.ctx, p.auth, "status")
	s.Close()
	if err != nil || status.Active || !status.Applied || status.Reason != "expired" {
		t.Fatal("real independent expiry after process death was not observed", err)
	}
	h.save("runner-death-applied", applied)
	h.save("runner-death-independent-expiry", status)
	h.copy("runner-death-original-prefix.jsonl", filepath.Join(p.runDir, "events.jsonl"))
	history, err := kubeexperiment.Replay(filepath.Join(p.runDir, "events.jsonl"))
	if err != nil || history.Verdict == result.Pass || history.Execution != result.CleanupPending {
		t.Fatal("interrupted run falsely completed", err)
	}
	h.save("runner-death-interrupted-history", history)
	// Corrupt only the dead runner's owned journal. Cleanup uses its independent
	// private inventory and must preserve the corrupt bytes for diagnosis.
	path := filepath.Join(p.runDir, "events.jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("{\"unsupportedPASS\":true}\n")
	_ = f.Close()
	corrupt, _ := os.ReadFile(path)
	if _, err = kubeexperiment.Replay(path); err == nil {
		t.Fatal("corrupt journal accepted")
	}
	receipt, err := h.cluster.Reconcile(h.ctx, p.runDir)
	if err != nil || receipt.CurrentState != "INACTIVE" || !receipt.RecoveryVerified {
		t.Fatal("corrupt-journal cleanup lost authority or fabricated recovery", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(corrupt, after) {
		t.Fatal("cleanup repaired/rewrote corrupt history")
	}
	h.copy("runner-death-corrupt-history.jsonl", path)
	h.save("runner-death-cleanup-receipt", receipt)
	t.Logf("REAL KIND runner killed (exit %d), controller restarted, independent expiry observed; corrupt history preserved and current recovery measured", code)
}

func (h *harness) negatives() {
	t := h.t
	t.Helper()
	p := h.prepare("negative", "healthy")
	results := []map[string]any{}
	for _, name := range []string{"cluster UID", "namespace UID", "Deployment UID", "generation", "Pod UID", "plan digest", "namespace policy", "unsupported action", "excess duration"} {
		candidate := p.plan
		c := *h.cluster
		switch name {
		case "cluster UID":
			c.Owner.ClusterUID = "99999999-9999-9999-9999-999999999999"
		case "namespace UID":
			c.Owner.NamespaceUID = "99999999-9999-9999-9999-999999999999"
		case "Deployment UID":
			candidate.Target.DeploymentUID = "99999999-9999-9999-9999-999999999999"
		case "generation":
			candidate.Target.DeploymentGeneration++
		case "Pod UID":
			candidate.Target.Fixture.PodUID = "99999999-9999-9999-9999-999999999999"
		case "plan digest":
			candidate.PreviewDigest = "sha256:" + kubefault.RandomID()
		case "namespace policy":
			candidate.Target.Namespace = "default"
		case "unsupported action":
			candidate.Fault.Type = "pod-delete"
		case "excess duration":
			candidate.Fault.DurationMS = 60000
		}
		err := c.Revalidate(h.ctx, candidate)
		if err == nil {
			t.Fatal("real-cluster admission failed to deny", name)
		}
		boundary := "REAL_API_IDENTITY_READS"
		if name == "namespace policy" || name == "unsupported action" || name == "excess duration" {
			boundary = "PURE_POLICY_BEFORE_API_ACTION"
		}
		results = append(results, map[string]any{"case": name, "boundary": boundary, "denied": true})
	}
	var signing struct {
		Key string `json:"privateKey"`
	}
	if err := localstate.Read(filepath.Join(h.state, "approver-key.json"), &signing); err != nil {
		t.Fatal(err)
	}
	key, _ := hex.DecodeString(signing.Key)
	expired, err := kubefault.Approve(p.plan, p.plan.Digest(), ed25519.PrivateKey(key), time.Now().Add(-30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	s, err := h.cluster.Connect(h.ctx, p.plan)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, name := range []string{"expired valid grant", "forged signature", "changed plan after approval"} {
		a := p.auth
		switch name {
		case "expired valid grant":
			a = expired
		case "forged signature":
			a.Grant.Signature = "00"
		case "changed plan after approval":
			a.Grant.Plan.Contract.Name = "changed-after-approval"
		}
		_, err = s.Client.Control(h.ctx, a, "apply")
		if !errors.Is(err, kubefault.ErrDenied) {
			t.Fatal("real fixture accepted stale/forged/mutated grant", name, err)
		}
		results = append(results, map[string]any{"case": name, "boundary": "REAL_KIND_AUTHENTICATED_FIXTURE_DENIAL", "denied": true})
	}
	status, err := s.Client.Control(h.ctx, p.auth, "status")
	if err != nil || status.Applied || status.Active || status.ApplyCount != 0 {
		t.Fatal("negative tests reached fault application", err)
	}
	h.save("admission-negative-results", results)
	h.save("negative-zero-apply-status", status)
	t.Log("REAL KIND stale/forged/spec-mutated grants denied with zero Apply; real API identity mismatches denied before fault commands")
}

func (h *harness) checkRBAC() {
	t := h.t
	t.Helper()
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(&clientcmd.ClientConfigLoadingRules{ExplicitPath: filepath.Join(h.state, "admin-kubeconfig")}, &clientcmd.ConfigOverrides{CurrentContext: "kind-themis-t21"}).ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	config.Timeout = 5 * time.Second
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = authzv1.AddToScheme(scheme)
	c, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	for name, uid := range map[string]string{"kube-system": h.cluster.Owner.ClusterUID, "themis-test": h.cluster.Owner.NamespaceUID} {
		ns := &corev1.Namespace{}
		if c.Get(h.ctx, client.ObjectKey{Name: name}, ns) != nil || string(ns.UID) != uid {
			t.Fatal("owned admin context UID mismatch")
		}
	}
	p, err := h.cluster.Plan(h.ctx, "latency-request", "healthy")
	if err != nil {
		t.Fatal(err)
	}
	results := []map[string]any{}
	for _, check := range []struct {
		actor, group, resource, subresource, verb, namespace, name string
		allowed                                                    bool
	}{
		{"themis-runner", "", "pods", "portforward", "create", "themis-test", p.Target.Fixture.PodName, true},
		{"themis-runner", "", "pods", "portforward", "create", "themis-test", "unrelated-pod", false},
		{"themis-runner", "", "pods", "exec", "create", "themis-test", p.Target.Fixture.PodName, false},
		{"themis-runner", "apps", "deployments", "", "get", "themis-test", "latency-fixture", true},
		{"themis-runner", "apps", "deployments", "", "patch", "themis-test", "latency-fixture", false},
		{"themis-runner", "", "pods", "", "delete", "themis-test", p.Target.Fixture.PodName, false},
		{"themis-runner", "batch", "jobs", "", "create", "themis-test", "job", false},
		{"themis-runner", "", "secrets", "", "get", "themis-test", "secret", false},
		{"themis-runner", "verification.themis.dev", "verificationruns", "status", "update", "themis-test", "latency-request", false},
		{"themis-runner", "apps", "deployments", "", "get", "default", "unrelated", false},
		{"themis-runner", "rbac.authorization.k8s.io", "roles", "", "update", "themis-test", "themis-runner", false},
		{"themis-controller", "apps", "deployments", "", "patch", "themis-test", "latency-fixture", false},
		{"themis-controller", "", "pods", "", "delete", "themis-test", p.Target.Fixture.PodName, false},
		{"themis-controller", "", "pods", "portforward", "create", "themis-test", p.Target.Fixture.PodName, false},
		{"themis-fixture", "", "pods", "", "get", "themis-test", p.Target.Fixture.PodName, false},
		{"themis-fixture", "", "secrets", "", "get", "themis-test", "secret", false},
	} {
		review := &authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{User: "system:serviceaccount:themis-test:" + check.actor, Groups: []string{"system:serviceaccounts", "system:serviceaccounts:themis-test", "system:authenticated"}, ResourceAttributes: &authzv1.ResourceAttributes{Group: check.group, Resource: check.resource, Subresource: check.subresource, Verb: check.verb, Namespace: check.namespace, Name: check.name}}}
		if err := c.Create(h.ctx, review); err != nil {
			t.Fatal(err)
		}
		if review.Status.Allowed != check.allowed {
			t.Fatalf("RBAC mismatch for %s %s/%s %s", check.actor, check.resource, check.subresource, check.verb)
		}
		results = append(results, map[string]any{"actor": check.actor, "group": check.group, "resource": check.resource, "subresource": check.subresource, "verb": check.verb, "namespace": check.namespace, "name": check.name, "allowed": review.Status.Allowed})
	}
	h.save("effective-rbac-reviews", results)
	t.Log("REAL Kubernetes SubjectAccessReviews deny unrelated mutations, Secrets, exec and other-Pod forwarding; fixture has no API resource grants")
}
