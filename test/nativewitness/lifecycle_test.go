package nativewitness_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	adapter "github.com/tamen25/themis/internal/dependencyexperiment"
	wire "github.com/tamen25/themis/internal/dependencyhttp"
	"github.com/tamen25/themis/pkg/evidence"
	obs "github.com/tamen25/themis/pkg/nativeobservation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func (h *harness) cluster() *adapter.Cluster {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, e := adapter.Open(ctx, filepath.Join(h.state, "installer"), "installer")
	if e != nil {
		h.t.Fatal(e)
	}
	return c
}
func (h *harness) proxy() *adapter.Connection {
	h.t.Helper()
	c := h.cluster()
	conn, e := c.Data("proxy")
	if e != nil {
		h.t.Fatal(e)
	}
	h.t.Cleanup(conn.Close)
	return conn
}
func (h *harness) active(p prepared, conn *adapter.Connection) wire.Reply {
	h.t.Helper()
	for start := time.Now(); time.Since(start) < 4*time.Second; {
		nonce := wire.ID()
		r, e := wire.Fetch(context.Background(), conn.Client, conn.Base+"/state?nonce="+nonce)
		if e == nil && r.Verified(p.plan.Binding.Target.Proxy.Process, nonce, "state") && r.State.Invocation == p.authorization.Grant.Invocation && r.State.Active {
			return r
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.t.Fatal("approved original actuator never became active")
	return wire.Reply{}
}
func (h *harness) effect(p prepared, count int) {
	h.t.Helper()
	for start := time.Now(); time.Since(start) < 4*time.Second; {
		raw, e := os.ReadFile(filepath.Join(p.session, "observations.jsonl"))
		if e == nil {
			f, _ := obs.Analyze(p.registration, raw, nil, evidence.Publisher{}, time.Now())
			if f.Effects >= count {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.t.Fatal("actual signed witness effect samples missing")
}
func (h *harness) external(label, program string, want int, args ...string) []byte {
	h.t.Helper()
	start := time.Now()
	cmd := exec.Command("rtk", append([]string{"proxy", program}, args...)...)
	cmd.Env = append(os.Environ(), "DOCKER_HOST=npipe:////./pipe/docker_engine", "DEBUG=")
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	e := cmd.Run()
	code := 0
	if e != nil {
		code = cmd.ProcessState.ExitCode()
	}
	h.commands = append(h.commands, command{label, program, args, code, out.String(), errOut.String(), time.Since(start).Milliseconds()})
	h.save("commands.json", h.commands)
	if code != want {
		h.t.Fatalf("%s actual child %d expected %d", label, code, want)
	}
	return out.Bytes()
}
func (h *harness) taskAction(c *adapter.Cluster, label, action, id string) {
	h.t.Helper()
	if action != "pause" && action != "resume" && action != "kill" {
		h.t.Fatal("fixed owned task action only")
	}
	if len(id) != 64 || !strings.HasPrefix(c.Owner.ClusterName, "themis-t42-") {
		h.t.Fatal("exact owned task required")
	}
	args := []string{"-H", "npipe:////./pipe/docker_engine", "exec", c.Owner.ClusterName + "-control-plane", "ctr", "-n", "k8s.io", "tasks", action}
	if action == "kill" {
		args = append(args, "--signal", "SIGKILL")
	}
	args = append(args, id)
	h.external(label, "docker", 0, args...)
}
func (h *harness) reconcile(label string, p prepared) string {
	h.t.Helper()
	before, _ := os.ReadFile(filepath.Join(p.directory, "events.jsonl"))
	report, reportError := os.ReadFile(filepath.Join(p.directory, "report.json"))
	raw := h.call(label, "themis-dependency", 0, "reconcile", "--state", filepath.Join(h.state, "runner"), "--directory", p.directory)
	after, _ := os.ReadFile(filepath.Join(p.directory, "events.jsonl"))
	later, laterError := os.ReadFile(filepath.Join(p.directory, "report.json"))
	if !bytes.Equal(before, after) || !bytes.Equal(report, later) || (os.IsNotExist(reportError) != os.IsNotExist(laterError)) {
		h.t.Fatal("cleanup rewrote or invented source history")
	}
	path := filepath.Join(h.public, label+".json")
	if os.WriteFile(path, raw, 0600) != nil {
		h.t.Fatal("public cleanup receipt")
	}
	return path
}

func TestOwnedKindActualWitnessAndRunnerDeath(t *testing.T) {
	h := newHarness(t)
	for _, mode := range []string{"D-witness-death", "E-runner-death"} {
		p := h.prepare(mode, "delay", 500)
		conn := h.proxy()
		runner := h.runner(mode+"-actual-runner", p)
		first := h.active(p, conn)
		h.effect(p, 3)
		h.active(p, conn)
		target := p.witness
		if mode == "E-runner-death" {
			target = runner
		}
		if e := target.cmd.Process.Kill(); e != nil {
			t.Fatal(e)
		}
		if _, code := h.wait(target); code == 0 {
			t.Fatal("actual process was not terminated")
		}
		if mode == "D-witness-death" {
			raw, code := h.wait(runner)
			if code != 0 {
				t.Fatal("independent original native runner changed after witness death", code, string(raw))
			}
		} else {
			if _, code := h.wait(p.witness); code != 0 {
				t.Fatal("witness died with runner")
			}
		}
		if _, code := h.wait(p.observer); code != 0 {
			t.Fatal("original observer died with another actor")
		}
		current, e := adapter.Control(context.Background(), conn, p.authorization, "status")
		if e != nil || current.State.Active || current.State.DeadlineNS != first.State.DeadlineNS || current.State.ApplyCount != 1 || current.State.Reason != "expired" {
			t.Fatal("fault expiry changed or depended on killed actor")
		}
		h.save(mode+"-original-expiry.json", current)
		receipt := h.reconcile(mode+"-independent-cleanup", p)
		result, _ := h.publish(mode, p, receipt, 8)
		f := result.NativeObservationCorroboration
		if f.SignatureChain != "VALID" || f.WitnessTrust != "TRUSTED" || f.Status != "OBSERVATIONS_INCOMPLETE" {
			t.Fatal("interruption classification", f)
		}
		if mode == "D-witness-death" && f.Complete {
			t.Fatal("witness death invented terminal coverage")
		}
		if mode == "E-runner-death" {
			if result.Evidence.Source.CandidateVerdict != "INCONCLUSIVE" || result.Evidence.Source.Execution != "INTERRUPTED" || f.Recovery < 3 {
				t.Fatal("runner death invented result or lost actual witness recovery", result)
			}
			if _, e = os.Stat(filepath.Join(p.directory, "report.json")); !os.IsNotExist(e) {
				t.Fatal("completed source report invented")
			}
		}
		t.Logf("REAL KIND %s killed direct child; fault deadline unchanged, signed-prefix retained, independent cleanup; source=%s recovery=%d", mode, result.Evidence.Source.CandidateVerdict, f.Recovery)
	}
}

func TestOwnedKindSignedWitnessAcrossAPIOutage(t *testing.T) {
	h := newHarness(t)
	p := h.prepare("G-api-outage", "delay", 500)
	c := h.cluster()
	conn := h.proxy()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	pod, e := c.API.CoreV1().Pods("kube-system").Get(ctx, "kube-apiserver-"+c.Owner.ClusterName+"-control-plane", metav1.GetOptions{})
	cancel()
	if e != nil || len(pod.Status.ContainerStatuses) != 1 {
		t.Fatal("original API task missing")
	}
	task := strings.TrimPrefix(pod.Status.ContainerStatuses[0].ContainerID, "containerd://")
	h.save("G-original-api-task.json", struct{ PodUID, ContainerID, Node string }{string(pod.UID), task, c.Owner.ClusterName + "-control-plane"})
	runner := h.runner("G-actual-runner", p)
	first := h.active(p, conn)
	h.effect(p, 3)
	h.active(p, conn)
	h.taskAction(c, "G-pause-owned-api", "pause", task)
	paused := true
	defer func() {
		if paused {
			h.taskAction(c, "G-resume-owned-api-defer", "resume", task)
		}
	}()
	time.Sleep(1800 * time.Millisecond)
	state, e := adapter.Control(context.Background(), conn, p.authorization, "status")
	if e != nil || state.State.Active || state.State.Reason != "expired" || state.State.DeadlineNS != first.State.DeadlineNS {
		t.Fatal("expiry depended on Kubernetes API")
	}
	h.save("G-expiry-while-api-paused.json", state)
	app, e := c.Data("application")
	if e != nil {
		t.Fatal(e)
	}
	defer app.Close()
	nonce := wire.ID()
	reply, e := wire.Fetch(context.Background(), app.Client, app.Base+"/value?nonce="+nonce)
	if e != nil || !reply.Verified(p.plan.Binding.Target.Application.Process, nonce, "value") || reply.Code != 200 || reply.Proxy == nil || reply.Proxy.State.Active {
		t.Fatal("actual application did not recover during API outage")
	}
	h.save("G-application-recovered-while-api-paused.json", reply)
	raw, code := h.wait(runner)
	var report adapter.Report
	if json.Unmarshal(raw, &report) != nil || code != 8 || report.Verdict != "INCONCLUSIVE" || report.Cleanup != "COMPLETE" {
		t.Fatal("API identity uncertainty erased or independent cleanup lost", code)
	}
	_, _ = h.wait(p.observer)
	if _, code = h.wait(p.witness); code != 8 {
		t.Fatal("witness hid API uncertainty", code)
	}
	h.taskAction(c, "G-restore-only-owned-api", "resume", task)
	paused = false
	receipt := h.reconcile("G-after-api-restoration", p)
	result, _ := h.publish("G-api-outage", p, receipt, 8)
	f := result.NativeObservationCorroboration
	if f.IdentityCorrelation != "UNCERTAIN" || f.Recovery < 3 || f.Status != "OBSERVATIONS_INCOMPLETE" {
		t.Fatal("incorrect API-outage identity or recovery classification", f)
	}
	t.Log("REAL KIND original API paused through local expiry and application recovery; signed witness preserved identity uncertainty, restored API only for current reconciliation")
}

func TestOwnedKindWitnessRecordsProxyCrashAndPodReplacement(t *testing.T) {
	h := newHarness(t)
	for _, mode := range []string{"F-proxy-container-kill", "F-proxy-pod-replacement"} {
		p := h.prepare(mode, "delay", 500)
		c := h.cluster()
		conn := h.proxy()
		runner := h.runner(mode+"-runner", p)
		h.active(p, conn)
		h.effect(p, 3)
		h.active(p, conn)
		original := p.plan.Binding.Target.Proxy
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		pod, e := c.API.CoreV1().Pods(c.Owner.Namespace).Get(ctx, original.Pod, metav1.GetOptions{})
		cancel()
		if e != nil || string(pod.UID) != original.Process.PodUID || pod.Status.ContainerStatuses[0].ContainerID != original.ContainerID {
			t.Fatal("original proxy UID/container changed")
		}
		if mode == "F-proxy-container-kill" {
			h.taskAction(c, mode+"-SIGKILL-original-container", "kill", strings.TrimPrefix(original.ContainerID, "containerd://"))
		} else {
			ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
			uid := types.UID(original.Process.PodUID)
			e = c.API.CoreV1().Pods(c.Owner.Namespace).Delete(ctx, original.Pod, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
			cancel()
			if e != nil {
				t.Fatal(e)
			}
			h.save(mode+"-UID-precondition-delete.json", struct{ Pod, UID string }{original.Pod, string(uid)})
		}
		app, e := c.Data("application")
		if e != nil {
			t.Fatal(e)
		}
		disrupted := false
		for start := time.Now(); time.Since(start) < 6*time.Second; {
			nonce := wire.ID()
			reply, e := wire.Fetch(context.Background(), app.Client, app.Base+"/value?nonce="+nonce)
			if e == nil && reply.Verified(p.plan.Binding.Target.Application.Process, nonce, "value") && reply.Code != 200 {
				h.save(mode+"-actual-application-disruption.json", reply)
				disrupted = true
				break
			}
			time.Sleep(30 * time.Millisecond)
		}
		app.Close()
		if !disrupted {
			t.Fatal("no authenticated real dependency-path disruption")
		}
		raw, code := h.wait(runner)
		var report adapter.Report
		if code == 0 || json.Unmarshal(raw, &report) != nil || report.Verdict == "PASS" {
			t.Fatal("proxy disruption became source PASS")
		}
		_, _ = h.wait(p.observer)
		_, _ = h.wait(p.witness)
		result, _ := h.publish(mode, p, "", 8)
		if result.NativeObservationCorroboration.Status != "OBSERVATIONS_INCOMPLETE" || result.NativeObservationCorroboration.ApplicationVerdict == "PASS" {
			t.Fatal("proxy loss presented as application recovery", result)
		}
		var replacement wire.Reply
		for start := time.Now(); time.Since(start) < 30*time.Second; {
			nonce := wire.ID()
			replacement, e = wire.Fetch(context.Background(), conn.Client, conn.Base+"/identity?nonce="+nonce)
			if e == nil && replacement.Identity.Boot != original.Process.Boot && replacement.Verified(replacement.Identity, nonce, "identity") {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if e != nil || replacement.Identity.Boot == original.Process.Boot || replacement.Identity.Key == original.Process.Key {
			t.Fatal("new boot identity not established")
		}
		if mode == "F-proxy-pod-replacement" && replacement.Identity.PodUID == original.Process.PodUID {
			t.Fatal("replacement Pod UID did not change")
		}
		h.save(mode+"-replacement-identity.json", replacement)
		cmd := wire.NewCommand("apply", p.authorization, time.Now())
		reply, _ := adapter.Post(context.Background(), conn, "/control", cmd, cmd.Nonce, replacement.Identity)
		if reply.Code != 403 || !reply.Verified(replacement.Identity, cmd.Nonce, "control") || reply.State.Applied {
			t.Fatal("replacement inherited original authority")
		}
		h.save(mode+"-old-authority-denied.json", reply)
		h.external(mode+"-explicit-owned-rebind", "powershell", 0, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", filepath.Join(h.repo, "scripts", "kind-native-witness.ps1"), "-Action", "refresh", "-ClusterName", c.Owner.ClusterName, "-CommandProxy", "rtk")
		t.Logf("REAL KIND %s: genuine signed application disruption, new boot/key, original authority denied; no recovery PASS", mode)
	}
}
