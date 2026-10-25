package nativedependency_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	adapter "github.com/tamen25/themis/internal/dependencyexperiment"
	wire "github.com/tamen25/themis/internal/dependencyhttp"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/test/ownedtask"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func (h *harness) cluster() *adapter.Cluster {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
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
		if e == nil && r.Verified(p.plan.Binding.Target.Proxy.Process, nonce, "state") && r.State.Active && r.State.Invocation == p.authorization.Grant.Invocation {
			return r
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.t.Fatal("actual actuator never became active")
	return wire.Reply{}
}
func (h *harness) runner(label string, p prepared) *process {
	return h.start(label, "run", "--state", filepath.Join(h.state, "runner"), "--directory", p.directory, "--observations", p.observations)
}
func (h *harness) external(label, program string, args ...string) []byte {
	h.t.Helper()
	start := time.Now()
	cmd := externalCommand(program, args...)
	cmd.Env = append(os.Environ(), "DEBUG=")
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	e := cmd.Run()
	code := 0
	if e != nil {
		code = -1
		if cmd.ProcessState != nil {
			code = cmd.ProcessState.ExitCode()
		} else {
			errOut.WriteString("launch failed: " + e.Error())
		}
	}
	h.records = append(h.records, commandRecord{program, label, args, code, out.String(), errOut.String(), time.Since(start).Milliseconds()})
	h.save("commands.json", h.records)
	if code != 0 {
		h.t.Fatalf("%s actual exit %d; retained evidence", label, code)
	}
	return out.Bytes()
}
func (h *harness) task(c *adapter.Cluster, component string) string {
	h.t.Helper()
	if component != "kube-apiserver" && component != "kube-controller-manager" {
		h.t.Fatal("fixed owned component only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if c.Environment(ctx) != nil {
		h.t.Fatal("owned namespace/cluster UID guard failed")
	}
	pod, e := c.API.CoreV1().Pods("kube-system").Get(ctx, component+"-"+c.Owner.ClusterName+"-control-plane", metav1.GetOptions{})
	if e != nil || len(pod.Status.ContainerStatuses) != 1 {
		h.t.Fatal("original owned component unavailable")
	}
	id := strings.TrimPrefix(pod.Status.ContainerStatuses[0].ContainerID, "containerd://")
	if len(id) != 64 {
		h.t.Fatal("exact task identity unavailable")
	}
	h.save(component+"-original-identity.json", struct{ PodUID, ContainerID, Node string }{string(pod.UID), id, c.Owner.ClusterName + "-control-plane"})
	return id
}
func (h *harness) taskAction(c *adapter.Cluster, label, action, id string) {
	h.t.Helper()
	if h.tasks == nil {
		owner, err := ownedtask.Read(h.state, c.Owner.ClusterName, c.Owner.ClusterUID, c.Owner.NamespaceUID)
		if err != nil {
			h.t.Fatal(err)
		}
		h.tasks = &ownedtask.Controller{Owner: owner}
		h.taskPins = map[string]bool{}
	}
	defer func() { h.save(label+"-task-commands.json", h.tasks.Receipts) }()
	if !h.taskPins[id] {
		if action == "resume" {
			h.t.Fatal("resume requires the original paused task binding")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if c.Environment(ctx) != nil {
			h.t.Fatal("original cluster identity unavailable")
		}
		podUID := ""
		for _, namespace := range []string{c.Owner.Namespace, "kube-system"} {
			pods, err := c.API.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
			if err != nil {
				h.t.Fatal("original task namespace unavailable")
			}
			for _, pod := range pods.Items {
				allowed := false
				if namespace == c.Owner.Namespace {
					for _, name := range c.Owner.Pods {
						if pod.Name == name {
							allowed = true
						}
					}
				} else {
					allowed = pod.Name == "kube-apiserver-"+c.Owner.ClusterName+"-control-plane" || pod.Name == "kube-controller-manager-"+c.Owner.ClusterName+"-control-plane"
				}
				if !allowed {
					continue
				}
				for _, status := range pod.Status.ContainerStatuses {
					if status.ContainerID == "containerd://"+id {
						runtimeUID, err := ownedtask.RuntimeUID(c.Owner.ClusterName, namespace, pod.Name, pod.Spec.NodeName, string(pod.UID), pod.Annotations)
						if err != nil {
							h.t.Fatal(err)
						}
						h.save(label+"-original-pod-binding.json", struct{ APIUID, RuntimeUID, ContainerID, Node string }{string(pod.UID), runtimeUID, id, pod.Spec.NodeName})
						podUID = runtimeUID
					}
				}
			}
		}
		if podUID == "" {
			h.t.Fatal("exact original owned task missing")
		}
		if err := h.tasks.Bind(id, podUID); err != nil {
			h.t.Fatal(err)
		}
		h.taskPins[id] = true
	}
	err := h.tasks.Action(action, id)
	h.save(label+"-task-control.json", struct {
		Action, Task, Node, Engine string
		Success                    bool
	}{action, id, h.tasks.Owner.NodeID, h.tasks.Owner.EngineID, err == nil})
	if err != nil {
		h.t.Fatal("original owned task operation failed", err)
	}
}

func TestOwnedKindRunnerDeathDuplicateAuthorityAndPolling(t *testing.T) {
	h := newHarness(t)
	p := h.prepare("F-runner-death", "delay", 500)
	conn := h.proxy()
	runner := h.runner("F-actual-runner", p)
	first := h.active(p, conn)
	cmd := wire.NewCommand("apply", p.authorization, time.Now())
	for i := 0; i < 2; i++ {
		r, e := adapter.Post(context.Background(), conn, "/control", cmd, cmd.Nonce, p.plan.Binding.Target.Proxy.Process)
		if e != nil || r.State.ApplyCount != 1 || r.State.DeadlineNS != first.State.DeadlineNS {
			t.Fatal("exact replay changed actuator deadline")
		}
		h.save("I-identical-apply-reply-"+string(rune('a'+i))+".json", r)
	}
	for range 100 {
		r, e := adapter.Control(context.Background(), conn, p.authorization, "status")
		if e != nil || r.State.DeadlineNS != first.State.DeadlineNS {
			t.Fatal("status polling extended fault or consumed mutation authority")
		}
	}
	if e := runner.cmd.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	if _, code := h.wait(runner); code == 0 {
		t.Fatal("runner termination did not occur")
	}
	if _, code := h.wait(p.observer); code != 0 {
		t.Fatal("independent observer died with runner")
	}
	current, e := adapter.Control(context.Background(), conn, p.authorization, "status")
	if e != nil || current.State.Active || current.State.ApplyCount != 1 || current.State.DeadlineNS != first.State.DeadlineNS || current.State.Reason != "expired" {
		t.Fatal("independent expiry after actual runner death missing")
	}
	h.save("F-independent-expiry.json", current)
	var observed adapter.ObserverReport
	b, e := os.ReadFile(filepath.Join(p.observations, "observations.json"))
	if e != nil || json.Unmarshal(b, &observed) != nil {
		t.Fatal("actual observer output missing")
	}
	evaluation := adapter.Evaluate(p.plan, observed, p.authorization.Grant.Invocation, false)
	if evaluation.Effects < 3 || evaluation.Recovery < 3 {
		t.Fatal("actual application effect/recovery missing")
	}
	h.save("F-independent-observations.json", observed)
	history, e := os.ReadFile(filepath.Join(p.directory, "events.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	h.call("F-independent-cleanup", 0, "reconcile", "--state", filepath.Join(h.state, "runner"), "--directory", p.directory)
	later, e := os.ReadFile(filepath.Join(p.directory, "events.jsonl"))
	if e != nil || !bytes.Equal(history, later) {
		t.Fatal("cleanup rewrote interrupted execution")
	}
	if _, e = os.Stat(filepath.Join(p.directory, "report.json")); !os.IsNotExist(e) {
		t.Fatal("invented completed runner report")
	}
	h.call("F-forbidden-restart", 6, "run", "--state", filepath.Join(h.state, "runner"), "--directory", p.directory, "--observations", p.observations)
	if e = os.WriteFile(filepath.Join(h.public, "F-original-runner.jsonl"), history, 0600); e != nil {
		t.Fatal(e)
	}
	t.Log("REAL KIND actual runner killed while active; exact Apply replay and 100 status polls did not renew; independent expiry, application recovery and cleanup confirmed; no resumed or fabricated history")
}
func TestOwnedKindAPIOutageDoesNotControlExpiryOrDataPath(t *testing.T) {
	h := newHarness(t)
	p := h.prepare("H-api-outage", "delay", 500)
	c := h.cluster()
	task := h.task(c, "kube-apiserver")
	conn := h.proxy()
	runner := h.runner("H-runner", p)
	first := h.active(p, conn)
	h.taskAction(c, "H-pause-only-owned-api", "pause", task)
	paused := true
	defer func() {
		if paused {
			h.taskAction(c, "H-restore-owned-api-defer", "resume", task)
		}
	}()
	time.Sleep(1800 * time.Millisecond)
	current, e := adapter.Control(context.Background(), conn, p.authorization, "status")
	if e != nil || current.State.Active || current.State.DeadlineNS != first.State.DeadlineNS || current.State.Reason != "expired" {
		t.Fatal("expiry depended on API")
	}
	h.save("H-expired-during-api-outage.json", current)
	app, e := c.Data("application")
	if e != nil {
		t.Fatal(e)
	}
	defer app.Close()
	nonce := wire.ID()
	recovered, e := wire.Fetch(context.Background(), app.Client, app.Base+"/value?nonce="+nonce)
	if e != nil || !recovered.Verified(p.plan.Binding.Target.Application.Process, nonce, "value") || recovered.Code != 200 || recovered.Proxy == nil || recovered.Proxy.HoldNS != 0 || recovered.Proxy.State.Invocation != "" {
		t.Fatal("real application path did not recover during API outage")
	}
	h.save("H-application-recovered-with-api-still-paused.json", recovered)
	raw, code := h.wait(runner)
	if code != 8 {
		t.Fatalf("expected conservative identity-uncertain runner exit 8, got %d", code)
	}
	var report adapter.Report
	if json.Unmarshal(raw, &report) != nil || report.Verdict != "INCONCLUSIVE" || report.Cleanup != "COMPLETE" {
		t.Fatal("API uncertainty semantics incorrect")
	}
	if _, code = h.wait(p.observer); code != 0 {
		t.Fatal("observer depended on API after admission")
	}
	h.publish("H-api-outage", p, report)
	h.taskAction(c, "H-resume-owned-api", "resume", task)
	paused = false
	h.call("H-later-reconcile", 0, "reconcile", "--state", filepath.Join(h.state, "runner"), "--directory", p.directory)
	t.Log("REAL KIND owned API task paused: live data path and local expiry/recovery continued; current Kubernetes identity remained uncertain; API restored and cleanup reconciled")
}
func TestOwnedKindControllerRestartAndCancellation(t *testing.T) {
	h := newHarness(t)
	// A pre-Apply stop is durable and fences the actuator before runner claim.
	p := h.prepare("cancel-before", "delay", 500)
	h.call("cancel-before-accepted", 0, "cancel", "--state", filepath.Join(h.state, "runner"), "--directory", p.directory)
	h.call("cancel-before-run", 9, "run", "--state", filepath.Join(h.state, "runner"), "--directory", p.directory, "--observations", p.observations)
	_, _ = h.wait(p.observer)
	conn := h.proxy()
	state, e := adapter.Control(context.Background(), conn, p.authorization, "status")
	if e != nil || state.State.Applied || !state.State.Fenced {
		t.Fatal("pre-Apply cancellation did not fence")
	}
	h.save("pre-apply-stop-fence.json", state)
	p = h.prepare("cancel-active", "delay", 500)
	runner := h.runner("cancel-active-runner", p)
	h.active(p, conn)
	h.call("cancel-active-accepted", 0, "cancel", "--state", filepath.Join(h.state, "runner"), "--directory", p.directory)
	raw, code := h.wait(runner)
	if code != 9 {
		t.Fatal("active cancellation ignored")
	}
	var report adapter.Report
	if json.Unmarshal(raw, &report) != nil || report.Verdict != "INCONCLUSIVE" {
		t.Fatal("cancelled run became PASS")
	}
	_, _ = h.wait(p.observer)
	h.publish("cancel-active", p, report)
	p = h.prepare("controller-restart", "delay", 500)
	c := h.cluster()
	task := h.task(c, "kube-controller-manager")
	runner = h.runner("controller-restart-runner", p)
	h.active(p, conn)
	h.taskAction(c, "restart-only-owned-kube-controller-manager", "kill", task)
	raw, code = h.wait(runner)
	if code != 0 {
		t.Fatal("independent path/expiry did not tolerate controller restart")
	}
	if json.Unmarshal(raw, &report) != nil || report.Verdict != "PASS" || report.Cleanup != "COMPLETE" {
		t.Fatal("controller restart evidence incomplete")
	}
	_, _ = h.wait(p.observer)
	h.publish("controller-restart", p, report)
	t.Log("REAL KIND pre-Apply and active cancellation fenced mutation; owned Kubernetes controller-manager restart did not control native expiry; existing Themis controller remains dry-run-only")
}
func TestOwnedKindProxyDeathAndPodReplacementCannotInheritAuthority(t *testing.T) {
	h := newHarness(t)
	for _, mode := range []string{"G-proxy-process-death", "E-proxy-pod-replacement"} {
		p := h.prepare(mode, "delay", 500)
		c := h.cluster()
		conn := h.proxy()
		runner := h.runner(mode+"-runner", p)
		h.active(p, conn)
		original := p.plan.Binding.Target.Proxy
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		pod, e := c.API.CoreV1().Pods(c.Owner.Namespace).Get(ctx, original.Pod, metav1.GetOptions{})
		cancel()
		if e != nil || string(pod.UID) != original.Process.PodUID || pod.Status.ContainerStatuses[0].ContainerID != original.ContainerID {
			t.Fatal("original proxy UID/container changed before guarded operation")
		}
		if mode == "G-proxy-process-death" {
			h.taskAction(c, mode+"-kill-exact-container", "kill", strings.TrimPrefix(original.ContainerID, "containerd://"))
		} else {
			ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
			uid := types.UID(original.Process.PodUID)
			e = c.API.CoreV1().Pods(c.Owner.Namespace).Delete(ctx, original.Pod, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
			cancel()
			if e != nil {
				t.Fatal("UID-precondition delete failed", e)
			}
			h.save(mode+"-guarded-delete.json", struct{ Pod, UID string }{original.Pod, string(uid)})
		}
		app, e := c.Data("application")
		if e != nil {
			t.Fatal(e)
		}
		app.Client.Timeout = 1500 * time.Millisecond
		var disrupted wire.Reply
		var nonce string
		disruption := false
		for start := time.Now(); time.Since(start) < 6*time.Second; {
			nonce = wire.ID()
			disrupted, e = wire.Fetch(context.Background(), app.Client, app.Base+"/value?nonce="+nonce)
			if e == nil && disrupted.Verified(p.plan.Binding.Target.Application.Process, nonce, "value") && disrupted.Code != 200 {
				disruption = true
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		app.Close()
		if !disruption {
			h.save(mode+"-unresolved-disruption-probe.json", struct {
				Reply wire.Reply
				Error bool
			}{disrupted, e != nil})
			t.Fatal("no authenticated application disruption observed after guarded termination")
		}
		h.save(mode+"-actual-application-disruption.json", disrupted)
		raw, code := h.wait(runner)
		if code == 0 {
			t.Fatal("replacement/crash run became PASS")
		}
		var report adapter.Report
		if json.Unmarshal(raw, &report) != nil || report.Verdict == "PASS" {
			t.Fatal("unsafe crash result")
		}
		_, _ = h.wait(p.observer)
		h.publish(mode, p, report)
		// The replacement serves a new boot identity but starts unbound/inactive.
		var replacement wire.Reply
		for start := time.Now(); time.Since(start) < 30*time.Second; {
			nonce = wire.ID()
			replacement, e = wire.Fetch(context.Background(), conn.Client, conn.Base+"/identity?nonce="+nonce)
			if e == nil && replacement.Identity.Boot != original.Process.Boot && replacement.Verified(replacement.Identity, nonce, "identity") {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if e != nil || replacement.Identity.Boot == original.Process.Boot || replacement.Identity.Key == original.Process.Key {
			t.Fatal("fresh replacement identity not observed")
		}
		if mode == "E-proxy-pod-replacement" && replacement.Identity.PodUID == original.Process.PodUID {
			t.Fatal("Pod UID did not change")
		}
		h.save(mode+"-fresh-boot-identity.json", replacement)
		cmd := wire.NewCommand("apply", p.authorization, time.Now())
		reply, _ := adapter.Post(context.Background(), conn, "/control", cmd, cmd.Nonce, replacement.Identity)
		if reply.Code != 403 || !reply.Verified(replacement.Identity, cmd.Nonce, "control") || reply.State.Applied {
			t.Fatal("replacement inherited original authority")
		}
		h.save(mode+"-old-authority-denied.json", reply)
		nonce = wire.ID()
		fresh, e := wire.Fetch(context.Background(), conn.Client, conn.Base+"/state?nonce="+nonce)
		if e != nil || fresh.State.Active || fresh.State.ApplyCount != 0 {
			t.Fatal("new proxy resumed a fault")
		}
		h.save(mode+"-replacement-inactive.json", fresh)
		// Explicit trusted installer rebinds current owned identities for subsequent
		// new plans only. No old approval/history is rewritten or redirected.
		h.external(mode+"-explicit-fresh-installation-binding", powershellProgram(), refreshArgs(filepath.Join(h.root, "scripts", "kind-dependency.ps1"), c.Owner.ClusterName)...)
		// Even a freshly signed approval for the old exact identity cannot act on
		// the now-bound replacement. This isolates identity denial from time expiry.
		var keys adapter.Keys
		if localstate.Read(filepath.Join(h.state, "keys", "keys.json"), &keys) != nil {
			t.Fatal("trusted negative-test approval unavailable")
		}
		stale := p.authorization
		stale.Grant.Issued = time.Now().UTC()
		stale.Grant.ApplyBefore = stale.Grant.Issued.Add(20 * time.Second)
		stale.Grant.CleanupBefore = stale.Grant.Issued.Add(5 * time.Minute)
		stale.Grant.Signature = ""
		stale.Grant.Signature = wire.Sign(wire.GrantVersion, stale.Grant, keys.ApproverPrivate)
		if !stale.Grant.Valid(time.Now(), true) {
			t.Fatal("negative approval was not otherwise valid")
		}
		cmd = wire.NewCommand("apply", stale, time.Now())
		reply, _ = adapter.Post(context.Background(), conn, "/control", cmd, cmd.Nonce, replacement.Identity)
		if reply.Code != 403 || !reply.Verified(replacement.Identity, cmd.Nonce, "control") || reply.State.Applied {
			t.Fatal("bound replacement accepted freshly approved stale-target authority")
		}
		h.save(mode+"-bound-replacement-rejects-fresh-stale-target-approval.json", reply)
	}
	t.Log("REAL KIND exact proxy container killed and exact disposable Pod replaced: real application disruption recorded, fresh boot/Pod denied original authority, no old fault resumed")
}
