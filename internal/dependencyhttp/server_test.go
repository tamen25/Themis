package dependencyhttp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

type redirectTransport struct {
	destinations map[string]string
	next         http.RoundTripper
}

func (r redirectTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	endpoint, e := url.Parse(r.destinations[request.URL.Host])
	if e != nil || endpoint.Host == "" {
		return nil, ErrDenied
	}
	copyURL := *request.URL
	copyURL.Scheme = endpoint.Scheme
	copyURL.Host = endpoint.Host
	clone.URL = &copyURL
	return r.next.RoundTrip(clone)
}

type fixture struct {
	servers                  []*Server
	proxy                    *Server
	plan                     Plan
	approver, installer      string
	appURL, proxyURL, depURL string
}

func uid(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
func newFixture(t testing.TB) *fixture {
	t.Helper()
	ip, ik, e := NewKey()
	if e != nil {
		t.Fatal(e)
	}
	ap, ak, e := NewKey()
	if e != nil {
		t.Fatal(e)
	}
	config := Config{ClusterUID: uid(1), NamespaceUID: uid(2), Namespace: "themis-dep-123456abcdef", InstallerKey: ip, ApproverKey: ap, Actor: "system:serviceaccount:themis-dep-123456abcdef:native-runner", ActorUID: uid(3), ProxyIP: "10.0.0.1"}
	f := &fixture{approver: ak, installer: ik}
	workloads := make([]Workload, 3)
	urls := make([]string, 3)
	for i, role := range []string{"application", "proxy", "dependency"} {
		s, e := NewServer(config, role, uid(10+i), t.TempDir())
		if e != nil {
			t.Fatal(e)
		}
		f.servers = append(f.servers, s)
		host := httptest.NewServer(s)
		urls[i] = host.URL
		t.Cleanup(func() { host.Close(); s.Close() })
		workloads[i] = Workload{Name: "native-" + role, DeploymentUID: uid(20 + i), Generation: 1, ReplicaSet: "native-" + role + "-rs", ReplicaSetUID: uid(30 + i), Pod: "native-" + role + "-rs-pod", ContainerID: "containerd://" + strings.Repeat(fmt.Sprint(i+1), 64), Image: "example/native@sha256:" + strings.Repeat("a", 64), ImageID: "example/native@sha256:" + strings.Repeat("b", 64), SpecDigest: Hash(role), Process: s.Identity}
	}
	destinations := map[string]string{"10.0.0.1:8080": urls[1], "10.0.0.2:8080": urls[0], "10.0.0.3:8080": urls[2]}
	for _, s := range f.servers {
		s.client.Transport = redirectTransport{destinations, http.DefaultTransport}
		s.peerClient = &http.Client{Transport: redirectTransport{destinations, http.DefaultTransport}, Timeout: time.Second}
	}
	b := Binding{Version: BindingVersion, Target: Target{Namespace: config.Namespace, Application: workloads[0], Proxy: workloads[1], Dependency: workloads[2], ApplicationIP: "10.0.0.2", DependencyIP: "10.0.0.3"}, Actor: config.Actor, ActorUID: config.ActorUID, ApproverKey: ap, InstallerKey: ip}
	b.Signature = Sign(BindingVersion, b, ik)
	f.proxy = f.servers[1]
	f.appURL = urls[0]
	f.proxyURL = urls[1]
	f.depURL = urls[2]
	f.plan = Plan{Version: PlanVersion, Run: ID(), Binding: b, DelayMS: 150, LifetimeMS: 1000, RequestMS: RequestMS, MaxApplicationMS: 500, Scenario: "delay"}
	if !f.plan.Valid() || f.proxy.bind(context.Background(), b) != nil {
		t.Fatal("valid native installation rejected")
	}
	return f
}
func (f *fixture) authorize(t testing.TB) Authorization {
	t.Helper()
	a, e := Approve(f.plan, f.plan.Digest(), f.approver, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func TestRealHTTPDependencyPathAndIndependentExpiry(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	client := HTTPClient()
	defer client.CloseIdleConnections()
	probe := func(endpoint string) (Reply, time.Duration) {
		t.Helper()
		nonce := ID()
		start := time.Now()
		r, e := Fetch(ctx, client, endpoint+"/value?nonce="+nonce)
		if e != nil || r.Nonce != nonce {
			t.Fatalf("actual HTTP probe: %v", e)
		}
		return r, time.Since(start)
	}
	baseline, _ := probe(f.appURL)
	if baseline.Proxy == nil || baseline.Proxy.Dependency == nil || baseline.Proxy.Dependency.Identity != f.servers[2].Identity {
		t.Fatal("application bypassed dependency")
	}
	a := f.authorize(t)
	first, e := f.proxy.mutate(ctx, NewCommand("apply", a, time.Now()))
	if e != nil {
		t.Fatal(e)
	}
	active, elapsed := probe(f.appURL)
	if active.Proxy == nil || active.Proxy.HoldNS < 100*time.Millisecond.Nanoseconds() || elapsed < 100*time.Millisecond {
		t.Fatal("outbound dependency delay not measured")
	}
	duplicate, e := f.proxy.mutate(ctx, NewCommand("apply", a, time.Now()))
	if e != nil || duplicate.DeadlineNS != first.DeadlineNS || duplicate.ApplyCount != 1 {
		t.Fatal("duplicate extended deadline")
	}
	// No runner or Remove exists during this wait; actual server timer expires.
	time.Sleep(1050 * time.Millisecond)
	recovered, _ := probe(f.appURL)
	state := f.proxy.snapshot(a.Grant.Invocation)
	if state.Active || state.Reason != "expired" || recovered.Proxy == nil || recovered.Proxy.State.Invocation != "" || recovered.Proxy.HoldNS != 0 {
		t.Fatal("expiry or real path recovery missing")
	}
	repeated, e := f.proxy.mutate(ctx, NewCommand("apply", a, time.Now()))
	if e != nil || repeated.Active || repeated.ApplyCount != 1 || repeated.DeadlineNS != first.DeadlineNS {
		t.Fatal("expired intervention renewed")
	}
}
func TestActuatorDeniesIdentityAndAuthoritySubstitution(t *testing.T) {
	for _, change := range []string{"cluster", "namespace", "app-pod", "proxy-pod", "boot", "container", "upstream", "app-image", "digest", "expired", "forged", "fixture-domain", "chaosmesh-domain", "latency", "deadline", "upstream-url"} {
		t.Run(change, func(t *testing.T) {
			f := newFixture(t)
			a := f.authorize(t)
			switch change {
			case "cluster":
				a.Grant.Plan.Binding.Target.Proxy.Process.ClusterUID = uid(90)
			case "namespace":
				a.Grant.Plan.Binding.Target.Proxy.Process.NamespaceUID = uid(90)
			case "app-pod":
				a.Grant.Plan.Binding.Target.Application.Process.PodUID = uid(90)
			case "proxy-pod":
				a.Grant.Plan.Binding.Target.Proxy.Process.PodUID = uid(90)
			case "boot":
				a.Grant.Plan.Binding.Target.Proxy.Process.Boot = ID()
			case "container":
				a.Grant.Plan.Binding.Target.Proxy.ContainerID = "containerd://" + ID()
			case "upstream":
				a.Grant.Plan.Binding.Target.Dependency.Process.Boot = ID()
			case "app-image":
				a.Grant.Plan.Binding.Target.Application.Image = "other@sha256:" + ID()
			case "digest":
				a.Grant.Digest = "sha256:" + ID()
			case "expired":
				a.Grant.Issued = time.Now().Add(-time.Minute)
				a.Grant.ApplyBefore = a.Grant.Issued.Add(20 * time.Second)
				a.Grant.CleanupBefore = a.Grant.Issued.Add(5 * time.Minute)
			case "forged":
				a.Grant.Signature = ID()
			case "fixture-domain":
				a.Grant.Version = "themis.kubernetes-execution-grant/v1alpha1"
			case "chaosmesh-domain":
				a.Grant.Version = "themis.chaosmesh-plan/v1alpha1"
			case "latency":
				a.Grant.Plan.DelayMS = MaxDelayMS + 1
			case "deadline":
				a.Grant.Plan.RequestMS = 0
			case "upstream-url":
				a.Grant.Plan.Binding.Target.DependencyIP = "example.com"
			}
			if change != "digest" && change != "forged" {
				a.Grant.Plan.Binding.Signature = ""
				a.Grant.Plan.Binding.Signature = Sign(BindingVersion, a.Grant.Plan.Binding, f.installer)
				a.Grant.Digest = a.Grant.Plan.Digest()
			}
			if change != "forged" {
				a.Grant.Signature = ""
				a.Grant.Signature = Sign(GrantVersion, a.Grant, f.approver)
			}
			if _, e := f.proxy.mutate(context.Background(), NewCommand("apply", a, time.Now())); e == nil {
				t.Fatal("unsafe authority admitted")
			}
			if f.proxy.snapshot(a.Grant.Invocation).Applied {
				t.Fatal("denied request mutated path")
			}
		})
	}
}
func TestRemovalFenceAndCorruptJournalCannotReactivate(t *testing.T) {
	f := newFixture(t)
	a := f.authorize(t)
	ctx := context.Background()
	if _, e := f.proxy.mutate(ctx, NewCommand("remove", a, time.Now())); e != nil {
		t.Fatal(e)
	}
	state, _ := f.proxy.mutate(ctx, NewCommand("apply", a, time.Now()))
	if state.Applied || state.Active {
		t.Fatal("pre-Apply fence bypassed")
	}
	a = f.authorize(t)
	if e := os.Truncate(f.proxy.journal.Name(), 1); e != nil {
		t.Fatal(e)
	}
	if _, e := f.proxy.mutate(ctx, NewCommand("apply", a, time.Now())); e == nil || !f.proxy.poisoned {
		t.Fatal("corrupt/torn journal accepted")
	}
}
func TestExpiryInterruptsInflightDelayAndRestartHasFreshAuthority(t *testing.T) {
	f := newFixture(t)
	a := f.authorize(t)
	state, e := f.proxy.mutate(context.Background(), NewCommand("apply", a, time.Now()))
	if e != nil {
		t.Fatal(e)
	}
	remaining := time.Duration(state.DeadlineNS) - time.Since(f.proxy.boot) - 30*time.Millisecond
	if remaining > 0 {
		time.Sleep(remaining)
	}
	r, e := Fetch(context.Background(), HTTPClient(), f.proxyURL+"/value?nonce="+ID())
	if e != nil || r.HoldNS > 100*time.Millisecond.Nanoseconds() {
		t.Fatal("in-flight hold outlived local expiry", e, r.HoldNS)
	}
	restarted, e := NewServer(f.proxy.config, "proxy", f.proxy.Identity.PodUID, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer restarted.Close()
	if restarted.Identity.Boot == f.proxy.Identity.Boot || restarted.Identity.Key == f.proxy.Identity.Key {
		t.Fatal("restart inherited identity")
	}
	if _, e = restarted.mutate(context.Background(), NewCommand("apply", a, time.Now())); e == nil {
		t.Fatal("stale boot authority accepted")
	}
}
func TestCanonicalBoundsAndFixedRoutes(t *testing.T) {
	f := newFixture(t)
	a := f.authorize(t)
	b := JSON(a.Grant)
	for _, bad := range [][]byte{[]byte(`{"version":null}`), append([]byte(`{"unknown":1,`), b[1:]...), []byte(strings.Replace(string(b), `"version":`, `"Version":`, 1)), []byte(strings.Repeat(" ", 1<<20+1))} {
		var g Grant
		if Decode(bad, &g) == nil {
			t.Fatal("ambiguous/unbounded input")
		}
	}
	for _, path := range []string{"/forward?url=http://example.com", "/value?nonce=" + ID() + "&upstream=other", "/control?nonce=" + ID()} {
		req := httptest.NewRequest("GET", path, nil)
		out := httptest.NewRecorder()
		f.proxy.ServeHTTP(out, req)
		if out.Code == 200 {
			t.Fatal("unapproved route accepted")
		}
	}
}
func FuzzNativeGrant(f *testing.F) {
	x := newFixture(f)
	a := x.authorize(f)
	f.Add(JSON(a.Grant))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 64<<10 {
			t.Skip()
		}
		var g Grant
		if Decode(b, &g) == nil {
			_ = g.Valid(time.Now(), true)
			_ = g.Plan.Valid()
		}
	})
}
