package safety

import (
	"bytes"
	"github.com/tamen25/themis/internal/contract"
	"github.com/tamen25/themis/internal/localpolicy"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/plan"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTrustedPolicyCannotBeRelaxedByContract(t *testing.T) {
	data, err := os.ReadFile("../../examples/owned-latency/experiment.yaml")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	actor := localstate.Actor{UID: "owner", Name: "operator", Host: "host"}
	id := plan.FixtureIdentity{Name: "demo", InstanceID: strings.Repeat("1", 64), ServiceID: strings.Repeat("2", 64), ProxyID: strings.Repeat("3", 64), EvidenceKey: strings.Repeat("4", 64), OwnerUID: actor.UID, Host: actor.Host, PID: 123, ServiceURL: "http://127.0.0.1:1234", ProxyURL: "http://127.0.0.1:1235", ControlURL: "http://127.0.0.1:1236", AdapterVersion: localpolicy.AdapterVersion, ExpiresAt: now.Add(time.Minute).UTC()}
	compile := func(data []byte, id plan.FixtureIdentity) plan.ExperimentPlan {
		t.Helper()
		c, err := contract.ParseExperiment(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		p, err := plan.CompileExperiment(c, id)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := compile(data, id)
	if err := Evaluate(p, actor, now); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string][2]string{"duration": {"duration: 2s", "duration: 4s"}, "latency": {"latency: 200ms", "latency: 400ms"}, "cleanup": {"timeout: 2s", "timeout: 3s"}, "budget": {"maxDuration: 10s", "maxDuration: 20s"}, "request rate": {"samples: 4", "samples: 20"}} {
		t.Run(name, func(t *testing.T) {
			changed := []byte(strings.Replace(string(data), change[0], change[1], 1))
			if err := Evaluate(compile(changed, id), actor, now); err == nil {
				t.Fatal("unsafe contract admitted")
			}
		})
	}
	wrongOwner := actor
	wrongOwner.UID = "other"
	if Evaluate(p, wrongOwner, now) == nil {
		t.Fatal("another owner admitted")
	}
	if Evaluate(p, actor, id.ExpiresAt) == nil {
		t.Fatal("expired fixture admitted")
	}
	a := Authorization{ID: strings.Repeat("5", 64), PlanDigest: p.Digest(), Actor: actor, FixtureID: id.InstanceID, ServiceID: id.ServiceID, ProxyID: id.ProxyID, Action: "http.response-latency", AdapterVersion: id.AdapterVersion, IssuedAt: now, ExpiresAt: now.Add(10 * time.Second)}
	if err := CheckAuthorization(a, p, actor, now); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Authorization){"stale": func(a *Authorization) { a.ExpiresAt = now }, "digest": func(a *Authorization) { a.PlanDigest = "sha256:changed" }, "target": func(a *Authorization) { a.FixtureID = id.ServiceID }, "adapter": func(a *Authorization) { a.AdapterVersion = "other" }, "actor": func(a *Authorization) { a.Actor.Name = "other" }, "future": func(a *Authorization) { a.IssuedAt = now.Add(time.Second) }} {
		t.Run(name, func(t *testing.T) {
			bad := a
			mutate(&bad)
			if CheckAuthorization(bad, p, actor, now) == nil {
				t.Fatal("invalid authorization accepted")
			}
		})
	}
	for _, endpoint := range []string{"http://localhost:80", "http://127.0.0.2:80", "http://[::1]:80", "http://127.0.0.1:80/path", "http://127.0.0.1:80?x", "https://127.0.0.1:80", "http://user@127.0.0.1:80"} {
		bad := id
		bad.ProxyURL = endpoint
		if plan.ValidateFixture(bad) == nil {
			t.Fatalf("unsafe endpoint %s", endpoint)
		}
	}
	bad := id
	bad.AdapterVersion = "untrusted/v1"
	if plan.ValidateFixture(bad) == nil {
		t.Fatal("wrong adapter admitted")
	}
	copy := p.JSON()
	copy[0] = '!'
	snapshot := p.Snapshot()
	snapshot.Target.InstanceID = "changed"
	if p.Snapshot().Target != id || p.Digest() == "" {
		t.Fatal("mutable plan")
	}
	again := compile(data, id)
	if !bytes.Equal(p.JSON(), again.JSON()) || p.Digest() != again.Digest() {
		t.Fatal("nondeterministic plan")
	}
}
