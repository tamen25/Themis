package kubeexperiment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

func localSession(t *testing.T, scenario string) (kubefault.Plan, *kubefault.Client, kubefault.Authorization) {
	t.Helper()
	_, p := clusterFixture(t)
	p.Scenario = scenario
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	s, err := kubefault.NewServer(kubefault.Config{ClusterUID: p.Target.Fixture.ClusterUID, NamespaceUID: p.Target.Fixture.NamespaceUID, ApproverKey: hex.EncodeToString(public), Operator: p.Operator}, p.Target.Fixture.PodName, p.Target.Fixture.PodUID)
	if err != nil {
		t.Fatal(err)
	}
	p.Target.Fixture = s.Identity
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.Serve(ctx, listener) }()
	c, err := kubefault.NewClient("http://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	a, err := kubefault.Approve(p, p.Digest(), key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return p, c, a
}

func measuredEvents(t *testing.T, scenario string) ([]Event, string) {
	t.Helper()
	p, c, a := localSession(t, scenario)
	ctx := context.Background()
	dir, err := localstate.CreateDirectory(filepath.Join(t.TempDir(), "private"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "events.jsonl")
	f, err := localstate.OpenNew(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	j := &journal{file: f, epoch: time.Now()}
	summary := publicAuthorization(a.Grant)
	appendEvent := func(e Event) {
		t.Helper()
		if err := j.append(e); err != nil {
			t.Fatal(err)
		}
	}
	appendEvent(Event{Type: "START", Plan: &p, Authorization: &summary})
	if err = collect(ctx, c, j, p, "baseline"); err != nil {
		t.Fatal(err)
	}
	appendEvent(Event{Type: "INTENT"})
	status, err := c.Control(ctx, a, "apply")
	if err != nil {
		t.Fatal(err)
	}
	appendEvent(Event{Type: "APPLIED", Status: &status})
	if err = collect(ctx, c, j, p, "intervention"); err != nil {
		t.Fatal(err)
	}
	status, err = c.Control(ctx, a, "remove")
	if scenario == "cleanup-denied" {
		if err == nil {
			t.Fatal("actual cleanup-denied mode did not deny")
		}
		appendEvent(Event{Type: "FINAL", Execution: string(result.CleanupPending)})
	} else {
		if err != nil {
			t.Fatal(err)
		}
		appendEvent(Event{Type: "REMOVED", Status: &status})
		if err = collect(ctx, c, j, p, "recovery"); err != nil {
			t.Fatal(err)
		}
		appendEvent(Event{Type: "FINAL", Execution: string(result.Succeeded)})
	}
	return j.events, path
}

func TestMeasuredLocalProtocolVerdictsAndUnsignedReplay(t *testing.T) {
	for _, scenario := range []string{"healthy", "buggy", "noop", "cleanup-denied"} {
		t.Run(scenario, func(t *testing.T) {
			events, path := measuredEvents(t, scenario)
			r := assess(events, true)
			want := map[string]result.Verdict{"healthy": result.Pass, "buggy": result.Fail, "noop": result.Inconclusive, "cleanup-denied": result.Inconclusive}[scenario]
			if r.Verdict != want {
				t.Fatalf("actual local HTTP fixture verdict: got %s want %s: %+v", r.Verdict, want, r)
			}
			if scenario == "cleanup-denied" && r.Execution != result.CleanupPending {
				t.Fatal("unresolved cleanup hidden")
			}
			replay, err := Replay(path)
			if err != nil {
				t.Fatal(err)
			}
			if replay.Verdict == result.Pass || replay.Authorized {
				t.Fatal("unsigned journal independently established PASS/authorization")
			}
			if replay.CandidateVerdict != r.CandidateVerdict {
				t.Fatal("replay predicates differ from live observations")
			}
		})
	}
}

func TestMissingTimingIdentityAndForgedResponseNeverPass(t *testing.T) {
	events, _ := measuredEvents(t, "healthy")
	for _, name := range []string{"missing observation", "forged response", "wrong instance", "negative timing", "duplicate request", "missing cleanup", "ambiguous Apply", "unsupported verdict"} {
		t.Run(name, func(t *testing.T) {
			data, _ := json.Marshal(events)
			var changed []Event
			_ = json.Unmarshal(data, &changed)
			switch name {
			case "missing observation":
				for i, e := range changed {
					if e.Observation != nil && e.Observation.Phase == "intervention" {
						changed = append(changed[:i], changed[i+1:]...)
						break
					}
				}
			case "forged response":
				for i := range changed {
					if changed[i].Observation != nil {
						changed[i].Observation.Probes[1].Response.Signature = "bad"
						break
					}
				}
			case "wrong instance":
				changed[0].Plan.Target.Fixture.InstanceID = kubefault.RandomID()
			case "negative timing":
				for i := range changed {
					if changed[i].Observation != nil {
						changed[i].Observation.Probes[1].CompletedNS = -1
						break
					}
				}
			case "duplicate request":
				id := ""
				for i := range changed {
					if changed[i].Observation != nil {
						if id == "" {
							id = changed[i].Observation.RequestID
						} else {
							changed[i].Observation.RequestID = id
							break
						}
					}
				}
			case "missing cleanup":
				for i, e := range changed {
					if e.Type == "REMOVED" {
						changed = append(changed[:i], changed[i+1:]...)
						break
					}
				}
			case "ambiguous Apply":
				for i, e := range changed {
					if e.Type == "APPLIED" {
						changed = append(changed[:i], changed[i+1:]...)
						break
					}
				}
			case "unsupported verdict":
				changed[len(changed)-1].Execution = "PASS"
			}
			if r := assess(changed, true); r.Verdict == result.Pass {
				t.Fatal("adversarial evidence yielded PASS")
			}
		})
	}
}

func TestJournalCorruptionTornWritesAndUnsupportedFields(t *testing.T) {
	_, path := measuredEvents(t, "healthy")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"torn", "corrupt", "extra PASS field"} {
		t.Run(name, func(t *testing.T) {
			copy := append([]byte{}, data...)
			switch name {
			case "torn":
				copy = copy[:len(copy)-1]
			case "corrupt":
				copy[40] ^= 1
			case "extra PASS field":
				copy = append([]byte(`{"verdict":"PASS",`), copy[1:]...)
			}
			bad := filepath.Join(t.TempDir(), "events.jsonl")
			if err := os.WriteFile(bad, copy, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadJournal(bad); err == nil {
				t.Fatal("corrupt/unsupported journal accepted")
			}
		})
	}
}

func TestNoopCannotBeConfirmedBySlowClientTimingAlone(t *testing.T) {
	events, _ := measuredEvents(t, "noop")
	p := *events[0].Plan
	observations := []Observation{}
	for _, e := range events {
		if e.Observation != nil && e.Observation.Phase == "intervention" {
			o := *e.Observation
			o.Probes = append([]Probe{}, o.Probes...)
			direct := o.Probes[0].CompletedNS - o.Probes[0].StartedNS
			o.Probes[1].CompletedNS = o.Probes[1].StartedNS + direct + int64(p.Fault.DelayMS)*1000000
			observations = append(observations, o)
		}
	}
	if confirmedLatency(p, events[0].Authorization.InvocationID, observations) {
		t.Fatal("slow/forged client timing elevated an authentic no-op response to intervention proof")
	}
}

func TestCredibleApplicationFailureSurvivesMissingSamples(t *testing.T) {
	events, _ := measuredEvents(t, "buggy")
	partial := []Event{}
	for _, e := range events {
		if e.Observation != nil && e.Observation.Phase == "intervention" && e.Observation.Index > 0 {
			continue
		}
		partial = append(partial, e)
	}
	if r := assess(partial, true); r.Verdict != result.Fail {
		t.Fatalf("credible signed 503 was hidden by missing samples: got %s want FAIL", r.Verdict)
	}
}

func FuzzKubernetesJournalNeverTrustsPASS(f *testing.F) {
	f.Add([]byte("{}\n"))
	f.Add([]byte("{\"verdict\":\"PASS\"}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			t.Skip()
		}
		var event Event
		if kubefault.Decode(data, &event) != nil {
			return
		}
		r := assess([]Event{event}, false)
		if r.Verdict == result.Pass || r.Authorized {
			t.Fatal("untrusted event established PASS")
		}
	})
}
