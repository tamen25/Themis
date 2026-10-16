package kubefault

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func setup(t *testing.T, scenario string) (*Server, *Client, Authorization, ed25519.PrivateKey) {
	t.Helper()
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	cfg := Config{"11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", hex.EncodeToString(public), Actor{OperatorName, "33333333-3333-3333-3333-333333333333"}}
	s, err := NewServer(cfg, "latency-fixture-abcdef-12345", "44444444-4444-4444-4444-444444444444")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.Serve(ctx, listener) }()
	c, err := NewClient("http://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	p := Plan{Version: PlanVersion, Policy: PolicyVersion, RunName: "latency-request", RunUID: "77777777-7777-7777-7777-777777777777", RunGeneration: 1, PreviewDigest: "sha256:" + strings.Repeat("a", 64), Operator: cfg.Operator, Target: Target{Namespace: "themis-test", Fixture: s.Identity, DeploymentName: "latency-fixture", DeploymentUID: "55555555-5555-5555-5555-555555555555", DeploymentGeneration: 1, TemplateDigest: "sha256:" + strings.Repeat("b", 64), ReplicaSetName: "latency-fixture-abcdef", ReplicaSetUID: "66666666-6666-6666-6666-666666666666", PodSpecDigest: "sha256:" + strings.Repeat("c", 64), ContainerID: "containerd://" + strings.Repeat("d", 64), Image: "example.invalid/fixture@sha256:" + strings.Repeat("e", 64), ImageID: "sha256:" + strings.Repeat("e", 64)}, Contract: Contract{"themis.kubernetes-experiment-contract/v1alpha1", "latency", 3, 3, "0"}, Fault: Fault{"http.response-latency", 200, 1500}, Scenario: scenario}
	a, err := Approve(p, p.Digest(), key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return s, c, a, key
}

func TestBoundedDelayDuplicateApplyAndIndependentExpiry(t *testing.T) {
	_, c, a, _ := setup(t, "healthy")
	ctx := context.Background()
	if _, err := c.Resolve(ctx, &a.Grant.Plan.Target.Fixture); err != nil {
		t.Fatal(err)
	}
	first, err := c.Control(ctx, a, "apply")
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"direct", "proxy", "application"} {
		id := RandomID()
		start := time.Now()
		body, code, err := c.Data(ctx, kind, id)
		elapsed := time.Since(start)
		if err != nil || !VerifyData(body, a.Grant.Plan.Target.Fixture, id, kind, code) || code != 200 {
			t.Fatalf("invalid independent %s probe: %v", kind, err)
		}
		if kind == "proxy" && elapsed < 150*time.Millisecond {
			t.Fatal("actual HTTP proxy did not delay")
		}
		if kind == "application" && !body.Degraded {
			t.Fatal("application did not exercise timed-out proxy/fallback path")
		}
	}
	duplicate, err := c.Control(ctx, a, "apply")
	if err != nil || duplicate.ApplyCount != 1 || duplicate.AppliedAt != first.AppliedAt || duplicate.ExpiresAt != first.ExpiresAt {
		t.Fatal("duplicate Apply changed the original effect/deadline")
	}
	time.Sleep(time.Until(first.ExpiresAt) + 30*time.Millisecond)
	status, err := c.Control(ctx, a, "status")
	if err != nil || status.Active || status.Reason != "expired" {
		t.Fatalf("independent expiry failed: %+v %v", status, err)
	}
	after, err := c.Control(ctx, a, "apply")
	if err != nil || after.Active || after.ApplyCount != 1 {
		t.Fatal("duplicate reactivated an expired invocation")
	}
}

func TestNoopAndCleanupDenial(t *testing.T) {
	for _, scenario := range []string{"noop", "cleanup-denied", "buggy"} {
		t.Run(scenario, func(t *testing.T) {
			_, c, a, _ := setup(t, scenario)
			status, err := c.Control(context.Background(), a, "apply")
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			body, code, err := c.Data(context.Background(), "proxy", RandomID())
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "noop" && (time.Since(start) > 150*time.Millisecond || code != 200 || body.InvocationID != a.Grant.InvocationID) {
				t.Fatal("no-op fixture unexpectedly delayed")
			}
			if scenario == "buggy" {
				_, code, err = c.Data(context.Background(), "application", RandomID())
				if err != nil || code != 503 {
					t.Fatal("buggy application did not fail under real proxy delay")
				}
			}
			_, err = c.Control(context.Background(), a, "remove")
			if scenario == "cleanup-denied" {
				var denied *Denial
				if !errors.As(err, &denied) || denied.Code != "SyntheticCleanupDenied" {
					t.Fatal("negative cleanup did not deny")
				}
				time.Sleep(time.Until(status.ExpiresAt) + 30*time.Millisecond)
				status, err = c.Control(context.Background(), a, "remove")
				if err != nil || status.Active {
					t.Fatal("independent expiry/repeated cleanup failed")
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAuthorizationAndIdentityNegatives(t *testing.T) {
	s, c, original, key := setup(t, "healthy")
	for _, name := range []string{"cluster", "namespace", "pod", "boot", "plan", "fault", "duration", "stale", "forged", "actor", "apply-key", "cleanup-key"} {
		t.Run(name, func(t *testing.T) {
			a := original
			switch name {
			case "cluster":
				a.Grant.Plan.Target.Fixture.ClusterUID = "99999999-9999-9999-9999-999999999999"
			case "namespace":
				a.Grant.Plan.Target.Fixture.NamespaceUID = "99999999-9999-9999-9999-999999999999"
			case "pod":
				a.Grant.Plan.Target.Fixture.PodUID = "99999999-9999-9999-9999-999999999999"
			case "boot":
				a.Grant.Plan.Target.Fixture.InstanceID = RandomID()
			case "plan":
				a.Grant.Plan.Contract.Name = "modified-after-approval"
			case "fault":
				a.Grant.Plan.Fault.Type = "pod-delete"
			case "duration":
				a.Grant.Plan.Fault.DurationMS = 60000
			case "stale":
				a.Grant.IssuedAt = time.Now().Add(-time.Minute)
				a.Grant.ApplyBefore = a.Grant.IssuedAt.Add(20 * time.Second)
				a.Grant.CleanupBefore = a.Grant.IssuedAt.Add(90 * time.Second)
			case "forged":
				a.Grant.Signature = strings.Repeat("0", 128)
			case "actor":
				a.Grant.Plan.Operator.Name = "cluster-admin"
			case "apply-key":
				a.InvocationKey = a.CleanupKey
			case "cleanup-key":
				a.CleanupKey = a.InvocationKey
			}
			if name != "plan" && name != "forged" && name != "apply-key" && name != "cleanup-key" {
				a.Grant.PlanDigest = a.Grant.Plan.Digest()
				a.Grant.Signature = ""
				a.Grant.Signature = Sign(GrantVersion, a.Grant, key)
			}
			action := "apply"
			if name == "cleanup-key" {
				action = "remove"
			}
			if _, err := c.Control(context.Background(), a, action); !errors.Is(err, ErrDenied) {
				t.Fatal("invalid capability accepted", err)
			}
		})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.invocations) != 0 {
		t.Fatal("denied requests reached Apply")
	}
}

type lostAcknowledgement struct {
	base    http.RoundTripper
	dropped bool
}

func (r *lostAcknowledgement) RoundTrip(q *http.Request) (*http.Response, error) {
	response, err := r.base.RoundTrip(q)
	if err == nil && q.URL.Path == "/control" && !r.dropped {
		r.dropped = true
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		return nil, io.ErrUnexpectedEOF
	}
	return response, err
}
func TestRealHTTPApplyAcknowledgementLost(t *testing.T) {
	_, c, a, _ := setup(t, "healthy")
	c.http.Transport = &lostAcknowledgement{base: c.http.Transport}
	if _, err := c.Control(context.Background(), a, "apply"); err == nil {
		t.Fatal("acknowledgement was not lost")
	}
	status, err := c.Control(context.Background(), a, "status")
	if err != nil || !status.Active || status.ApplyCount != 1 {
		t.Fatal("lost acknowledgement masked an actually applied fault")
	}
	before := status.ExpiresAt
	status, err = c.Control(context.Background(), a, "apply")
	if err != nil || status.ExpiresAt != before || status.ApplyCount != 1 {
		t.Fatal("ambiguous retry extended the fault")
	}
}

func TestStrictProtocolAndFencedApply(t *testing.T) {
	for _, data := range []string{`{"version":"x","fault":"x"}`, `{"version":"x","Version":"y"}`, `{"Version":"x"}`, `{} {}`, strings.Repeat(" ", 65537)} {
		var p Plan
		if Decode([]byte(data), &p) == nil {
			t.Fatal("unsupported protocol accepted")
		}
	}
	_, c, a, _ := setup(t, "healthy")
	if _, err := c.Control(context.Background(), a, "remove"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Control(context.Background(), a, "apply"); !errors.Is(err, ErrDenied) {
		t.Fatal("cleanup fence permitted later Apply")
	}
}

func TestDamagedCommandKeysAreRejectedBeforeExecution(t *testing.T) {
	_, _, a, _ := setup(t, "healthy")
	if err := a.CheckKeys(); err != nil {
		t.Fatal(err)
	}
	for _, which := range []string{"missing cleanup", "wrong cleanup", "wrong invocation", "damaged seed"} {
		broken := a
		switch which {
		case "missing cleanup":
			broken.CleanupKey = ""
		case "wrong cleanup":
			broken.CleanupKey = a.InvocationKey
		case "wrong invocation":
			broken.InvocationKey = a.CleanupKey
		case "damaged seed":
			broken.InvocationKey = strings.Repeat("0", 64) + a.InvocationKey[64:]
		}
		if err := broken.CheckKeys(); err == nil {
			t.Fatal("damaged command capability accepted", which)
		}
	}
}
