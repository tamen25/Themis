package kubefault

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestFixtureChildProcess(t *testing.T) {
	if os.Getenv("THEMIS_TEST_FIXTURE_CHILD") != "1" {
		return
	}
	var config Config
	if json.NewDecoder(os.Stdin).Decode(&config) != nil {
		os.Exit(21)
	}
	s, err := NewServer(config, "test-pod", "44444444-4444-4444-4444-444444444444")
	if err != nil {
		os.Exit(22)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		os.Exit(23)
	}
	_ = json.NewEncoder(os.Stdout).Encode(struct {
		Address  string
		Identity Identity
	}{listener.Addr().String(), s.Identity})
	_ = s.Serve(context.Background(), listener)
	os.Exit(0)
}

func TestActualProxyProcessDeathAndReplacementCannotProveRecovery(t *testing.T) {
	original, _, template, key := setup(t, "healthy")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFixtureChildProcess$")
	cmd.Env = append(os.Environ(), "THEMIS_TEST_FIXTURE_CHILD=1")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	dead := false
	defer func() {
		if !dead {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	if err = json.NewEncoder(input).Encode(original.config); err != nil {
		t.Fatal(err)
	}
	_ = input.Close()
	var startup struct {
		Address  string
		Identity Identity
	}
	if err = json.NewDecoder(output).Decode(&startup); err != nil {
		t.Fatal(err)
	}
	p := template.Grant.Plan
	p.Target.Fixture = startup.Identity
	a, err := Approve(p, p.Digest(), key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient("http://" + startup.Address)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	status, err := c.Control(ctx, a, "apply")
	if err != nil || !status.Active {
		t.Fatal("child proxy did not apply", err)
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	dead = true
	if err == nil {
		t.Fatal("actual fixture process was not terminated")
	}
	if _, _, err = c.Data(ctx, "application", RandomID()); err == nil {
		t.Fatal("dead proxy was treated as recovered application")
	}
	// Reuse the exact endpoint and Pod UID with a fresh boot key. Copied grants
	// must fail even before considering a different Kubernetes Pod UID.
	replacement, err := NewServer(original.config, "test-pod", startup.Identity.PodUID)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", startup.Address)
	if err != nil {
		t.Fatal(err)
	}
	replacementCtx, stop := context.WithCancel(context.Background())
	defer stop()
	go func() { _ = replacement.Serve(replacementCtx, listener) }()
	if _, err = c.Resolve(ctx, &startup.Identity); err == nil {
		t.Fatal("replacement endpoint accepted as original fixture")
	}
	if _, err = c.Control(ctx, a, "apply"); err == nil {
		t.Fatal("copied grant applied against replacement boot")
	}
	replacement.mu.Lock()
	defer replacement.mu.Unlock()
	if len(replacement.invocations) != 0 {
		t.Fatal("replacement received an application")
	}
}
