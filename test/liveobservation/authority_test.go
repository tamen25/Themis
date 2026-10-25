package liveobservation_test

import (
	"encoding/hex"
	"errors"
	"github.com/tamen25/themis/internal/kubeexperiment"
	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/localstate"
	"path/filepath"
	"testing"
)

func TestOwnedKindWitnessKeyHasNoFaultAuthority(t *testing.T) {
	h := newHarness(t)
	cluster, e := kubeexperiment.Open(h.ctx, h.state)
	if e != nil {
		t.Fatal(e)
	}
	plan, e := cluster.Plan(h.ctx, "latency-request", "healthy")
	if e != nil {
		t.Fatal(e)
	}
	auth, e := cluster.Approve(h.ctx, plan, plan.Digest())
	if e != nil {
		t.Fatal(e)
	}
	session, e := cluster.Connect(h.ctx, plan)
	if e != nil {
		t.Fatal(e)
	}
	defer session.Close()
	// This is an operator test of the fixture boundary. The production observer
	// never receives this authorization or invokes the control endpoint.
	defer func() { _, _ = session.Client.Control(h.ctx, auth, "remove") }()
	var witnessKey struct {
		Version    string `json:"version"`
		Witness    string `json:"witness"`
		PrivateKey []byte `json:"privateKey"`
	}
	if e = localstate.Read(filepath.Join(h.keyDir, "witness-key.json"), &witnessKey); e != nil {
		t.Fatal(e)
	}
	forged := auth
	forged.InvocationKey = hex.EncodeToString(witnessKey.PrivateKey)
	_, denied := session.Client.Control(h.ctx, forged, "apply")
	if !errors.Is(denied, kubefault.ErrDenied) {
		t.Fatal("witness key obtained fault authority", denied)
	}
	state, e := session.Client.Control(h.ctx, auth, "status")
	if e != nil || state.Active || state.Applied || state.ApplyCount != 0 {
		t.Fatal("denied witness caused a fault", e)
	}
	h.save("J-witness-control-denial.json", struct {
		Denial string           `json:"denial"`
		Status kubefault.Status `json:"status"`
	}{denied.Error(), state})
	t.Log("REAL KIND witness key rejected as Apply authority; fixture independently reported zero Apply")
}
