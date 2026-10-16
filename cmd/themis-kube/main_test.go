package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tamen25/themis/internal/localstate"
)

func TestCLIRequiresExplicitCompleteCommands(t *testing.T) {
	for _, test := range []struct {
		args []string
		exit int
	}{{nil, 4}, {[]string{"unknown"}, 4}, {[]string{"init", "--help"}, 0}, {[]string{"plan", "--help"}, 0}, {[]string{"approve"}, 4}, {[]string{"run"}, 4}, {[]string{"reconcile"}, 4}, {[]string{"status"}, 4}, {[]string{"replay"}, 4}, {[]string{"plan", "--force"}, 4}, {[]string{"plan", "unexpected"}, 4}} {
		var out, diagnostics bytes.Buffer
		if got := run(context.Background(), test.args, &out, &diagnostics); got != test.exit {
			t.Fatalf("%v exit=%d want=%d", test.args, got, test.exit)
		}
	}
}

func TestSetupKeyIsPrivateAndCannotBeOverwritten(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	var out, diagnostics bytes.Buffer
	if got := run(context.Background(), []string{"init", "--state", dir}, &out, &diagnostics); got != 0 {
		t.Fatal(got, diagnostics.String())
	}
	var public struct {
		Key string `json:"approverKey"`
	}
	if json.Unmarshal(out.Bytes(), &public) != nil {
		t.Fatal("invalid setup output")
	}
	var signing struct {
		Key string `json:"privateKey"`
	}
	path := filepath.Join(dir, "approver-key.json")
	if err := localstate.Read(path, &signing); err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(signing.Key)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		t.Fatal("invalid signing key")
	}
	if hex.EncodeToString(ed25519.PrivateKey(key).Public().(ed25519.PublicKey)) != public.Key || strings.Contains(out.String(), signing.Key) {
		t.Fatal("private key exposure or mismatched public key")
	}
	before, _ := os.ReadFile(path)
	out.Reset()
	diagnostics.Reset()
	if got := run(context.Background(), []string{"init", "--state", dir}, &out, &diagnostics); got != 6 {
		t.Fatal("setup overwrote existing signing authority")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("existing authority was overwritten")
	}
}

func TestUnsupportedPlanAndClaimedPASSAreRejected(t *testing.T) {
	for _, value := range []string{`{"digest":"bad","plan":{}}`, `{"digest":"bad","plan":{},"executionAllowed":true}`, strings.Repeat(" ", 65537)} {
		path := filepath.Join(t.TempDir(), "plan.json")
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readPlan(path); err == nil {
			t.Fatal("unsupported plan accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "events.jsonl")
	_ = os.WriteFile(path, []byte("{\"verdict\":\"PASS\"}\n"), 0600)
	var out, diagnostics bytes.Buffer
	if code := run(context.Background(), []string{"replay", "-f", path}, &out, &diagnostics); code != 6 || out.Len() != 0 {
		t.Fatal("untrusted PASS claim accepted")
	}
}
