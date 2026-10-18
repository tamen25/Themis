package evidencecli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tamen25/themis/pkg/evidence"
	obs "github.com/tamen25/themis/pkg/nativeobservation"
)

func TestNativeUnsupportedMappingKeepsUnsupportedExit(t *testing.T) {
	original, err := os.ReadFile("../evidencesource/testdata/native-pass/bundle.zip")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 18, 15, 0, 0, 0, time.UTC)
	opened, err := evidence.Verify(bytes.NewReader(original), int64(len(original)), nil, now)
	if err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := opened.Manifest
	m.Source.Mapping = obs.Engine + "/v999"
	m.Publisher = evidence.Publisher{Name: "controlled-unsupported-publisher", KeyID: evidence.Fingerprint(pub), PublicKey: pub, Algorithm: evidence.Algorithm, Domain: evidence.Domain}
	bundle, err := evidence.Sign(m, opened.Artifacts, key)
	if err != nil {
		t.Fatal(err)
	}
	policy := evidence.Policy{Version: evidence.PolicyVersion, Keys: []evidence.TrustedKey{{Publisher: m.Publisher.Name, KeyID: m.Publisher.KeyID, PublicKey: pub, Algorithm: evidence.Algorithm, Engines: []string{obs.Engine}, NotBefore: now.Add(-time.Hour).Format(time.RFC3339Nano), NotAfter: now.Add(time.Hour).Format(time.RFC3339Nano)}}}
	dir := t.TempDir()
	path, policyPath := filepath.Join(dir, "unsupported.zip"), filepath.Join(dir, "publisher-policy.json")
	if os.WriteFile(path, bundle, 0600) != nil {
		t.Fatal("write public bundle")
	}
	raw, _ := json.Marshal(policy)
	if os.WriteFile(policyPath, raw, 0600) != nil {
		t.Fatal("write external public policy")
	}
	var out bytes.Buffer
	code := run([]string{"verify", "--bundle", path, "--trust-policy", policyPath}, &out, now)
	t.Logf("ACTUAL SIGNED BUNDLE CLI unknown native mapping exit=%d output=%s", code, out.String())
	if code != 7 {
		t.Fatal("unsupported mapping was misclassified as an unknown witness")
	}
}

func TestNativeVerificationUsesOneExternalPolicySnapshotDuringRotation(t *testing.T) {
	root := "../evidencesource/testdata/native-pass"
	publisherBytes, err := os.ReadFile(filepath.Join(root, "publisher-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	witnessBytes, err := os.ReadFile(filepath.Join(root, "witness-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := evidence.ReadPolicy(publisherBytes)
	if err != nil {
		t.Fatal(err)
	}
	w, err := obs.ReadPolicy(witnessBytes)
	if err != nil {
		t.Fatal(err)
	}
	begin, _ := obs.UTC(w.Keys[0].NotBefore)
	now := begin.Add(time.Hour + time.Minute)
	p.Keys[0].Revoked = true
	revokedBytes, _ := json.Marshal(p)
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "current-policy.json")
	verify := func() int {
		var out bytes.Buffer
		return run([]string{"verify", "--bundle", filepath.Join(root, "bundle.zip"), "--trust-policy", policyPath, "--witness-policy", filepath.Join(root, "witness-policy.json")}, &out, now)
	}
	for _, tc := range []struct {
		raw  []byte
		want int
	}{{publisherBytes, 0}, {revokedBytes, 5}} {
		if os.WriteFile(policyPath, tc.raw, 0600) != nil || verify() != tc.want {
			t.Fatal("independently selected original/revoked policy did not govern verification")
		}
	}
	var workers sync.WaitGroup
	workers.Add(1)
	done := make(chan struct{})
	go func() {
		defer workers.Done()
		for i := range 40 {
			raw := publisherBytes
			if i%2 == 0 {
				raw = revokedBytes
			}
			temp := filepath.Join(dir, "next-policy.json")
			if err := os.WriteFile(temp, raw, 0600); err != nil {
				t.Error(err)
				break
			}
			// Actual same-directory rename publishes a complete new policy.
			// Windows may deny replacement while another handle is open. That
			// leaves the previous complete snapshot authoritative for that read.
			if err := os.Rename(temp, policyPath); err != nil {
				t.Log("OS denied concurrent policy replacement:", err)
			}
		}
		close(done)
	}()
	results := make(chan int, 32)
	for range 32 {
		workers.Add(1)
		go func() { defer workers.Done(); results <- verify() }()
	}
	workers.Wait()
	<-done
	close(results)
	counts := map[int]int{}
	for code := range results {
		if code != 0 && code != 5 {
			t.Fatal("rotation caused a mixed policy or unexpected outcome", code)
		}
		counts[code]++
	}
	t.Logf("ACTUAL FILE CONCURRENCY 32 native verifications during 40 external policy replacement attempts: exits=%v; each invocation uses its independently decoded snapshot, no policy cache", counts)
}
