package livewitness

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/pkg/evidence"
	obs "github.com/tamen25/themis/pkg/liveobservation"
)

type crashConfig struct {
	Registration obs.Registration `json:"registration"`
	Key          []byte           `json:"key"`
}

func crashFixture(t *testing.T) crashConfig {
	t.Helper()
	raw, e := os.ReadFile(filepath.Join("..", "evidencesource", "testdata", "witness-healthy", "artifacts", "witness-registration.json"))
	if e != nil {
		t.Fatal(e)
	}
	var r obs.Registration
	if obs.Decode(raw, &r) != nil {
		t.Fatal("public fixture")
	}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	r.Witness = "crash-test-witness"
	r.PublicKey = pub
	r.KeyID = evidence.Fingerprint(pub)
	r.Session = localstate.RandomID()
	now := time.Now()
	r.NotBefore = now.UTC().Format(time.RFC3339Nano)
	r.NotAfter = now.Add(20 * time.Second).UTC().Format(time.RFC3339Nano)
	r = obs.SignRegistration(r, key)
	if r.Validate() != nil {
		t.Fatal("crash test registration")
	}
	return crashConfig{r, key}
}
func TestWitnessTornWriteChild(t *testing.T) {
	directory := os.Getenv("THEMIS_WITNESS_TORN_CHILD")
	if directory == "" {
		t.Skip("child-only witness write checkpoint")
	}
	var cfg crashConfig
	if e := localstate.Read(filepath.Join(directory, "private-config.json"), &cfg); e != nil {
		t.Fatal(e)
	}
	file, e := localstate.OpenNew(filepath.Join(directory, "observations.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	j := &journal{file: file, reg: cfg.Registration, key: cfg.Key, epoch: time.Now(), process: localstate.RandomID()}
	start, e := j.append("START", "", "LIVE_SESSION_STARTED", nil, "", -1)
	if e != nil {
		t.Fatal(e)
	}
	sample := start
	sample.Type = "SAMPLE"
	sample.Sequence = 1
	sample.Previous = start.Hash
	sample.Nonce = localstate.RandomID()
	sample = obs.Seal(sample, cfg.Key)
	raw, _ := json.Marshal(sample)
	if _, e = file.Write(raw[:len(raw)/2]); e != nil {
		t.Fatal(e)
	}
	if e = file.Sync(); e != nil {
		t.Fatal(e)
	}
	if e = localstate.WriteNew(filepath.Join(directory, "half-written.json"), struct {
		Reached bool `json:"reached"`
	}{true}); e != nil {
		t.Fatal(e)
	}
	time.Sleep(time.Minute)
	t.Fatal("parent failed to terminate actual child")
}
func TestActualWitnessDeathDuringJournalWrite(t *testing.T) {
	directory, e := localstate.CreateDirectory(filepath.Join(t.TempDir(), "private"))
	if e != nil {
		t.Fatal(e)
	}
	cfg := crashFixture(t)
	if e = localstate.WriteNew(filepath.Join(directory, "private-config.json"), cfg); e != nil {
		t.Fatal(e)
	}
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(executable, "-test.run=^TestWitnessTornWriteChild$", "-test.v")
	cmd.Env = append(os.Environ(), "THEMIS_WITNESS_TORN_CHILD="+directory)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	ready := false
	for until := time.Now().Add(10 * time.Second); time.Now().Before(until); time.Sleep(5 * time.Millisecond) {
		if _, e = os.Stat(filepath.Join(directory, "half-written.json")); e == nil {
			ready = true
			break
		}
	}
	if !ready {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		waited = true
		t.Fatal("child did not reach actual partial-write checkpoint", output.String())
	}
	if e = cmd.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	e = cmd.Wait()
	waited = true
	if e == nil {
		t.Fatal("terminated child unexpectedly succeeded")
	}
	raw, e := os.ReadFile(filepath.Join(directory, "observations.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	f, records := obs.Analyze(cfg.Registration, raw, nil, time.Now())
	if f.Complete || f.Status == "OBSERVED_AND_CORRELATED" || len(records) != 1 || f.SignatureChain != "VALID" || !strings.Contains(strings.Join(f.Problems, ","), "TORN_JOURNAL") {
		t.Fatal("crash recovery fabricated records or lost the signed prefix", f)
	}
	wrapped, e := obs.EncodeJournal(raw)
	if e != nil {
		t.Fatal(e)
	}
	restored, e := obs.DecodeJournalArtifact(wrapped)
	if e != nil || !bytes.Equal(raw, restored) {
		t.Fatal("torn evidence changed during archive wrapping")
	}
}

type shortFile struct{ writes, syncs int }

func (f *shortFile) Write(p []byte) (int, error) { f.writes++; return len(p) / 2, nil }
func (f *shortFile) Sync() error                 { f.syncs++; return nil }
func (f *shortFile) Close() error                { return nil }
func TestShortWritePermanentlyPoisonsWitnessJournal(t *testing.T) {
	cfg := crashFixture(t)
	file := &shortFile{}
	j := &journal{file: file, reg: cfg.Registration, key: cfg.Key, epoch: time.Now(), process: localstate.RandomID()}
	if _, e := j.append("START", "", "LIVE_SESSION_STARTED", nil, "", -1); e != io.ErrShortWrite {
		t.Fatal(e)
	}
	if _, e := j.append("END", "", "COMPLETED", nil, "", -1); e == nil || file.writes != 1 || file.syncs != 0 {
		t.Fatal("continued writing after torn state", e)
	}
}
func TestDedicatedKeyStorageNoImplicitTrustAndNoReuse(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "key")
	identity, e := Keygen(dir, "test-witness")
	if e != nil {
		t.Fatal(e)
	}
	if localstate.Check(filepath.Join(dir, "witness-key.json")) != nil {
		t.Fatal("key unprotected")
	}
	if _, e = Keygen(dir, "test-witness"); e == nil {
		t.Fatal("key directory overwritten")
	}
	var out bytes.Buffer
	if code := Run(t.Context(), []string{"keygen", "--key-dir", filepath.Join(t.TempDir(), "cli-key"), "--witness", "cli-witness"}, &out); code != 0 {
		t.Fatal(out.String())
	}
	if bytes.Contains(out.Bytes(), []byte("privateKey")) || bytes.Contains(out.Bytes(), []byte("scopes")) || identity.KeyID == "" {
		t.Fatal("key material or invented trust scope emitted")
	}
}

type closedOutput struct{}

func (closedOutput) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestWitnessCLIOutputFailureIsNotSuccessfulProvisioning(t *testing.T) {
	code := Run(t.Context(), []string{"keygen", "--key-dir", filepath.Join(t.TempDir(), "key"), "--witness", "test-witness"}, closedOutput{})
	if code != 3 {
		t.Fatal("failed JSON output reported success", code)
	}
}
