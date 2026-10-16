package postgres

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

func testPlan(t *testing.T) (Plan, keys) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	lpub, lpriv, _ := ed25519.GenerateKey(rand.Reader)
	run := strings.Repeat("a", 64)
	labels := func(role string) map[string]string {
		return map[string]string{ownerLabel: run, "dev.themis.postgres.role": role, "dev.themis.postgres.policy": Workflow}
	}
	i := Inventory{Version: Version, Run: run, Directory: t.TempDir(), Actor: localstate.Actor{UID: "test", Name: "test", Host: "test"}, Endpoint: "unix:///var/run/docker.sock", Engine: "test-local-engine-000", Image: Image, ImageID: "sha256:" + strings.Repeat("b", 64), Approver: pub, LedgerKey: lpub, CleanupBefore: time.Now().UTC().Add(time.Minute)}
	if runtime.GOOS == "windows" {
		i.Endpoint = "npipe:////./pipe/dockerDesktopLinuxEngine"
	}
	i.Network = Network{ID: strings.Repeat("c", 64), Name: "themis-pg-" + run, Driver: "bridge", Internal: true, Labels: labels("network")}
	for n, r := range []*Resource{&i.Source, &i.Restore} {
		role := []string{"source", "restore"}[n]
		*r = Resource{Role: role, ID: strings.Repeat([]string{"d", "e"}[n], 64), Volume: Volume{Name: "themis-pg-" + run + "-" + role, Driver: "local", CreatedAt: "now", Labels: labels(role), Options: map[string]string{"type": "tmpfs", "device": "tmpfs", "o": "size=134217728,uid=999,gid=999,mode=0700"}}, DB: DBIdentity{Database: Database, System: role, Boot: "now", Version: "180006"}}
	}
	p, e := Compile(Example("healthy"), i)
	if e != nil {
		t.Fatal(e)
	}
	return p, keys{priv, lpriv}
}

func TestContractPlanAuthorization(t *testing.T) {
	p, k := testPlan(t)
	q, e := Compile(p.Contract, p.Inventory)
	if e != nil || p.Digest != q.Digest {
		t.Fatal("nondeterministic plan")
	}
	for _, change := range []func(*Plan){func(p *Plan) { p.Contract.Target = "external" }, func(p *Plan) { p.Contract.MaxLostCommits++ }, func(p *Plan) { p.Inventory.Source.ID = p.Inventory.Restore.ID }, func(p *Plan) { p.Inventory.Source.DB.Database = "postgres" }, func(p *Plan) { p.Inventory.Engine = "another-engine" }, func(p *Plan) { p.Inventory.Image = "postgres:latest" }} {
		b, _ := json.Marshal(p)
		var altered Plan
		json.Unmarshal(b, &altered)
		change(&altered)
		if altered.Validate() == nil {
			t.Fatal("altered frozen plan admitted")
		}
	}
	now := time.Now()
	g := Grant{Version: Version, Plan: p.Digest, Run: p.Inventory.Run, Database: Database, Operations: "seed,commit,backup,stop-source,restore,verify", StartBefore: now.Add(time.Second), ExecuteBefore: now.Add(121 * time.Second), CleanupBefore: p.Inventory.CleanupBefore}
	g.Signature = ed25519.Sign(k.Approver, grantMessage(g))
	if e := validateGrant(p, g, now, true); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*Grant){func(g *Grant) { g.Database = "postgres" }, func(g *Grant) { g.Plan = "forged" }, func(g *Grant) { g.Run = "different" }, func(g *Grant) { g.StartBefore = now.Add(-time.Second) }, func(g *Grant) { g.ExecuteBefore = now.Add(-time.Second) }, func(g *Grant) { g.Signature = nil }} {
		v := g
		change(&v)
		if validateGrant(p, v, now, true) == nil {
			t.Fatal("invalid grant admitted")
		}
	}
	if ValidateEndpoint("tcp://127.0.0.1:2375") == nil || ValidateEndpoint("ssh://localhost") == nil {
		t.Fatal("remote transport admitted")
	}
	for _, raw := range []string{`{"version":"x","Version":"x"}`, `{"unknown":true}`, `{} {}`} {
		var c Contract
		if localstate.Unmarshal([]byte(raw), &c) == nil {
			t.Fatal("ambiguous contract parsed")
		}
	}
}

type faultyWriter struct {
	bytes.Buffer
	short, syncFail bool
	writes          int
}

func (w *faultyWriter) Write(b []byte) (int, error) {
	w.writes++
	if w.short {
		return len(b) - 1, nil
	}
	return w.Buffer.Write(b)
}
func (w *faultyWriter) Sync() error {
	if w.syncFail {
		return errors.New("disk sync failed")
	}
	return nil
}
func TestJournalPoisonAndCorruption(t *testing.T) {
	for _, w := range []*faultyWriter{{short: true}, {syncFail: true}} {
		j := journal{w: w, start: time.Now(), plan: "plan"}
		if j.append("INTENT", nil) == nil || j.append("NEXT", nil) == nil || w.writes != 1 {
			t.Fatal("writer not poisoned")
		}
	}
	w := &faultyWriter{}
	j := journal{w: w, start: time.Now(), plan: "plan"}
	if j.append("INTENT", nil) != nil || j.append("OBSERVED", nil) != nil {
		t.Fatal("append")
	}
	data := w.Bytes()
	if VerifyJournal(data, "plan") != nil {
		t.Fatal("valid chain rejected")
	}
	for _, bad := range [][]byte{data[:len(data)-1], append([]byte("x"), data...), bytes.ReplaceAll(data, []byte("INTENT"), []byte("FORGED"))} {
		if VerifyJournal(bad, "plan") == nil {
			t.Fatal("damaged chain accepted")
		}
	}
	if VerifyJournal(data, "other-plan") == nil {
		t.Fatal("wrong plan accepted")
	}
}

func TestReceiptsAndConservativeThresholds(t *testing.T) {
	p, k := testPlan(t)
	var receipts []Receipt
	prev := ""
	for id := 1; id <= 16; id++ {
		r := Receipt{Version: Version, Plan: p.Digest, ID: id, Payload: payload(id), XID: "100", AckNS: int64(id), Previous: prev}
		r.Signature = ed25519.Sign(k.Ledger, receiptMessage(r))
		prev = digest("receipt", r)
		receipts = append(receipts, r)
	}
	if verifyReceipts(receipts, p, 16) != nil {
		t.Fatal("valid receipt ledger rejected")
	}
	if verifyReceipts(receipts[:15], p, 16) == nil {
		t.Fatal("missing coverage accepted")
	}
	forged := append([]Receipt(nil), receipts...)
	forged[4].Payload = payload(99)
	if verifyReceipts(forged, p, 16) == nil {
		t.Fatal("forged receipt accepted")
	}
	zero := 0
	m := Measurements{DumpExit: &zero, RestoreExit: &zero, BackupReadable: true, SourceStopped: true, SchemaMatch: true, SchemaObserved: true, ReadWriteReady: true, IntegrityObserved: true, IntegrityOK: true, ReceiptCoverage: true, DataLossExact: true, RestoreToReadinessNS: p.Contract.MaxRestoreMillis * int64(time.Millisecond)}
	verdict := func(m Measurements, clean bool, problem string) result.Verdict {
		return result.Aggregate(required, assess(p, m, CleanupReceipt{Complete: clean}, problem), result.RunEvidence{PreconditionsMet: true})
	}
	if verdict(m, true, "") != result.Pass {
		t.Fatal("inclusive time boundary rejected")
	}
	m.RestoreToReadinessNS++
	if verdict(m, true, "") != result.Fail {
		t.Fatal("time breach passed")
	}
	m.RestoreToReadinessNS--
	m.ReceiptCoverage = false
	m.DataLossExact = false
	if verdict(m, true, "") != result.Inconclusive {
		t.Fatal("missing receipt passed")
	}
	m.Missing = []int{17}
	if verdict(m, true, "uncertain") != result.Fail {
		t.Fatal("credible loss hidden by missing evidence")
	}
	m.Missing = nil
	if verdict(m, false, "") != result.Inconclusive {
		t.Fatal("cleanup pending passed")
	}
	var dst bytes.Buffer
	w := limitedWriter{&dst, 3}
	if _, e := w.Write([]byte("four")); e == nil || dst.Len() != 0 {
		t.Fatal("output limit not enforced")
	}
}

func TestBackupAttestationAndBounds(t *testing.T) {
	p, k := testPlan(t)
	dir, e := localstate.CreateDirectory(filepath.Join(t.TempDir(), "private"))
	if e != nil {
		t.Fatal(e)
	}
	data := []byte("PGDMPsynthetic-bounded-fixture")
	f, e := localstate.OpenNew(filepath.Join(dir, "backup.dump"))
	if e != nil {
		t.Fatal(e)
	}
	f.Write(data)
	f.Close()
	// Wrong digest has a genuine authorized signature: content checking is still required.
	b := backupInfo{Plan: p.Digest, Run: p.Inventory.Run, Source: p.Inventory.Source.ID, Restore: p.Inventory.Restore.ID, SHA256: strings.Repeat("0", 64), Bytes: int64(len(data))}
	b.Signature = ed25519.Sign(k.Ledger, backupMessage(b))
	if e = localstate.WriteNew(filepath.Join(dir, "backup-info.json"), b); e != nil {
		t.Fatal(e)
	}
	if f, _, e := backupFile(dir, p); e == nil {
		f.Close()
		t.Fatal("wrong digest admitted")
	}
	if _, e = io.Copy(&limitedWriter{io.Discard, 1}, strings.NewReader("too much")); e == nil {
		t.Fatal("storage bound not enforced")
	}
}

func FuzzContract(f *testing.F) {
	b, _ := json.Marshal(Example("healthy"))
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		var c Contract
		if localstate.Unmarshal(b, &c) == nil && c.Validate() == nil {
			encoded, _ := json.Marshal(c)
			var d Contract
			if localstate.Unmarshal(encoded, &d) != nil || digest("contract", c) != digest("contract", d) {
				t.Fatal("unstable contract")
			}
		}
	})
}

func TestOfflineWholeRunForgeryNeverPasses(t *testing.T) {
	p, _ := testPlan(t)
	dir := t.TempDir()
	// The attacker controls keys, all plan fields, journal hashes and candidate
	// report bytes. Structural self-consistency is deliberately insufficient.
	p.Inventory.Directory = dir
	p.Digest = ""
	p.Digest = digest("themis.postgres.plan.v1", p)
	w := &faultyWriter{}
	j := journal{w: w, start: time.Now(), plan: p.Digest}
	if e := j.append("FORGED_SUCCESS", map[string]bool{"pass": true}); e != nil {
		t.Fatal(e)
	}
	r := Report{Version: Version, Run: p.Inventory.Run, Plan: p.Digest, Verdict: result.Pass, Live: true}
	for name, value := range map[string]any{"plan.json": p, "report.json": r} {
		b, _ := json.Marshal(value)
		if e := os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.WriteFile(filepath.Join(dir, "journal.jsonl"), w.Bytes(), 0600); e != nil {
		t.Fatal(e)
	}
	replayed, e := Replay(dir)
	if e != nil || replayed.Live || replayed.Verdict != result.Inconclusive {
		t.Fatalf("forgery gained trust: %v", e)
	}
}

func TestPlanSnapshotsAndContractTableArity(t *testing.T) {
	p, _ := testPlan(t)
	c := p.Contract
	i := p.Inventory
	q, e := Compile(c, i)
	if e != nil {
		t.Fatal(e)
	}
	c.RequiredTables[0] = "mutated"
	i.Network.Labels[ownerLabel] = "mutated"
	if e = q.Validate(); e != nil {
		t.Fatal("input mutation changed frozen snapshot")
	}
	c = Example("healthy")
	c.RequiredTables = append(c.RequiredTables, "unsupported")
	if c.Validate() == nil {
		t.Fatal("extra required table silently discarded")
	}
	for _, limit := range []int64{0, -1, 60001} {
		c = Example("healthy")
		c.MaxRestoreMillis = limit
		if c.Validate() == nil {
			t.Fatal("invalid time budget accepted")
		}
	}
}
