package postgres

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

func testDurablePlan(t *testing.T) (DurablePlan, keys) {
	t.Helper()
	old, k := testPlan(t)
	i := DurableInventory{Inventory: old.Inventory, Storage: DurableStorage, CreatedAt: time.Now().UTC(), SourceStarted: "now", RestoreStarted: "now"}
	i.Version = DurableVersion
	i.CleanupBefore = time.Now().UTC().Add(30 * time.Minute)
	i.BackupDirectory = filepath.Join(i.Directory, "backup-store")
	i.BackupID = digest("themis.postgres.durable.backup-id.v1", i.Run)
	i.CleanupKey, _, _ = ed25519.GenerateKey(rand.Reader)
	i.Network.Name = "themis-pgd-" + i.Run
	i.Network.Labels["dev.themis.postgres.policy"] = DurableWorkflow
	for _, r := range []*Resource{&i.Source, &i.Restore} {
		r.Volume.Name = "themis-pgd-" + i.Run + "-" + r.Role
		r.Volume.Options = nil
		r.Volume.Labels["dev.themis.postgres.policy"] = DurableWorkflow
	}
	p, e := CompileDurable(DurableExample("healthy"), i)
	if e != nil {
		t.Fatal(e)
	}
	return p, k
}
func TestDurableFrozenPlanAndScope(t *testing.T) {
	p, k := testDurablePlan(t)
	q, e := CompileDurable(p.Contract, p.Inventory)
	if e != nil || p.Digest != q.Digest {
		t.Fatal("nondeterministic durable plan")
	}
	q.Inventory.Network.Labels[ownerLabel] = "changed"
	q.Contract.RequiredTables[0] = "changed"
	if p.Validate() != nil {
		t.Fatal("plan aliases mutable inputs")
	}
	for _, change := range []func(*DurablePlan){func(p *DurablePlan) { p.Version = Version }, func(p *DurablePlan) { p.Contract.Failure = "stop" }, func(p *DurablePlan) { p.Contract.MaxVolumeBytes++ }, func(p *DurablePlan) { p.Inventory.Source.ID = p.Inventory.Restore.ID }, func(p *DurablePlan) { p.Inventory.BackupDirectory = filepath.Dir(p.Inventory.Directory) }, func(p *DurablePlan) { p.Inventory.Source.Volume.Options = map[string]string{"type": "tmpfs"} }} {
		var v DurablePlan
		b, _ := json.Marshal(p)
		json.Unmarshal(b, &v)
		change(&v)
		if v.Validate() == nil {
			t.Fatal("altered frozen plan admitted")
		}
	}
	now := time.Now().UTC()
	i := p.Inventory
	b := DurableBackup{SHA256: strings.Repeat("a", 64), Bytes: 1024}
	g := DurableGrant{Version: DurableVersion, Scope: "sigkill-source-once", Plan: p.Digest, Run: i.Run, Engine: i.Engine, Endpoint: i.Endpoint, Source: i.Source.ID, SourceSystem: i.Source.DB.System, Restore: i.Restore.ID, Database: Database, Failure: "SIGKILL", BackupID: i.BackupID, BackupSHA256: b.SHA256, BackupBytes: b.Bytes, StartBefore: now.Add(30 * time.Second), ExecuteBefore: now.Add(150 * time.Second), CleanupBefore: i.CleanupBefore}
	g.Signature = ed25519.Sign(k.Approver, durableGrantMessage(g))
	if e = validateDurableGrant(p, g, g.Scope, &b, now, true); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*DurableGrant){func(g *DurableGrant) { g.Version = Version }, func(g *DurableGrant) { g.Scope = "prepare" }, func(g *DurableGrant) { g.Source = g.Restore }, func(g *DurableGrant) { g.Engine = "other" }, func(g *DurableGrant) { g.Endpoint = "tcp://localhost:2375" }, func(g *DurableGrant) { g.SourceSystem = "other" }, func(g *DurableGrant) { g.BackupSHA256 = strings.Repeat("b", 64) }, func(g *DurableGrant) { g.BackupBytes++ }, func(g *DurableGrant) { g.ExecuteBefore = now }, func(g *DurableGrant) { g.StartBefore = now.Add(-time.Second) }, func(g *DurableGrant) { g.Signature = nil }} {
		v := g
		change(&v)
		if validateDurableGrant(p, v, "sigkill-source-once", &b, now, true) == nil {
			t.Fatal("mismatched or expired grant admitted")
		}
	}
	// Even correctly signed preparation authority cannot be elevated to fault.
	g.Scope = "prepare"
	g.Failure = "none"
	g.BackupSHA256 = ""
	g.BackupBytes = 0
	g.Signature = ed25519.Sign(k.Approver, durableGrantMessage(g))
	if validateDurableGrant(p, g, "prepare", nil, now, true) != nil || validateDurableGrant(p, g, "sigkill-source-once", &b, now, true) == nil {
		t.Fatal("preparation elevated to SIGKILL")
	}
	old := Grant{Version: Version, Plan: p.Digest}
	raw, _ := json.Marshal(old)
	var wrong DurableGrant
	if json.Unmarshal(raw, &wrong) != nil {
		t.Fatal("fixture")
	}
	if validateDurableGrant(p, wrong, "sigkill-source-once", &b, now, true) == nil {
		t.Fatal("T3.0 grant authorized SIGKILL")
	}
}
func TestDurableJournalPoisonAndVersion(t *testing.T) {
	for _, w := range []*faultyWriter{{short: true}, {syncFail: true}} {
		j := journal{w: w, start: time.Now(), plan: "p", version: DurableVersion}
		if j.append("INTENT", nil) == nil {
			t.Fatal("write failure ignored")
		}
		n := w.writes
		if j.append("EFFECT", nil) == nil || w.writes != n {
			t.Fatal("poisoned journal continued")
		}
	}
	w := &faultyWriter{}
	j := journal{w: w, start: time.Now(), plan: "p", version: DurableVersion}
	if j.append("INTENT", nil) != nil || VerifyDurableJournal(w.Bytes(), "p") != nil || VerifyJournal(w.Bytes(), "p") == nil {
		t.Fatal("version/domain confusion")
	}
	if VerifyDurableJournal(w.Bytes()[:len(w.Bytes())-1], "p") == nil {
		t.Fatal("partial append admitted")
	}
}
func TestDurableReceiptSessionsAndThresholds(t *testing.T) {
	p, k := testDurablePlan(t)
	var rs []DurableReceipt
	previous := ""
	for id := 1; id <= 19; id++ {
		session := strings.Repeat("a", 64)
		offset := int64(id)
		if id > 16 {
			session = strings.Repeat("b", 64)
			offset = int64(id - 16)
		}
		r := DurableReceipt{Version: DurableVersion, Plan: p.Digest, Session: session, ID: id, Payload: payload(id), XID: string(rune('a' + id)), AckOffsetNS: offset, AckAtUTC: time.Now().UTC(), Previous: previous}
		r.Signature = ed25519.Sign(k.Ledger, durableReceiptMessage(r))
		rs = append(rs, r)
		previous = digest("durable-receipt", r)
	}
	if e := verifyDurableReceipts(rs, p, 19); e != nil {
		t.Fatal(e)
	}
	rs[7].Signature[0] ^= 1
	if verifyDurableReceipts(rs, p, 19) == nil {
		t.Fatal("forged receipt accepted")
	}
	m := DurableMeasurements{Missing: []int{17, 18, 19}, ExpectedCommits: 19}
	a := assessDurable(p, m, CleanupReceipt{}, "missing other evidence")
	if result.Aggregate(durableRequired, a, result.RunEvidence{PreconditionsMet: true}) != result.Fail {
		t.Fatal("credible loss did not dominate incomplete evidence")
	}
	m.Missing = nil
	a = assessDurable(p, m, CleanupReceipt{Complete: true}, "")
	if result.Aggregate(durableRequired, a, result.RunEvidence{PreconditionsMet: true}) == result.Pass {
		t.Fatal("incomplete evidence passed")
	}
	timeline := FailureTimeline{Anchor: DurableAnchor, IntentNS: 1, LastAvailableStartNS: 2, LastAvailableEndNS: 3, KillStartNS: 4, KillEndNS: 5, FirstUnavailableStartNS: 6, FirstUnavailableEndNS: 7, RestoreStartNS: 8, ReadyNS: 10, FailureUncertaintyNS: 5, RecoveryUpperNS: 8, RecoveryLowerNS: 3}
	if !validTimeline(timeline) {
		t.Fatal("valid timing rejected")
	}
	timeline.RecoveryUpperNS--
	if validTimeline(timeline) {
		t.Fatal("inconsistent timing accepted")
	}
}
func TestDurableIdenticalReplacementRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "archive")
	data := append([]byte{'P', 'G', 'D', 'M', 'P', 1, 16, 0}, bytes.Repeat([]byte("x"), 64)...)
	if e := os.WriteFile(path, data, 0600); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	id, e := backupFileIdentity(f)
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	other := path + "-substitute"
	os.WriteFile(other, data, 0600)
	f, e = os.Open(other)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if e = validateDurableFile(f, DurableBackup{Bytes: int64(len(data)), FileIdentity: id}); e == nil {
		t.Fatal("identical substituted archive accepted")
	}
}
func FuzzDurableContract(f *testing.F) {
	b, _ := json.Marshal(DurableExample("healthy"))
	f.Add(b)
	f.Add([]byte(`{"version":"x","Version":"x"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		var c DurableContract
		if localstate.Unmarshal(b, &c) == nil && c.Validate() == nil {
			if c.Version != DurableVersion || c.Failure != "docker-sigkill" || c.MaxBackupBytes != BackupBytes || c.MaxRuntimeSeconds != 120 {
				t.Fatal("unsafe contract admitted")
			}
		}
	})
}

func TestDurableExamplesAndSchema(t *testing.T) {
	path := "../../schemas/postgres-durable-v1alpha1.json"
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var doc any
	if e = json.Unmarshal(b, &doc); e != nil {
		t.Fatal(e)
	}
	compiler := jsonschema.NewCompiler()
	if e = compiler.AddResource("schema.json", doc); e != nil {
		t.Fatal(e)
	}
	schema, e := compiler.Compile("schema.json")
	if e != nil {
		t.Fatal(e)
	}
	for _, scenario := range []string{"healthy", "ack-loss", "missing-receipt", "cleanup-denied", "inflight-crash"} {
		path := filepath.Join("../../examples/postgres-durable", scenario+".json")
		c, e := ReadDurableContract(path)
		if e != nil || c.Scenario != scenario {
			t.Fatalf("invalid example %s %v", scenario, e)
		}
		b, _ := json.Marshal(c)
		var v any
		json.Unmarshal(b, &v)
		if e = schema.Validate(v); e != nil {
			t.Fatalf("schema differs from runtime %s: %v", scenario, e)
		}
	}
}
func TestDurableSelfContainedForgeryNeverPasses(t *testing.T) {
	p, _ := testDurablePlan(t)
	dir := t.TempDir()
	write := func(name string, v any) {
		b, _ := json.Marshal(v)
		if e := os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	r := DurableReport{Version: DurableVersion, Run: p.Inventory.Run, Plan: p.Digest, Verdict: result.Pass, Execution: result.Succeeded, Live: true}
	for _, id := range durableRequired {
		r.Assertions = append(r.Assertions, result.AssertionResult{ID: id, Verdict: result.Pass, Evidence: result.Sufficient})
	}
	write("durable-report.json", r)
	write("durable-plan.json", p)
	w := &faultyWriter{}
	j := journal{w: w, start: time.Now(), plan: p.Digest, version: DurableVersion}
	if e := j.append("FABRICATED_PASS", r); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"durable-prepare.jsonl", "durable-journal.jsonl"} {
		if e := os.WriteFile(filepath.Join(dir, name), w.Bytes(), 0600); e != nil {
			t.Fatal(e)
		}
	}
	replay, e := ReplayDurable(dir)
	if e != nil || replay.Live || replay.Verdict != result.Inconclusive {
		t.Fatalf("self-contained forged PASS trusted: %v", e)
	}
	for _, a := range replay.Assertions {
		if a.Verdict != result.Inconclusive {
			t.Fatal("historical assertion remained trusted")
		}
	}
}
