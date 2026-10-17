package postgres

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

func TestPITRPublishedSchemaAndExamples(t *testing.T) {
	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile("../../schemas/postgres-pitr-v1alpha1.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"healthy", "ack-loss", "missing-wal", "cleanup-denied", "inflight-crash"} {
		path := filepath.Join("..", "..", "examples", "postgres-pitr", scenario+".json")
		c, err := ReadPITRContract(path)
		if err != nil {
			t.Fatal(err)
		}
		if c != PITRExample(scenario) {
			t.Fatal("published contract differs from fixed workflow")
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var value any
		if err = json.Unmarshal(b, &value); err != nil {
			t.Fatal(err)
		}
		if err = schema.Validate(value); err != nil {
			t.Fatal(err)
		}
	}
	for _, raw := range []string{`{"version":"x","Version":"x"}`, `{"unknown":true}`, `{} {}`} {
		var c PITRContract
		if localstate.Unmarshal([]byte(raw), &c) == nil {
			t.Fatal("ambiguous physical contract decoded")
		}
	}
}

func testPITRPlan(t *testing.T) (PITRPlan, keys) {
	t.Helper()
	old, k := testPlan(t)
	now := time.Now().UTC()
	i := PITRInventory{Inventory: old.Inventory, CreatedAt: now, Profiles: map[string]string{}, Starts: map[string]string{}}
	i.Version = PITRVersion
	i.CleanupBefore = now.Add(30 * time.Minute)
	i.CleanupKey, _, _ = ed25519.GenerateKey(rand.Reader)
	i.Network.Name = "themis-pgp-" + i.Run
	i.Network.Labels["dev.themis.postgres.policy"] = PITRWorkflow
	i.Archive = Resource{Role: "archive", ID: strings.Repeat("f", 64), Volume: Volume{Driver: "local", CreatedAt: "now"}}
	i.Restore.DB = DBIdentity{}
	for _, r := range []*Resource{&i.Source, &i.Restore, &i.Archive} {
		r.Volume.Name = "themis-pgp-" + i.Run + "-" + r.Role
		r.Volume.Options = nil
		r.Volume.Labels = map[string]string{ownerLabel: i.Run, "dev.themis.postgres.role": r.Role, "dev.themis.postgres.policy": PITRWorkflow}
		i.Profiles[r.Role] = strings.Repeat("a", 64)
		i.Starts[r.Role] = "now"
	}
	p, err := CompilePITR(PITRExample("healthy"), i)
	if err != nil {
		t.Fatal(err)
	}
	return p, k
}
func TestPITRContractsPlansAndIndependentAuthority(t *testing.T) {
	p, k := testPITRPlan(t)
	q, err := CompilePITR(p.Contract, p.Inventory)
	if err != nil || q.Digest != p.Digest {
		t.Fatal("PITR plan nondeterministic")
	}
	q.Inventory.Profiles["source"] = "changed"
	q.Inventory.Source.Volume.Labels[ownerLabel] = "changed"
	if p.Validate() != nil {
		t.Fatal("plan aliases mutable inventory")
	}
	for _, alter := range []func(*PITRPlan){func(p *PITRPlan) { p.Version = DurableVersion }, func(p *PITRPlan) { p.Inventory.Actor.UID = "other" }, func(p *PITRPlan) { p.Inventory.Engine = "other-engine" }, func(p *PITRPlan) { p.Inventory.Source.ID = p.Inventory.Restore.ID }, func(p *PITRPlan) { p.Inventory.Source.Volume = p.Inventory.Restore.Volume }, func(p *PITRPlan) { p.Inventory.Source.DB.System = "other" }, func(p *PITRPlan) { p.TargetName = "operator" }, func(p *PITRPlan) { p.TargetTimeline = 2 }, func(p *PITRPlan) { p.TargetBoundary = 16 }, func(p *PITRPlan) { p.Contract.MaxWALBytes++ }} {
		b, _ := json.Marshal(p)
		var changed PITRPlan
		json.Unmarshal(b, &changed)
		alter(&changed)
		if changed.Validate() == nil {
			t.Fatal("changed PITR plan accepted")
		}
	}
	now := time.Now().UTC()
	g := PITRGrant{PITRVersion, "sigkill-physical-target-once", p.Digest, strings.Repeat("b", 64), pitrInventoryHash(p.Inventory), now.Add(30 * time.Second), now.Add(150 * time.Second), nil}
	g.Signature = ed25519.Sign(k.Approver, pitrGrantMessage(g))
	if validatePITRGrant(p, g, g.Scope, g.Prepared, now, true) != nil {
		t.Fatal("valid grant rejected")
	}
	for _, alter := range []func(*PITRGrant){func(g *PITRGrant) { g.Version = DurableVersion }, func(g *PITRGrant) { g.Scope = "prepare" }, func(g *PITRGrant) { g.Plan = "changed" }, func(g *PITRGrant) { g.Prepared = "changed" }, func(g *PITRGrant) { g.Inventory = "changed" }, func(g *PITRGrant) { g.StartBefore = now }, func(g *PITRGrant) { g.ExecuteBefore = now }, func(g *PITRGrant) { g.Signature = nil }} {
		v := g
		alter(&v)
		if validatePITRGrant(p, v, g.Scope, g.Prepared, now, true) == nil {
			t.Fatal("invalid grant accepted")
		}
	}
	old := DurableGrant{Version: DurableVersion, Scope: "sigkill-source-once", Plan: p.Digest}
	b, _ := json.Marshal(old)
	var incompatible PITRGrant
	if localstate.Unmarshal(b, &incompatible) == nil {
		t.Fatal("logical SIGKILL grant decoded as PITR grant")
	}
	g.Scope = "prepare"
	g.Prepared = ""
	g.Signature = ed25519.Sign(k.Approver, pitrGrantMessage(g))
	if validatePITRGrant(p, g, "prepare", "", now, true) != nil || validatePITRGrant(p, g, "sigkill-physical-target-once", "", now, true) == nil {
		t.Fatal("preparation elevated to source failure")
	}
	for _, before := range []time.Time{now.Add(-time.Second), now.Add(-121 * time.Second)} {
		expired := g
		expired.StartBefore = before
		expired.ExecuteBefore = before.Add(120 * time.Second)
		expired.Signature = ed25519.Sign(k.Approver, pitrGrantMessage(expired))
		if validatePITRGrant(p, expired, "prepare", "", now, true) == nil {
			t.Fatal("correctly signed expired approval admitted")
		}
	}
}
func TestPITRWALRangesAndBudgets(t *testing.T) {
	names, err := pitrWALNames("0/FFF00000", "1/100000")
	if err != nil || !slices.Equal(names, []string{"000000010000000000000FFF", "000000010000000100000000"}) {
		t.Fatalf("WAL rollover incorrect %v %v", names, err)
	}
	for _, v := range [][2]string{{"0/10", "0/10"}, {"0/20", "0/10"}, {"0/0", "0/2000000"}, {"../x", "0/1"}, {"0/000000000", "0/1"}} {
		if _, err := pitrWALNames(v[0], v[1]); err == nil {
			t.Fatalf("unsafe WAL range %v", v)
		}
	}
}
func TestPITRUnsafePhysicalTar(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind byte
		mode int64
	}{{"../PG_VERSION", tar.TypeReg, 0600}, {"/PG_VERSION", tar.TypeReg, 0600}, {"pg_wal/link", tar.TypeSymlink, 0600}, {"pg_tblspc/123", tar.TypeReg, 0600}, {"recovery.signal", tar.TypeReg, 0600}, {"PG_VERSION", tar.TypeReg, 0644}, {"pg_wal/x", tar.TypeFifo, 0600}} {
		var b bytes.Buffer
		tw := tar.NewWriter(&b)
		if err := tw.WriteHeader(&tar.Header{Name: tc.name, Mode: tc.mode, Typeflag: tc.kind, Linkname: "/etc/passwd"}); err != nil {
			t.Fatal(err)
		}
		tw.Close()
		if _, _, err := pitrReadTar(bytes.NewReader(b.Bytes()), "system"); err == nil {
			t.Fatalf("unsafe tar accepted: %s", tc.name)
		}
	}
}
func TestPITRJournalAndReceiptIntegrity(t *testing.T) {
	p, k := testPITRPlan(t)
	for _, w := range []*faultyWriter{{short: true}, {syncFail: true}} {
		j := journal{w: w, start: time.Now(), plan: p.Digest, version: PITRVersion}
		if j.append("FAULT_INTENT", nil) == nil || j.append("ANOTHER_EFFECT", nil) == nil || w.writes != 1 {
			t.Fatal("failed journal did not poison writer")
		}
	}
	w := &faultyWriter{}
	j := journal{w: w, start: time.Now(), plan: p.Digest, version: PITRVersion}
	j.append("INTENT", nil)
	if verifyJournal(w.Bytes(), p.Digest, PITRVersion) != nil || VerifyDurableJournal(w.Bytes(), p.Digest) == nil || verifyJournal(w.Bytes()[:w.Len()-1], p.Digest, PITRVersion) == nil {
		t.Fatal("journal corruption/version admitted")
	}
	r := PITRReceipt{Version: PITRVersion, Plan: p.Digest, Session: strings.Repeat("c", 64), ID: 1, Payload: payload(1), XID: "123", AckOffsetNS: 1, AckAtUTC: time.Now().UTC()}
	r.Signature = ed25519.Sign(k.Ledger, pitrReceiptMessage(r))
	if verifyPITRReceipts([]PITRReceipt{r}, p, 1) != nil {
		t.Fatal("valid receipt rejected")
	}
	r.XID = "124"
	if verifyPITRReceipts([]PITRReceipt{r}, p, 1) == nil {
		t.Fatal("forged commit identity accepted")
	}
}
func TestPITRNoPassWithoutEachRecoveryGate(t *testing.T) {
	p, _ := testPITRPlan(t)
	clock := FailureTimeline{Anchor: DurableAnchor, IntentNS: 1, LastAvailableStartNS: 2, LastAvailableEndNS: 3, KillStartNS: 4, KillEndNS: 5, FirstUnavailableStartNS: 6, FirstUnavailableEndNS: 7, RestoreStartNS: 8, ReadyNS: 10, FailureUncertaintyNS: 5, RecoveryUpperNS: 8, RecoveryLowerNS: 3, KillAcknowledged: true}
	base := PITRMeasurements{BackupVerified: true, WALVerified: true, FailureObserved: true, TargetObserved: true, TargetFidelity: true, Promoted: true, SchemaObserved: true, SchemaMatch: true, IntegrityObserved: true, IntegrityOK: true, ReadWriteReady: true, ReceiptCoverage: true, DataLossExact: true, Timeline: clock}
	clean := CleanupReceipt{Complete: true}
	verdict := func(m PITRMeasurements) result.Verdict {
		return result.Aggregate(pitrRequired, assessPITR(p, m, clean, ""), result.RunEvidence{PreconditionsMet: true})
	}
	if verdict(base) != result.Pass {
		t.Fatal("complete candidate rejected")
	}
	for _, alter := range []func(*PITRMeasurements){func(m *PITRMeasurements) { m.BackupVerified = false }, func(m *PITRMeasurements) { m.WALVerified = false }, func(m *PITRMeasurements) { m.FailureObserved = false }, func(m *PITRMeasurements) { m.TargetObserved = false }, func(m *PITRMeasurements) { m.TargetFidelity = false }, func(m *PITRMeasurements) { m.Promoted = false }, func(m *PITRMeasurements) { m.SchemaObserved = false }, func(m *PITRMeasurements) { m.SchemaMatch = false }, func(m *PITRMeasurements) { m.IntegrityOK = false }, func(m *PITRMeasurements) { m.ReadWriteReady = false }, func(m *PITRMeasurements) { m.ReceiptCoverage = false }, func(m *PITRMeasurements) { m.DataLossExact = false }, func(m *PITRMeasurements) { m.Uncertain = []int{21} }, func(m *PITRMeasurements) { m.Timeline.KillAmbiguous = true }, func(m *PITRMeasurements) { m.Timeline.RecoveryUpperNS++ }} {
		m := base
		alter(&m)
		if verdict(m) == result.Pass {
			t.Fatal("missing recovery gate manufactured PASS")
		}
	}
	m := base
	m.Missing = []int{21, 22, 23}
	if !m.TargetFidelity || verdict(m) != result.Fail {
		t.Fatal("correct earlier target concealed acknowledged loss")
	}
	m.ReceiptCoverage = false
	m.DataLossExact = false
	if verdict(m) != result.Fail {
		t.Fatal("known acknowledged loss masked by missing evidence")
	}
	m = base
	m.Timeline.ReadyNS = 60000000003
	m.Timeline.RecoveryUpperNS = m.Timeline.ReadyNS - 2
	m.Timeline.RecoveryLowerNS = m.Timeline.ReadyNS - 7
	if verdict(m) != result.Fail {
		t.Fatal("recovery time above inclusive bound accepted")
	}
}
func TestPITROfflineForgeryCannotAuthenticate(t *testing.T) {
	dir, err := localstate.CreateDirectory(filepath.Join(t.TempDir(), "forged"))
	if err != nil {
		t.Fatal(err)
	}
	r := PITRReport{Version: PITRVersion, Run: strings.Repeat("a", 64), Plan: strings.Repeat("b", 64), Verdict: result.Pass, Live: true, Assertions: []result.AssertionResult{{ID: "target-proof", Verdict: result.Pass, Evidence: result.Sufficient}}}
	if err = localstate.WriteNew(filepath.Join(dir, "pitr-report.json"), r); err != nil {
		t.Fatal(err)
	}
	offline, err := ReplayPITR(dir)
	if err != nil || offline.Live || offline.Verdict != result.Inconclusive || offline.Assertions[0].Verdict != result.Inconclusive {
		t.Fatal("forged report gained execution trust")
	}
}
func FuzzPITRUntrustedRecoveryData(f *testing.F) {
	f.Add([]byte(`{"Version":"wrong"}`))
	f.Add([]byte("../wal"))
	f.Add([]byte("0/FFF00000"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		var c PITRContract
		if localstate.Unmarshal(b, &c) == nil && c.Validate() == nil {
			if c.Version != PITRVersion || c.MaxBackupBytes != PITRBackupBytes || c.MaxWALBytes != PITRWALBytes {
				t.Fatal("unbounded physical contract")
			}
		}
		pitrReadTar(bytes.NewReader(b), "not-authority")
		pitrLSN(string(b))
	})
}

// This test uses actual filesystem publication, not a simulated archive seal.
func TestPITRPartialPublicationCannotBeReplaced(t *testing.T) {
	dir, err := localstate.CreateDirectory(filepath.Join(t.TempDir(), "capsule"))
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(dir, "segment")
	if err = pitrPublish(name, strings.NewReader("longer-than-budget"), 3); err == nil {
		t.Fatal("oversized file published")
	}
	if _, err = os.Stat(name); !os.IsNotExist(err) {
		t.Fatal("incomplete archive eligible")
	}
	if err = pitrPublish(name, strings.NewReader("new"), 3); err == nil {
		t.Fatal("partial publication silently resumed")
	}
}
