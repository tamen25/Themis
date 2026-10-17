package postgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/tamen25/themis/internal/result"
)

func testReplicationPlan(t *testing.T) (ReplicationPlan, replicationKeys) {
	t.Helper()
	old, _ := testPlan(t)
	v := old.Inventory
	now := time.Now().UTC()
	i := ReplicationInventory{Version: ReplicationVersion, Run: v.Run, Directory: v.Directory, Actor: v.Actor, Endpoint: v.Endpoint, Engine: v.Engine, Image: v.Image, ImageID: v.ImageID, Primary: v.Source, Standby: v.Restore, Network: v.Network, PrimaryIP: "172.20.0.2", StandbyIP: "172.20.0.3", CreatedAt: now, CleanupBefore: now.Add(30 * time.Minute), Profiles: map[string]string{}, Starts: map[string]string{}}
	i.Primary.Role = "primary"
	i.Standby.Role = "standby"
	i.Standby.DB.System = i.Primary.DB.System
	i.Standby.DB.Boot = "distinct-standby-boot"
	i.Network.Name = "themis-pgr-" + i.Run
	i.Network.Driver = "bridge"
	i.Network.Labels = map[string]string{ownerLabel: i.Run, "dev.themis.postgres.role": "network", "dev.themis.postgres.policy": ReplicationWorkflow}
	for _, r := range []*Resource{&i.Primary, &i.Standby} {
		r.Volume.Name = "themis-pgr-" + i.Run + "-" + r.Role
		r.Volume.Driver = "local"
		r.Volume.Options = nil
		r.Volume.Labels = map[string]string{ownerLabel: i.Run, "dev.themis.postgres.role": r.Role, "dev.themis.postgres.policy": ReplicationWorkflow}
		i.Profiles[r.Role] = strings.Repeat("a", 64)
		i.Starts[r.Role] = "now"
	}
	k := replicationKeys{}
	for _, pair := range []struct{ pub, priv *[]byte }{{&i.PrepareKey, &k.Prepare}, {&i.TerminationKey, &k.Termination}, {&i.PromotionKey, &k.Promotion}, {&i.LedgerKey, &k.Ledger}, {&i.CleanupKey, &k.Cleanup}} {
		pub, priv, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		*pair.pub, *pair.priv = pub, priv
	}
	p, err := CompileReplication(ReplicationExample("healthy"), i)
	if err != nil {
		t.Fatal(err)
	}
	return p, k
}
func testReplicationState(i ReplicationInventory) ReplicationObservation {
	return ReplicationObservation{Primary: i.Primary.DB, Standby: i.Standby.DB, SynchronousStandbyNames: replicationNames, SynchronousCommit: "remote_apply", SenderState: "streaming", SyncState: "sync", SenderUser: "themis_repl", SenderApplication: "themis_standby", SenderAddress: i.StandbyIP, CurrentLSN: "0/100", SentLSN: "0/100", WriteLSN: "0/100", FlushLSN: "0/100", ReplayLSN: "0/100", ReceiverState: "streaming", ReceiverHost: i.PrimaryIP, ReceiverPort: 5432, ReceivedLSN: "0/100", ReplayedLSN: "0/100", InRecovery: true, ReadOnly: true, Fsync: true, FullPageWrites: true, PrimaryWritable: true, AuthenticationVerified: true}
}
func TestReplicationImmutablePlansAndApprovalDomains(t *testing.T) {
	p, k := testReplicationPlan(t)
	q, err := CompileReplication(p.Contract, p.Inventory)
	if err != nil || q.Digest != p.Digest {
		t.Fatal("nondeterministic plan")
	}
	q.Inventory.Primary.Volume.Labels[ownerLabel] = "changed"
	q.Inventory.Profiles["primary"] = "changed"
	if p.Validate() != nil {
		t.Fatal("plan aliases caller memory")
	}
	for _, alter := range []func(*ReplicationPlan){func(p *ReplicationPlan) { p.Inventory.Engine = "other-engine" }, func(p *ReplicationPlan) { p.Inventory.Actor.UID = "other" }, func(p *ReplicationPlan) { p.Inventory.Endpoint = "tcp://127.0.0.1:2375" }, func(p *ReplicationPlan) { p.Inventory.Primary.ID = p.Inventory.Standby.ID }, func(p *ReplicationPlan) { p.Inventory.Standby.DB.System = "unrelated" }, func(p *ReplicationPlan) { p.Inventory.Primary.DB.Boot = "restarted" }, func(p *ReplicationPlan) { p.Inventory.Standby.Volume = p.Inventory.Primary.Volume }, func(p *ReplicationPlan) { p.Mode = "async" }, func(p *ReplicationPlan) { p.Fence = "none" }, func(p *ReplicationPlan) { p.MaxDurationSeconds++ }} {
		b, _ := json.Marshal(p)
		var changed ReplicationPlan
		json.Unmarshal(b, &changed)
		alter(&changed)
		if changed.Validate() == nil {
			t.Fatal("changed identity or plan admitted")
		}
	}
	now := time.Now().UTC()
	g := ReplicationGrant{ReplicationVersion, "terminate-and-fence", p.Digest, strings.Repeat("b", 64), replicationInventoryHash(p.Inventory), strings.Repeat("c", 64), now.Add(30 * time.Second), now.Add(150 * time.Second), nil}
	g.Signature = ed25519.Sign(k.Termination, replicationGrantMessage(g))
	if validateReplicationGrant(p, g, g.Scope, g.Prepared, g.Invocation, now, true) != nil {
		t.Fatal("valid scoped grant denied")
	}
	if validateReplicationGrant(p, g, "promote-fenced-standby", g.Prepared, g.Invocation, now, true) == nil {
		t.Fatal("termination grant authorized promotion")
	}
	if validateReplicationGrant(p, g, g.Scope, g.Prepared, g.Invocation, g.StartBefore, true) == nil {
		t.Fatal("expired start grant accepted")
	}
	for _, version := range []string{Version, DurableVersion, PITRVersion} {
		other := g
		other.Version = version
		other.Signature = ed25519.Sign(k.Termination, replicationGrantMessage(other))
		if validateReplicationGrant(p, other, g.Scope, g.Prepared, g.Invocation, now, true) == nil {
			t.Fatal("old recovery grant authorized failover")
		}
	}
	wrongKey := g
	wrongKey.Signature = ed25519.Sign(k.Prepare, replicationGrantMessage(wrongKey))
	if validateReplicationGrant(p, wrongKey, g.Scope, g.Prepared, g.Invocation, now, true) == nil {
		t.Fatal("preparation authority terminated primary")
	}
}
func TestReplicationRejectsUnprovenSynchronousGuarantees(t *testing.T) {
	p, _ := testReplicationPlan(t)
	good := testReplicationState(p.Inventory)
	if !validReplicationState(p.Inventory, good, "0/100") {
		t.Fatal("valid observation rejected")
	}
	for _, alter := range []func(*ReplicationObservation){func(o *ReplicationObservation) { o.SenderState = "catchup" }, func(o *ReplicationObservation) { o.SyncState = "async" }, func(o *ReplicationObservation) { o.SynchronousCommit = "local" }, func(o *ReplicationObservation) { o.SynchronousStandbyNames = "" }, func(o *ReplicationObservation) { o.ReceiverState = "" }, func(o *ReplicationObservation) { o.ReceiverHost = "unrelated" }, func(o *ReplicationObservation) { o.ReceivedLSN = "" }, func(o *ReplicationObservation) { o.ReplayedLSN = "0/FF" }, func(o *ReplicationObservation) { o.SenderAddress = "unrelated" }, func(o *ReplicationObservation) { o.InRecovery = false }, func(o *ReplicationObservation) { o.ReadOnly = false }, func(o *ReplicationObservation) { o.Fsync = false }, func(o *ReplicationObservation) { o.PrimaryWritable = false }, func(o *ReplicationObservation) { o.Slots = 1 }, func(o *ReplicationObservation) { o.Standby.Boot = "restarted" }} {
		v := good
		alter(&v)
		if validReplicationState(p.Inventory, v, "0/100") {
			t.Fatal("unverified replication or acknowledgement semantics accepted")
		}
	}
}
func testReplicationReceipts(p ReplicationPlan, k replicationKeys) []ReplicationReceipt {
	var rs []ReplicationReceipt
	previous := ""
	for n := 1; n <= replicationCommits; n++ {
		r := ReplicationReceipt{Version: ReplicationVersion, Plan: p.Digest, Session: strings.Repeat("d", 64), ID: n, Payload: payload(n), XID: strconv.Itoa(n + 100), Mode: "remote_apply", FlushLSN: "0/100", AckOffsetNS: int64(n), AckAtUTC: time.Now().UTC(), Previous: previous}
		r.Signature = ed25519.Sign(k.Ledger, replicationReceiptMessage(r))
		previous = digest("replication-receipt", r)
		rs = append(rs, r)
	}
	return rs
}
func TestReplicationReceiptForgeryAndCoverage(t *testing.T) {
	p, k := testReplicationPlan(t)
	rs := testReplicationReceipts(p, k)
	if verifyReplicationReceipts(rs, p) != nil {
		t.Fatal("valid ledger rejected")
	}
	if verifyReplicationReceipts(rs[:19], p) == nil {
		t.Fatal("missing independent receipt accepted")
	}
	for _, alter := range []func([]ReplicationReceipt){func(rs []ReplicationReceipt) { rs[0], rs[1] = rs[1], rs[0] }, func(rs []ReplicationReceipt) { rs[3].Payload = "forged" }, func(rs []ReplicationReceipt) { rs[3].Mode = "on" }, func(rs []ReplicationReceipt) { rs[3].Plan = strings.Repeat("e", 64) }, func(rs []ReplicationReceipt) { rs[3].Previous = "" }, func(rs []ReplicationReceipt) { rs[3].Signature = nil }} {
		copyRS := append([]ReplicationReceipt(nil), rs...)
		alter(copyRS)
		if verifyReplicationReceipts(copyRS, p) == nil {
			t.Fatal("forged or reordered receipt accepted")
		}
	}
}
func TestReplicationPromotionRequiresFenceBeforeDocker(t *testing.T) {
	p, _ := testReplicationPlan(t)
	if replicationPromote(context.Background(), Docker{}, p, ReplicationPrepared{}, ReplicationGrant{}, nil, &ReplicationMeasurements{}, replicationOptions{}) == nil {
		t.Fatal("promotion without verified fencing accepted")
	}
}

func TestReplicationTimeUncertaintyAndCancellation(t *testing.T) {
	p, _ := testReplicationPlan(t)
	ms := int64(time.Millisecond)
	m := ReplicationMeasurements{Authorization: true, ReplicationVerified: true, FailureObserved: true, Fenced: true, PrimaryAbsentAfterReady: true, PromotionAcknowledged: true, PromotionObserved: true, ReadWriteReady: true, ReceiptCoverage: true, DataLossExact: true, SchemaObserved: true, SchemaMatch: true, IntegrityObserved: true, IntegrityOK: true, FenceStartNS: 8 * ms, FenceEndNS: 9 * ms, PromotionStartNS: 10 * ms, PromotionEndNS: 11 * ms, Timeline: FailureTimeline{Anchor: DurableAnchor, IntentNS: ms, LastAvailableStartNS: 2 * ms, LastAvailableEndNS: 3 * ms, KillStartNS: 4 * ms, KillEndNS: 5 * ms, KillAcknowledged: true, FirstUnavailableStartNS: 6 * ms, FirstUnavailableEndNS: 7 * ms, RestoreStartNS: 10 * ms, ReadyNS: 12 * ms, FailureUncertaintyNS: 5 * ms, RecoveryUpperNS: 10 * ms, RecoveryLowerNS: 5 * ms}}
	for _, tc := range []struct {
		limit int64
		want  result.Verdict
	}{{10, result.Pass}, {4, result.Fail}, {5, result.Inconclusive}, {6, result.Inconclusive}} {
		p.Contract.MaxFailoverMillis = tc.limit
		out := result.Aggregate(replicationRequired, assessReplication(p, m, CleanupReceipt{Complete: true}, ""), result.RunEvidence{PreconditionsMet: true})
		if out != tc.want {
			t.Fatalf("limit=%d verdict=%s want=%s", tc.limit, out, tc.want)
		}
	}
	p.Contract.MaxFailoverMillis = 10
	for _, change := range []func(*ReplicationMeasurements){func(m *ReplicationMeasurements) { m.Fenced = false }, func(m *ReplicationMeasurements) { m.PromotionObserved = false }, func(m *ReplicationMeasurements) { m.ReceiptCoverage = false }, func(m *ReplicationMeasurements) { m.ReplicationVerified = false }, func(m *ReplicationMeasurements) { m.ReadWriteReady = false }} {
		incomplete := m
		change(&incomplete)
		out := result.Aggregate(replicationRequired, assessReplication(p, incomplete, CleanupReceipt{Complete: true}, ""), result.RunEvidence{PreconditionsMet: true})
		if out == result.Pass {
			t.Fatal("missing failover prerequisite became PASS")
		}
	}
	if out := result.Aggregate(replicationRequired, assessReplication(p, m, CleanupReceipt{Complete: true}, "canceled during cleanup"), result.RunEvidence{PreconditionsMet: true}); out == result.Pass {
		t.Fatal("canceled finalization became PASS")
	}
}
func TestReplicationOfflineNeverAuthenticatesForgedPASS(t *testing.T) {
	p, _ := testReplicationPlan(t)
	dir := t.TempDir()
	r := ReplicationReport{Version: ReplicationVersion, Run: p.Inventory.Run, Plan: p.Digest, Live: true, Verdict: result.Pass}
	b, _ := json.Marshal(r)
	if err := os.WriteFile(filepath.Join(dir, "replication-report.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := ReplayReplication(dir)
	if err != nil || out.Live || out.Verdict != result.Inconclusive {
		t.Fatal("unsigned forged PASS became trusted")
	}
}
func FuzzReplicationUntrustedEvidence(f *testing.F) {
	seed, _ := json.Marshal(ReplicationExample("healthy"))
	f.Add(seed)
	f.Add([]byte(`{"version":"themis.postgres-replication/v1alpha1"}`))
	f.Add([]byte(`{"version":"x","Version":"y"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		if c, err := parseReplicationContract(b); err == nil {
			canonical, _ := json.Marshal(c)
			roundtrip, e := parseReplicationContract(canonical)
			if e != nil || roundtrip != c || c.Validate() != nil {
				t.Fatal("accepted contract lost strict validation or canonical identity")
			}
		}
		var o ReplicationObservation
		if json.Unmarshal(b, &o) == nil && validReplicationState(ReplicationInventory{}, o, "0/100") {
			t.Fatal("unbound external evidence became verified")
		}
	})
}

func TestReplicationPublishedSchemaAndStrictContract(t *testing.T) {
	valid, _ := json.Marshal(ReplicationExample("healthy"))
	for _, invalid := range [][]byte{bytes.Replace(valid, []byte(`"maxLostCommits":0`), []byte(`"maxLostCommits":null`), 1), bytes.Replace(valid, []byte(`"version":`), []byte(`"Version":`), 1)} {
		if _, err := parseReplicationContract(invalid); err == nil {
			t.Fatal("null or case-mismatched contract field accepted")
		}
	}
	schema, err := jsonschema.NewCompiler().Compile("../../schemas/postgres-replication-v1alpha1.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"healthy", "time-violation", "missing-receipt", "cleanup-denied"} {
		path := filepath.Join("..", "..", "examples", "postgres-replication", scenario+".json")
		c, e := ReadReplicationContract(path)
		if e != nil || c != ReplicationExample(scenario) {
			t.Fatal("published example differs from accepted workflow")
		}
		data, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		var value any
		json.Unmarshal(data, &value)
		if e = schema.Validate(value); e != nil {
			t.Fatal(e)
		}
	}
	for _, data := range []string{`{}`, `{"version":"x","Version":"y"}`, `{} {}`, `{"version":"themis.postgres-replication/v1alpha1","name":"x","workflow":"remote-apply-fenced-failover-v1","scenario":"healthy","maxFailoverMillis":60000}`, `{"version":"themis.postgres-replication/v1alpha1","name":"x","workflow":"remote-apply-fenced-failover-v1","scenario":"healthy","maxFailoverMillis":60000,"maxLostCommits":0,"sql":"SELECT 1"}`} {
		if _, e := parseReplicationContract([]byte(data)); e == nil {
			t.Fatal("incomplete or untrusted contract accepted")
		}
	}
}
