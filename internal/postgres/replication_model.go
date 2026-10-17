package postgres

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"github.com/tamen25/themis/internal/localstate"
)

const (
	ReplicationVersion  = "themis.postgres-replication/v1alpha1"
	ReplicationWorkflow = "remote-apply-fenced-failover-v1"
	replicationCommits  = 20
	replicationNames    = "FIRST 1 (themis_standby)"
)

type ReplicationContract struct {
	Version           string `json:"version"`
	Name              string `json:"name"`
	Workflow          string `json:"workflow"`
	Scenario          string `json:"scenario"`
	MaxFailoverMillis int64  `json:"maxFailoverMillis"`
	MaxLostCommits    int    `json:"maxLostCommits"`
}

func ReplicationExample(scenario string) ReplicationContract {
	c := ReplicationContract{ReplicationVersion, "streaming-failover", ReplicationWorkflow, scenario, 60000, 0}
	if scenario == "time-violation" {
		c.MaxFailoverMillis = 1
	}
	return c
}
func (c ReplicationContract) Validate() error {
	if c.Version != ReplicationVersion || !namePattern.MatchString(c.Name) || c.Workflow != ReplicationWorkflow || c.MaxFailoverMillis < 1 || c.MaxFailoverMillis > 60000 || c.MaxLostCommits != 0 {
		return errors.New("invalid streaming replication contract or budgets")
	}
	switch c.Scenario {
	case "healthy", "time-violation", "missing-receipt", "cleanup-denied":
		return nil
	}
	return errors.New("unsupported replication scenario")
}
func ReadReplicationContract(path string) (c ReplicationContract, err error) {
	b, err := readBounded(path)
	if err != nil {
		return c, err
	}
	return parseReplicationContract(b)
}
func parseReplicationContract(b []byte) (c ReplicationContract, err error) {
	if len(b) > 65536 {
		return c, errors.New("contract exceeds 64KiB")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil || len(fields) != 6 {
		return c, errors.New("all replication contract fields are required")
	}
	for _, name := range []string{"version", "name", "workflow", "scenario", "maxFailoverMillis", "maxLostCommits"} {
		value, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return c, errors.New("replication contract requires exact non-null fields")
		}
	}
	if err = localstate.Unmarshal(b, &c); err != nil {
		return c, err
	}
	return c, c.Validate()
}

type ReplicationInventory struct {
	Version, Run, Directory, Endpoint, Engine, Image, ImageID       string
	Actor                                                           localstate.Actor
	Primary, Standby                                                Resource
	Network                                                         Network
	PrimaryIP, StandbyIP                                            string
	PrepareKey, TerminationKey, PromotionKey, LedgerKey, CleanupKey []byte
	CreatedAt, CleanupBefore                                        time.Time
	Profiles, Starts                                                map[string]string
}
type replicationKeys struct {
	Prepare, Termination, Promotion, Ledger, Cleanup []byte
	Password, ReplicationPassword                    string
}

func (i ReplicationInventory) resources() []Resource { return []Resource{i.Primary, i.Standby} }
func (i ReplicationInventory) validate() error {
	if i.Version != ReplicationVersion || !hexID.MatchString(i.Run) || !filepath.IsAbs(i.Directory) || i.Actor.UID == "" || len(i.Engine) < 16 || i.Image != Image || len(i.ImageID) != 71 || i.ImageID[:7] != "sha256:" || !hexID.MatchString(i.ImageID[7:]) || i.CreatedAt.IsZero() || i.CleanupBefore.Sub(i.CreatedAt) != 30*time.Minute || len(i.Profiles) != 2 || len(i.Starts) != 2 || !replicationIP(i.PrimaryIP) || !replicationIP(i.StandbyIP) || i.PrimaryIP == i.StandbyIP {
		return errors.New("invalid replication ownership inventory")
	}
	keys := [][]byte{i.PrepareKey, i.TerminationKey, i.PromotionKey, i.LedgerKey, i.CleanupKey}
	for n, k := range keys {
		if len(k) != 32 {
			return errors.New("invalid replication public key")
		}
		for _, prior := range keys[:n] {
			if bytes.Equal(k, prior) {
				return errors.New("replication authority keys must be distinct")
			}
		}
	}
	for n, r := range i.resources() {
		role := []string{"primary", "standby"}[n]
		if r.Role != role || !hexID.MatchString(r.ID) || r.Volume.Name != "themis-pgr-"+i.Run+"-"+role || r.Volume.Driver != "local" || len(r.Volume.Options) != 0 || r.Volume.CreatedAt == "" || !replicationLabelsOK(r.Volume.Labels, i.Run, role) || !hexID.MatchString(i.Profiles[role]) || i.Starts[role] == "" || r.DB.Database != Database || r.DB.Version != "180006" || r.DB.System == "" || r.DB.Boot == "" {
			return errors.New("invalid original replica, boot or volume identity")
		}
	}
	if i.Primary.ID == i.Standby.ID || i.Primary.DB.System != i.Standby.DB.System || i.Primary.DB.Boot == i.Standby.DB.Boot || !hexID.MatchString(i.Network.ID) || i.Network.Name != "themis-pgr-"+i.Run || i.Network.Driver != "bridge" || !i.Network.Internal || !replicationLabelsOK(i.Network.Labels, i.Run, "network") {
		return errors.New("physical replica or network identity invalid")
	}
	return ValidateEndpoint(i.Endpoint)
}
func replicationInventoryHash(i ReplicationInventory) string {
	return digest("themis.postgres.replication.inventory.v1", i)
}
func loadReplicationInventory(dir string) (i ReplicationInventory, err error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return i, err
	}
	if err = localstate.Read(filepath.Join(abs, "replication-ownership.json"), &i); err != nil {
		return i, err
	}
	a, err := localstate.CurrentActor()
	if err != nil {
		return i, err
	}
	if i.Directory != abs || i.Actor != a {
		return i, errors.New("original replication actor or directory mismatch")
	}
	if err = i.validate(); err != nil {
		return i, err
	}
	var s inventorySeal
	if err = localstate.Read(filepath.Join(abs, "replication-ownership-seal.json"), &s); err != nil {
		return i, err
	}
	if s.Version != ReplicationVersion || s.Digest != replicationInventoryHash(i) || !ed25519.Verify(i.CleanupKey, []byte(s.Digest), s.Signature) {
		return i, errors.New("replication ownership seal invalid")
	}
	return i, nil
}
func loadReplicationKeys(i ReplicationInventory) (k replicationKeys, err error) {
	if err = localstate.Read(filepath.Join(i.Directory, "replication-keys.json"), &k); err != nil {
		return k, err
	}
	for _, pair := range []struct{ private, public []byte }{{k.Prepare, i.PrepareKey}, {k.Termination, i.TerminationKey}, {k.Promotion, i.PromotionKey}, {k.Ledger, i.LedgerKey}, {k.Cleanup, i.CleanupKey}} {
		if len(pair.private) != 64 || !bytes.Equal(ed25519.PrivateKey(pair.private).Public().(ed25519.PublicKey), pair.public) {
			return k, errors.New("replication key pair mismatch")
		}
	}
	if !hexID.MatchString(k.Password) || !hexID.MatchString(k.ReplicationPassword) || k.Password == k.ReplicationPassword {
		return k, errors.New("replication private credentials invalid")
	}
	return k, nil
}

type ReplicationPlan struct {
	Version                         string               `json:"version"`
	Contract                        ReplicationContract  `json:"contract"`
	Inventory                       ReplicationInventory `json:"inventory"`
	Mode, Failure, Fence, Promotion string
	MaxDurationSeconds              int
	Limits                          ReplicationLimits
	Digest                          string `json:"digest"`
}

type ReplicationLimits struct {
	Containers, Volumes, Networks, CPUs, PIDs                    int
	MemoryBytes, FileBytes, DatabaseBytes, VolumeBytes, WALBytes int64
}

func CompileReplication(c ReplicationContract, i ReplicationInventory) (p ReplicationPlan, err error) {
	if err = c.Validate(); err != nil {
		return p, err
	}
	if err = i.validate(); err != nil {
		return p, err
	}
	b, _ := json.Marshal(i)
	var snapshot ReplicationInventory
	if err = localstate.Unmarshal(b, &snapshot); err != nil {
		return p, err
	}
	p = ReplicationPlan{Version: ReplicationVersion, Contract: c, Inventory: snapshot, Mode: "remote_apply", Failure: "SIGKILL-original-primary-once", Fence: "remove-stopped-original-container-and-observe-absence", Promotion: "pg_promote-original-standby-once", MaxDurationSeconds: 120, Limits: ReplicationLimits{2, 2, 1, 1, 64, MemoryBytes, FileBytes, DatabaseBytes, VolumeBytes, 32 << 20}}
	p.Digest = digest("themis.postgres.replication.plan.v1", p)
	return p, nil
}
func (p ReplicationPlan) Validate() error {
	q, e := CompileReplication(p.Contract, p.Inventory)
	if e != nil || digest("replication-plan", p) != digest("replication-plan", q) {
		return errors.New("replication plan identity or digest invalid")
	}
	return nil
}
func PlanReplicationFile(dir string, c ReplicationContract) (ReplicationPlan, error) {
	i, e := loadReplicationInventory(dir)
	if e != nil {
		return ReplicationPlan{}, e
	}
	p, e := CompileReplication(c, i)
	if e != nil {
		return p, e
	}
	return p, localstate.WriteNew(filepath.Join(i.Directory, "replication-plan.json"), p)
}
func loadReplicationPlan(dir string) (p ReplicationPlan, err error) {
	i, err := loadReplicationInventory(dir)
	if err != nil {
		return p, err
	}
	if err = localstate.Read(filepath.Join(i.Directory, "replication-plan.json"), &p); err != nil {
		return p, err
	}
	if err = p.Validate(); err != nil {
		return p, err
	}
	if replicationInventoryHash(p.Inventory) != replicationInventoryHash(i) {
		return p, errors.New("replication plan ownership mismatch")
	}
	return p, nil
}

type ReplicationGrant struct {
	Version, Scope, Plan, Prepared, Inventory, Invocation string
	StartBefore, ExecuteBefore                            time.Time
	Signature                                             []byte
}

func replicationGrantMessage(g ReplicationGrant) []byte {
	g.Signature = nil
	return []byte(digest("themis.postgres.replication.authority.v1", g))
}
func replicationGrantKey(i ReplicationInventory, scope string) []byte {
	switch scope {
	case "prepare":
		return i.PrepareKey
	case "terminate-and-fence":
		return i.TerminationKey
	case "promote-fenced-standby":
		return i.PromotionKey
	}
	return nil
}
func validateReplicationGrant(p ReplicationPlan, g ReplicationGrant, scope, prepared, invocation string, now time.Time, start bool) error {
	if scope != "prepare" && (!hexID.MatchString(prepared) || !hexID.MatchString(invocation)) {
		return errors.New("failover approval requires sealed preparation and one invocation")
	}
	k := replicationGrantKey(p.Inventory, scope)
	if p.Validate() != nil || len(k) != 32 || g.Version != ReplicationVersion || g.Scope != scope || g.Plan != p.Digest || g.Prepared != prepared || g.Inventory != replicationInventoryHash(p.Inventory) || g.Invocation != invocation || g.ExecuteBefore.Sub(g.StartBefore) != 120*time.Second || !g.ExecuteBefore.Before(p.Inventory.CleanupBefore) || !now.Before(g.ExecuteBefore) || (start && !now.Before(g.StartBefore)) || !ed25519.Verify(k, replicationGrantMessage(g), g.Signature) || (scope == "prepare") != (prepared == "" && invocation == "") {
		return errors.New("replication approval invalid, expired or mismatched")
	}
	return nil
}
func ApproveReplication(dir, expected, scope string) (g ReplicationGrant, err error) {
	p, err := loadReplicationPlan(dir)
	if err != nil {
		return g, err
	}
	if len(replicationGrantKey(p.Inventory, scope)) != 32 {
		return g, errors.New("unsupported replication authority scope")
	}
	prepared, invocation, want := "", "", p.Digest
	if scope != "prepare" {
		s, e := loadReplicationPrepared(p)
		if e != nil {
			return g, e
		}
		prepared, invocation, want = s.Digest, s.Invocation, s.Digest
	}
	if expected != want {
		return g, errors.New("reviewed replication digest mismatch")
	}
	k, err := loadReplicationKeys(p.Inventory)
	if err != nil {
		return g, err
	}
	private := k.Prepare
	if scope == "terminate-and-fence" {
		private = k.Termination
	}
	if scope == "promote-fenced-standby" {
		private = k.Promotion
	}
	now := time.Now().UTC()
	g = ReplicationGrant{ReplicationVersion, scope, p.Digest, prepared, replicationInventoryHash(p.Inventory), invocation, now.Add(30 * time.Second), now.Add(150 * time.Second), nil}
	g.Signature = ed25519.Sign(private, replicationGrantMessage(g))
	if err = validateReplicationGrant(p, g, scope, prepared, invocation, now, true); err != nil {
		return g, err
	}
	return g, localstate.WriteNew(filepath.Join(p.Inventory.Directory, "replication-"+scope+"-authorization.json"), g)
}
