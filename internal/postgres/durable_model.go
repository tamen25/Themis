package postgres

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"time"

	"github.com/tamen25/themis/internal/localstate"
)

const (
	DurableVersion  = "themis.postgres-durable/v1alpha1"
	DurableWorkflow = "pg-logical-persistent-sigkill-v1"
	DurableStorage  = "local-persistent-fixed-workload-v1"
	DurableAnchor   = "last-available-query-start-to-ready"
	DatabaseBytes   = 16 << 20
	FileBytes       = 8 << 20
)

// DurableContract is a separate wire type. A v1 temporary-storage contract or
// grant cannot be reinterpreted as authority for SIGKILL.
type DurableContract struct {
	Version           string   `json:"version"`
	Name              string   `json:"name"`
	Target            string   `json:"target"`
	Workflow          string   `json:"workflow"`
	Storage           string   `json:"storage"`
	Failure           string   `json:"failure"`
	BackupMethod      string   `json:"backupMethod"`
	RestoreMethod     string   `json:"restoreMethod"`
	TimingAnchor      string   `json:"timingAnchor"`
	Scenario          string   `json:"scenario"`
	MaxRecoveryMillis int64    `json:"maxRecoveryMillis"`
	MaxLostCommits    int      `json:"maxLostCommits"`
	MinReceipts       int      `json:"minReceipts"`
	RequiredTables    []string `json:"requiredTables"`
	Integrity         string   `json:"integrity"`
	CleanupRequired   bool     `json:"cleanupRequired"`
	MaxRuntimeSeconds int      `json:"maxRuntimeSeconds"`
	MaxBackupBytes    int64    `json:"maxBackupBytes"`
	MaxDatabaseBytes  int64    `json:"maxDatabaseBytes"`
	MaxVolumeBytes    int64    `json:"maxVolumeBytes"`
	MaxFileBytes      int64    `json:"maxFileBytes"`
}

func DurableExample(scenario string) DurableContract {
	return DurableContract{DurableVersion, "durable-recovery", "owned-docker-postgres", DurableWorkflow, DurableStorage, "docker-sigkill",
		"pg_dump-custom-1.16.0", "pg_restore-single-transaction", DurableAnchor, scenario, 60000, 0, BaselineCommits,
		[]string{"accounts", "health", "transactions"}, "exact-receipts-and-constraints", true, 120, BackupBytes, DatabaseBytes, VolumeBytes, FileBytes}
}
func (c DurableContract) Validate() error {
	if c.Version != DurableVersion || !namePattern.MatchString(c.Name) || c.Target != "owned-docker-postgres" || c.Workflow != DurableWorkflow || c.Storage != DurableStorage || c.Failure != "docker-sigkill" ||
		c.BackupMethod != "pg_dump-custom-1.16.0" || c.RestoreMethod != "pg_restore-single-transaction" || c.TimingAnchor != DurableAnchor || c.MaxRecoveryMillis < 1 || c.MaxRecoveryMillis > 60000 || c.MaxLostCommits < 0 || c.MaxLostCommits > 3 ||
		c.MinReceipts != BaselineCommits || !slices.Equal(c.RequiredTables, []string{"accounts", "health", "transactions"}) || c.Integrity != "exact-receipts-and-constraints" || !c.CleanupRequired ||
		c.MaxRuntimeSeconds != 120 || c.MaxBackupBytes != BackupBytes || c.MaxDatabaseBytes != DatabaseBytes || c.MaxVolumeBytes != VolumeBytes || c.MaxFileBytes != FileBytes {
		return errors.New("invalid durable PostgreSQL contract or unsupported budgets")
	}
	switch c.Scenario {
	case "healthy", "ack-loss", "missing-receipt", "cleanup-denied", "inflight-crash":
		return nil
	}
	return errors.New("unsupported durable synthetic scenario")
}
func ReadDurableContract(path string) (DurableContract, error) {
	var c DurableContract
	b, e := readBounded(path)
	if e != nil {
		return c, e
	}
	if len(b) > 65536 {
		return c, errors.New("contract exceeds 64KiB")
	}
	if e = localstate.Unmarshal(b, &c); e != nil {
		return c, e
	}
	return c, c.Validate()
}

type DurableInventory struct {
	Inventory
	Storage         string    `json:"storage"`
	CreatedAt       time.Time `json:"createdAt"`
	BackupDirectory string    `json:"backupDirectory"`
	BackupID        string    `json:"backupId"`
	CleanupKey      []byte    `json:"cleanupKey"`
	SourceStarted   string    `json:"sourceStarted"`
	RestoreStarted  string    `json:"restoreStarted"`
}
type durableKeys struct{ Approver, Ledger, Cleanup []byte }
type inventorySeal struct {
	Version, Digest string
	Signature       []byte
}

func (i DurableInventory) validate() error {
	if i.Version != DurableVersion || i.Storage != DurableStorage || !hexID.MatchString(i.Run) || i.Image != Image || len(i.ImageID) != 71 || !hexID.MatchString(i.ImageID[7:]) || i.ImageID[:7] != "sha256:" ||
		!filepath.IsAbs(i.Directory) || i.BackupDirectory != filepath.Join(i.Directory, "backup-store") || i.BackupID != digest("themis.postgres.durable.backup-id.v1", i.Run) || i.Actor.UID == "" || i.Engine == "" ||
		len(i.Approver) != 32 || len(i.LedgerKey) != 32 || len(i.CleanupKey) != 32 || bytes.Equal(i.Approver, i.CleanupKey) || bytes.Equal(i.LedgerKey, i.CleanupKey) || bytes.Equal(i.LedgerKey, i.Approver) ||
		!hexID.MatchString(i.Source.ID) || !hexID.MatchString(i.Restore.ID) || i.Source.ID == i.Restore.ID || i.Source.Role != "source" || i.Restore.Role != "restore" ||
		i.Source.DB.Database != Database || i.Restore.DB.Database != Database || i.Source.DB.Version != "180006" || i.Restore.DB.Version != "180006" || i.Source.DB.System == "" || i.Source.DB.System == i.Restore.DB.System ||
		i.Source.DB.Boot == "" || i.Restore.DB.Boot == "" || i.SourceStarted == "" || i.RestoreStarted == "" || i.CreatedAt.IsZero() || !i.CleanupBefore.After(i.CreatedAt) ||
		!hexID.MatchString(i.Network.ID) || i.Network.Name != "themis-pgd-"+i.Run || i.Network.Driver != "bridge" || !i.Network.Internal || !durableLabelsOK(i.Network.Labels, i.Run, "network") {
		return errors.New("invalid durable ownership inventory")
	}
	for _, r := range []Resource{i.Source, i.Restore} {
		if r.Volume.Name != "themis-pgd-"+i.Run+"-"+r.Role || r.Volume.Driver != "local" || len(r.Volume.Options) != 0 || r.Volume.CreatedAt == "" || !durableLabelsOK(r.Volume.Labels, i.Run, r.Role) {
			return errors.New("invalid persistent volume identity")
		}
	}
	return ValidateEndpoint(i.Endpoint)
}
func loadDurableInventory(dir string) (DurableInventory, error) {
	i, e := loadDurableControlInventory(dir)
	if e != nil {
		return i, e
	}
	return i, localstate.Check(i.BackupDirectory)
}

// Cleanup requires the protected original control records, not the continued
// existence of an execution artifact or backup directory.
func loadDurableControlInventory(dir string) (DurableInventory, error) {
	var i DurableInventory
	abs, e := filepath.Abs(dir)
	if e != nil {
		return i, e
	}
	if e = localstate.Read(filepath.Join(abs, "durable-ownership.json"), &i); e != nil {
		return i, e
	}
	a, e := localstate.CurrentActor()
	if e != nil {
		return i, e
	}
	if i.Directory != abs || i.Actor != a {
		return i, errors.New("original durable actor or directory mismatch")
	}
	if e = i.validate(); e != nil {
		return i, e
	}
	var seal inventorySeal
	if e = localstate.Read(filepath.Join(abs, "durable-ownership-seal.json"), &seal); e != nil {
		return i, e
	}
	want := digest("themis.postgres.durable.inventory.v1", i)
	if seal.Version != DurableVersion || seal.Digest != want || !ed25519.Verify(i.CleanupKey, []byte(want), seal.Signature) {
		return i, errors.New("protected ownership seal invalid")
	}
	return i, nil
}

type DurablePlan struct {
	Version   string           `json:"version"`
	Contract  DurableContract  `json:"contract"`
	Inventory DurableInventory `json:"inventory"`
	Digest    string           `json:"digest"`
}

func CompileDurable(c DurableContract, i DurableInventory) (DurablePlan, error) {
	if e := c.Validate(); e != nil {
		return DurablePlan{}, e
	}
	if e := i.validate(); e != nil {
		return DurablePlan{}, e
	}
	b, _ := json.Marshal(i)
	var snapshot DurableInventory
	if e := json.Unmarshal(b, &snapshot); e != nil {
		return DurablePlan{}, e
	}
	c.RequiredTables = slices.Clone(c.RequiredTables)
	p := DurablePlan{Version: DurableVersion, Contract: c, Inventory: snapshot}
	p.Digest = digest("themis.postgres.durable.plan.v1", p)
	return p, nil
}
func (p DurablePlan) Validate() error {
	q, e := CompileDurable(p.Contract, p.Inventory)
	if e != nil || p.Version != DurableVersion || p.Digest != q.Digest {
		return errors.New("durable plan digest or identity invalid")
	}
	return nil
}
func PlanDurableFile(dir string, c DurableContract) (DurablePlan, error) {
	i, e := loadDurableInventory(dir)
	if e != nil {
		return DurablePlan{}, e
	}
	p, e := CompileDurable(c, i)
	if e != nil {
		return p, e
	}
	return p, localstate.WriteNew(filepath.Join(i.Directory, "durable-plan.json"), p)
}
func loadDurablePlan(dir string) (DurablePlan, error) {
	var p DurablePlan
	i, e := loadDurableInventory(dir)
	if e != nil {
		return p, e
	}
	if e = localstate.Read(filepath.Join(i.Directory, "durable-plan.json"), &p); e != nil {
		return p, e
	}
	if e = p.Validate(); e != nil {
		return p, e
	}
	if digest("inventory", i) != digest("inventory", p.Inventory) {
		return p, errors.New("durable plan ownership mismatch")
	}
	return p, nil
}

// Two scopes deliberately require separate approvals. The failure grant includes
// the actual published archive identity; preparation can never authorize kill.
type DurableGrant struct {
	Version, Scope, Plan, Run, Engine, Endpoint, Source, SourceSystem, Restore, Database, Failure string
	BackupID, BackupSHA256                                                                        string
	BackupBytes                                                                                   int64
	StartBefore, ExecuteBefore, CleanupBefore                                                     time.Time
	Signature                                                                                     []byte
}

func durableGrantMessage(g DurableGrant) []byte {
	g.Signature = nil
	return []byte(digest("themis.postgres.durable.authorization.v1", g))
}
func validateDurableGrant(p DurablePlan, g DurableGrant, scope string, backup *DurableBackup, now time.Time, start bool) error {
	i := p.Inventory
	if p.Validate() != nil || g.Version != DurableVersion || g.Scope != scope || g.Plan != p.Digest || g.Run != i.Run || g.Engine != i.Engine || g.Endpoint != i.Endpoint || g.Source != i.Source.ID || g.SourceSystem != i.Source.DB.System || g.Restore != i.Restore.ID || g.Database != Database || g.BackupID != i.BackupID ||
		g.CleanupBefore != i.CleanupBefore || !g.ExecuteBefore.Before(g.CleanupBefore) || !g.ExecuteBefore.After(g.StartBefore) || g.ExecuteBefore.Sub(g.StartBefore) > 120*time.Second || !now.Before(g.ExecuteBefore) || (start && !now.Before(g.StartBefore)) || !ed25519.Verify(i.Approver, durableGrantMessage(g), g.Signature) {
		return errors.New("invalid, expired or mismatched durable authorization")
	}
	if scope == "prepare" {
		if g.Failure != "none" || g.BackupSHA256 != "" || g.BackupBytes != 0 {
			return errors.New("preparation grant includes fault authority")
		}
		return nil
	}
	if scope != "sigkill-source-once" || g.Failure != "SIGKILL" || backup == nil || g.BackupSHA256 != backup.SHA256 || g.BackupBytes != backup.Bytes {
		return errors.New("failure grant lacks exact published backup binding")
	}
	return nil
}
func approveDurable(dir, expected, backupHash, scope string) (DurableGrant, error) {
	p, e := loadDurablePlan(dir)
	if e != nil {
		return DurableGrant{}, e
	}
	if p.Digest != expected {
		return DurableGrant{}, errors.New("reviewed durable plan mismatch")
	}
	var k durableKeys
	if e = localstate.Read(filepath.Join(p.Inventory.Directory, "durable-keys.json"), &k); e != nil {
		return DurableGrant{}, e
	}
	if len(k.Approver) != 64 || !bytes.Equal(ed25519.PrivateKey(k.Approver).Public().(ed25519.PublicKey), p.Inventory.Approver) {
		return DurableGrant{}, errors.New("durable approver key mismatch")
	}
	now := time.Now().UTC()
	i := p.Inventory
	g := DurableGrant{Version: DurableVersion, Scope: scope, Plan: p.Digest, Run: i.Run, Engine: i.Engine, Endpoint: i.Endpoint, Source: i.Source.ID, SourceSystem: i.Source.DB.System, Restore: i.Restore.ID, Database: Database, Failure: "none", BackupID: i.BackupID, StartBefore: now.Add(30 * time.Second), ExecuteBefore: now.Add(150 * time.Second), CleanupBefore: i.CleanupBefore}
	path := "durable-prepare-authorization.json"
	if scope == "sigkill-source-once" {
		f, b, e := openDurableBackup(p)
		if e != nil {
			return g, e
		}
		f.Close()
		if b.SHA256 != backupHash {
			return g, errors.New("reviewed backup SHA256 mismatch")
		}
		g.Failure = "SIGKILL"
		g.BackupSHA256 = b.SHA256
		g.BackupBytes = b.Bytes
		path = "durable-failure-authorization.json"
	}
	g.Signature = ed25519.Sign(k.Approver, durableGrantMessage(g))
	if !g.ExecuteBefore.Before(i.CleanupBefore) {
		return g, errors.New("insufficient remaining cleanup authority")
	}
	return g, localstate.WriteNew(filepath.Join(i.Directory, path), g)
}
func ApprovePreparation(dir, expected string) (DurableGrant, error) {
	return approveDurable(dir, expected, "", "prepare")
}
func ApproveFailure(dir, expected, backupSHA256 string) (DurableGrant, error) {
	return approveDurable(dir, expected, backupSHA256, "sigkill-source-once")
}
