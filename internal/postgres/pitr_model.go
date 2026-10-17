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
	PITRVersion            = "themis.postgres-pitr/v1alpha1"
	PITRWorkflow           = "physical-named-target-sigkill-v1"
	PITRBackupBytes  int64 = 64 << 20
	PITRWALBytes     int64 = 32 << 20
	PITRSegmentBytes int64 = 1 << 20
	PITRBoundary           = 20
)

// PITR has its own contracts and authority. Logical recovery grants cannot be
// decoded or verified as authority for a physical recovery experiment.
type PITRContract struct {
	Version           string `json:"version"`
	Name              string `json:"name"`
	Workflow          string `json:"workflow"`
	Scenario          string `json:"scenario"`
	MaxRecoveryMillis int64  `json:"maxRecoveryMillis"`
	MaxLostCommits    int    `json:"maxLostCommits"`
	MaxBackupBytes    int64  `json:"maxBackupBytes"`
	MaxWALBytes       int64  `json:"maxWalBytes"`
}

func PITRExample(scenario string) PITRContract {
	return PITRContract{PITRVersion, "physical-pitr", PITRWorkflow, scenario, 60000, 0, PITRBackupBytes, PITRWALBytes}
}
func (c PITRContract) Validate() error {
	if c.Version != PITRVersion || !namePattern.MatchString(c.Name) || c.Workflow != PITRWorkflow || c.MaxRecoveryMillis < 1 || c.MaxRecoveryMillis > 60000 || c.MaxLostCommits != 0 || c.MaxBackupBytes != PITRBackupBytes || c.MaxWALBytes != PITRWALBytes {
		return errors.New("invalid physical PITR contract or budgets")
	}
	switch c.Scenario {
	case "healthy", "ack-loss", "missing-wal", "cleanup-denied", "inflight-crash":
		return nil
	}
	return errors.New("unsupported physical PITR scenario")
}
func ReadPITRContract(path string) (c PITRContract, err error) {
	b, err := readBounded(path)
	if err != nil {
		return c, err
	}
	if len(b) > 65536 {
		return c, errors.New("contract exceeds 64KiB")
	}
	if err = localstate.Unmarshal(b, &c); err != nil {
		return c, err
	}
	return c, c.Validate()
}

type PITRInventory struct {
	Inventory
	Archive    Resource
	CreatedAt  time.Time
	CleanupKey []byte
	Profiles   map[string]string
	Starts     map[string]string
}
type pitrKeys struct {
	Approver, Ledger, Cleanup []byte
	Password                  string
}

func (i PITRInventory) resources() []Resource { return []Resource{i.Source, i.Restore, i.Archive} }
func (i PITRInventory) validate() error {
	if i.Version != PITRVersion || !hexID.MatchString(i.Run) || i.Image != Image || len(i.ImageID) != 71 || i.ImageID[:7] != "sha256:" || !hexID.MatchString(i.ImageID[7:]) || !filepath.IsAbs(i.Directory) || i.Actor.UID == "" || len(i.Engine) < 16 || len(i.Approver) != 32 || len(i.LedgerKey) != 32 || len(i.CleanupKey) != 32 || bytes.Equal(i.Approver, i.LedgerKey) || bytes.Equal(i.CleanupKey, i.Approver) || bytes.Equal(i.CleanupKey, i.LedgerKey) || i.CreatedAt.IsZero() || i.CleanupBefore.Sub(i.CreatedAt) != 30*time.Minute || len(i.Profiles) != 3 || len(i.Starts) != 3 {
		return errors.New("invalid physical PITR original inventory")
	}
	ids, volumes := map[string]bool{}, map[string]bool{}
	for n, r := range i.resources() {
		role := []string{"source", "restore", "archive"}[n]
		if r.Role != role || !hexID.MatchString(r.ID) || ids[r.ID] || volumes[r.Volume.Name] || r.Volume.Name != "themis-pgp-"+i.Run+"-"+role || r.Volume.Driver != "local" || len(r.Volume.Options) != 0 || r.Volume.CreatedAt == "" || !pitrLabelsOK(r.Volume.Labels, i.Run, role) || !hexID.MatchString(i.Profiles[role]) || i.Starts[role] == "" {
			return errors.New("PITR original container, volume or profile invalid")
		}
		ids[r.ID], volumes[r.Volume.Name] = true, true
	}
	if i.Source.DB.System == "" || i.Source.DB.Boot == "" || i.Source.DB.Version != "180006" || i.Source.DB.Database != Database || i.Restore.DB != (DBIdentity{}) || i.Archive.DB != (DBIdentity{}) || !hexID.MatchString(i.Network.ID) || i.Network.Name != "themis-pgp-"+i.Run || !i.Network.Internal || i.Network.Driver != "bridge" || !pitrLabelsOK(i.Network.Labels, i.Run, "network") {
		return errors.New("PITR database or network identity invalid")
	}
	return ValidateEndpoint(i.Endpoint)
}
func pitrInventoryHash(i PITRInventory) string { return digest("themis.postgres.pitr.inventory.v1", i) }
func loadPITRInventory(dir string) (i PITRInventory, err error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return i, err
	}
	if err = localstate.Read(filepath.Join(abs, "pitr-ownership.json"), &i); err != nil {
		return i, err
	}
	a, err := localstate.CurrentActor()
	if err != nil {
		return i, err
	}
	if i.Directory != abs || i.Actor != a {
		return i, errors.New("original PITR actor or directory mismatch")
	}
	if err = i.validate(); err != nil {
		return i, err
	}
	var s inventorySeal
	if err = localstate.Read(filepath.Join(abs, "pitr-ownership-seal.json"), &s); err != nil {
		return i, err
	}
	if s.Version != PITRVersion || s.Digest != pitrInventoryHash(i) || !ed25519.Verify(i.CleanupKey, []byte(s.Digest), s.Signature) {
		return i, errors.New("PITR ownership seal invalid")
	}
	return i, nil
}

type PITRPlan struct {
	Version        string        `json:"version"`
	Contract       PITRContract  `json:"contract"`
	Inventory      PITRInventory `json:"inventory"`
	TargetName     string        `json:"targetName"`
	TargetTimeline int           `json:"targetTimeline"`
	TargetBoundary int           `json:"targetBoundary"`
	Digest         string        `json:"digest"`
}

func CompilePITR(c PITRContract, i PITRInventory) (p PITRPlan, err error) {
	if err = c.Validate(); err != nil {
		return p, err
	}
	if err = i.validate(); err != nil {
		return p, err
	}
	// JSON round-trip makes the plan independent of caller-owned maps/slices.
	b, _ := json.Marshal(i)
	var snapshot PITRInventory
	if err = localstate.Unmarshal(b, &snapshot); err != nil {
		return p, err
	}
	p = PITRPlan{Version: PITRVersion, Contract: c, Inventory: snapshot, TargetName: "themis_" + i.Run[:32], TargetTimeline: 1, TargetBoundary: PITRBoundary}
	p.Digest = digest("themis.postgres.pitr.preparation-plan.v1", p)
	return p, nil
}
func (p PITRPlan) Validate() error {
	q, err := CompilePITR(p.Contract, p.Inventory)
	if err != nil || digest("plan", p) != digest("plan", q) {
		return errors.New("physical PITR plan identity or digest invalid")
	}
	return nil
}
func PlanPITRFile(dir string, c PITRContract) (PITRPlan, error) {
	i, err := loadPITRInventory(dir)
	if err != nil {
		return PITRPlan{}, err
	}
	p, err := CompilePITR(c, i)
	if err != nil {
		return p, err
	}
	return p, localstate.WriteNew(filepath.Join(i.Directory, "pitr-plan.json"), p)
}
func loadPITRPlan(dir string) (p PITRPlan, err error) {
	i, err := loadPITRInventory(dir)
	if err != nil {
		return p, err
	}
	if err = localstate.Read(filepath.Join(i.Directory, "pitr-plan.json"), &p); err != nil {
		return p, err
	}
	if err = p.Validate(); err != nil {
		return p, err
	}
	if pitrInventoryHash(p.Inventory) != pitrInventoryHash(i) {
		return p, errors.New("PITR plan original inventory mismatch")
	}
	return p, nil
}

type PITRGrant struct {
	Version, Scope, Plan, Prepared, Inventory string
	StartBefore, ExecuteBefore                time.Time
	Signature                                 []byte
}

func pitrGrantMessage(g PITRGrant) []byte {
	g.Signature = nil
	return []byte(digest("themis.postgres.pitr.authority.v1", g))
}
func validatePITRGrant(p PITRPlan, g PITRGrant, scope, prepared string, now time.Time, start bool) error {
	if p.Validate() != nil || g.Version != PITRVersion || g.Scope != scope || g.Plan != p.Digest || g.Prepared != prepared || g.Inventory != pitrInventoryHash(p.Inventory) || !g.ExecuteBefore.Before(p.Inventory.CleanupBefore) || g.ExecuteBefore.Sub(g.StartBefore) != 120*time.Second || !now.Before(g.ExecuteBefore) || (start && !now.Before(g.StartBefore)) || !ed25519.Verify(p.Inventory.Approver, pitrGrantMessage(g), g.Signature) || (scope != "prepare" && scope != "sigkill-physical-target-once") {
		return errors.New("invalid, expired or mismatched physical PITR grant")
	}
	if (scope == "prepare") != (prepared == "") {
		return errors.New("PITR preparation and failure scopes are distinct")
	}
	return nil
}
func pitrLoadKeys(i PITRInventory) (k pitrKeys, err error) {
	if err = localstate.Read(filepath.Join(i.Directory, "pitr-keys.json"), &k); err != nil {
		return k, err
	}
	for _, pair := range []struct{ private, public []byte }{{k.Approver, i.Approver}, {k.Ledger, i.LedgerKey}, {k.Cleanup, i.CleanupKey}} {
		if len(pair.private) != 64 || !bytes.Equal(ed25519.PrivateKey(pair.private).Public().(ed25519.PublicKey), pair.public) {
			return k, errors.New("PITR key pair mismatch")
		}
	}
	if !hexID.MatchString(k.Password) {
		return k, errors.New("PITR private database credential invalid")
	}
	return k, nil
}
func ApprovePITR(dir, expected, scope string) (g PITRGrant, err error) {
	p, err := loadPITRPlan(dir)
	if err != nil {
		return g, err
	}
	prepared := ""
	if scope == "sigkill-physical-target-once" {
		s, err := loadPITRPrepared(p)
		if err != nil {
			return g, err
		}
		prepared = s.Digest
		if err = verifyPITRCapsule(p, s); err != nil {
			return g, err
		}
	}
	want := p.Digest
	if prepared != "" {
		want = prepared
	}
	if expected != want {
		return g, errors.New("reviewed PITR plan digest mismatch")
	}
	k, err := pitrLoadKeys(p.Inventory)
	if err != nil {
		return g, err
	}
	now := time.Now().UTC()
	g = PITRGrant{PITRVersion, scope, p.Digest, prepared, pitrInventoryHash(p.Inventory), now.Add(30 * time.Second), now.Add(150 * time.Second), nil}
	g.Signature = ed25519.Sign(k.Approver, pitrGrantMessage(g))
	if err = validatePITRGrant(p, g, scope, prepared, now, true); err != nil {
		return g, err
	}
	return g, localstate.WriteNew(filepath.Join(p.Inventory.Directory, "pitr-"+scope+"-authorization.json"), g)
}
