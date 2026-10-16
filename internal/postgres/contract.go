// Package postgres implements one owned, local, synthetic logical recovery experiment.
// It deliberately has no Kubernetes dependencies or arbitrary SQL/DSN interface.
package postgres

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"slices"

	"github.com/tamen25/themis/internal/localstate"
)

const (
	Version         = "themis.postgres/v1alpha1"
	Workflow        = "pg-logical-v1"
	Image           = "docker.io/library/postgres:18.6-bookworm@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c"
	Database        = "themis_recovery"
	VolumeBytes     = 128 << 20
	BackupBytes     = 8 << 20
	MemoryBytes     = 256 << 20
	BaselineCommits = 16
)

var hexID = regexp.MustCompile(`^[a-f0-9]{64}$`)
var namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)

type Contract struct {
	Version           string   `json:"version"`
	Name              string   `json:"name"`
	Target            string   `json:"target"`
	Workflow          string   `json:"workflow"`
	BackupMethod      string   `json:"backupMethod"`
	RestoreMethod     string   `json:"restoreMethod"`
	Scenario          string   `json:"scenario"`
	MaxRestoreMillis  int64    `json:"maxRestoreMillis"`
	MaxLostCommits    int      `json:"maxLostCommits"`
	MinReceipts       int      `json:"minReceipts"`
	RequiredTables    []string `json:"requiredTables"`
	Integrity         string   `json:"integrity"`
	CleanupRequired   bool     `json:"cleanupRequired"`
	MaxRuntimeSeconds int      `json:"maxRuntimeSeconds"`
	MaxBackupBytes    int64    `json:"maxBackupBytes"`
	MaxVolumeBytes    int64    `json:"maxVolumeBytes"`
}

func Example(scenario string) Contract {
	return Contract{Version, "synthetic-recovery", "owned-docker-postgres", Workflow,
		"pg_dump-custom", "pg_restore-single-transaction", scenario, 60000, 0, BaselineCommits,
		[]string{"accounts", "health", "transactions"}, "exact-receipts-and-constraints", true, 120, BackupBytes, VolumeBytes}
}

func (c Contract) Validate() error {
	if c.Version != Version || !namePattern.MatchString(c.Name) || c.Target != "owned-docker-postgres" || c.Workflow != Workflow ||
		c.BackupMethod != "pg_dump-custom" || c.RestoreMethod != "pg_restore-single-transaction" ||
		c.MaxRestoreMillis < 1 || c.MaxRestoreMillis > 60000 || c.MaxLostCommits < 0 || c.MaxLostCommits > 32 ||
		c.MinReceipts != BaselineCommits || !slices.Equal(c.RequiredTables, []string{"accounts", "health", "transactions"}) ||
		c.Integrity != "exact-receipts-and-constraints" || !c.CleanupRequired || c.MaxRuntimeSeconds != 120 ||
		c.MaxBackupBytes != BackupBytes || c.MaxVolumeBytes != VolumeBytes {
		return errors.New("invalid PostgreSQL recovery contract or unsupported limits")
	}
	switch c.Scenario {
	case "healthy", "ack-loss", "missing-receipt", "cleanup-denied":
		return nil
	}
	return errors.New("unsupported synthetic scenario")
}

func ReadContract(path string) (Contract, error) {
	var c Contract
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(data) > 65536 {
		return c, errors.New("contract read failed or exceeds 64KiB")
	}
	if err := localstate.Unmarshal(data, &c); err != nil {
		return c, err
	}
	return c, c.Validate()
}

func digest(domain string, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	h := sha256.Sum256(append([]byte(domain+"\n"), b...))
	return hex.EncodeToString(h[:])
}

type Plan struct {
	Version   string    `json:"version"`
	Contract  Contract  `json:"contract"`
	Inventory Inventory `json:"inventory"`
	Digest    string    `json:"digest"`
}

func Compile(c Contract, i Inventory) (Plan, error) {
	if err := c.Validate(); err != nil {
		return Plan{}, err
	}
	if err := i.validate(); err != nil {
		return Plan{}, err
	}
	// Snapshot reference-bearing metadata, then verify the digest before effects.
	encoded, _ := json.Marshal(i)
	var snapshot Inventory
	if err := json.Unmarshal(encoded, &snapshot); err != nil {
		return Plan{}, err
	}
	p := Plan{Version: Version, Contract: c, Inventory: snapshot}
	p.Contract.RequiredTables = slices.Clone(c.RequiredTables)
	p.Digest = digest("themis.postgres.plan.v1", p)
	return p, nil
}

func (p Plan) Validate() error {
	q, err := Compile(p.Contract, p.Inventory)
	if err != nil || p.Version != Version || q.Digest != p.Digest {
		return errors.New("plan digest or identity invalid")
	}
	return nil
}
