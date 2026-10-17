package postgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

func replaceDurableTestFile(t *testing.T, path string, v any) func() {
	t.Helper()
	old, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	return func() {
		if e := os.WriteFile(path, old, 0600); e != nil {
			t.Fatal(e)
		}
	}
}
func TestRealDurableArtifactAndAdmission(t *testing.T) {
	dir, p := durableLivePrepare(t, "healthy")
	i := p.Inventory
	d := Docker{i.Endpoint, i.Engine}
	ctx := context.Background()
	for _, kind := range []string{"wrong-engine", "remote-endpoint", "wrong-source", "wrong-restore", "wrong-label", "wrong-volume", "wrong-actor", "missing-inventory", "corrupt-inventory", "cleanup-auth", "cleanup-expired", "unrelated-delete"} {
		t.Run(kind, func(t *testing.T) {
			var e error
			switch kind {
			case "wrong-engine":
				e = (Docker{i.Endpoint, "other-engine"}).durableTarget(ctx, i, i.Source)
			case "remote-endpoint":
				e = (Docker{"tcp://127.0.0.1:2375", i.Engine}).durableTarget(ctx, i, i.Source)
			case "wrong-source":
				r := i.Source
				r.ID = i.Restore.ID
				e = d.durableTarget(ctx, i, r)
			case "wrong-restore":
				r := i.Restore
				r.ID = i.Source.ID
				e = d.durableTarget(ctx, i, r)
			case "wrong-label":
				r := i.Source
				r.Volume.Labels = map[string]string{ownerLabel: "unrelated"}
				e = d.durableVolume(ctx, i, r)
			case "wrong-volume":
				r := i.Source
				r.Volume.CreatedAt = "different"
				e = d.durableVolume(ctx, i, r)
			case "wrong-actor":
				v := i
				v.Actor.UID = "unrelated"
				restore := replaceDurableTestFile(t, filepath.Join(dir, "durable-ownership.json"), v)
				defer restore()
				_, e = loadDurableInventory(dir)
			case "missing-inventory":
				path := filepath.Join(dir, "durable-ownership.json")
				if e = os.Rename(path, path+".held"); e != nil {
					t.Fatal(e)
				}
				defer func() {
					if e := os.Rename(path+".held", path); e != nil {
						t.Fatal(e)
					}
				}()
				_, e = ReconcileDurable(ctx, dir)
			case "corrupt-inventory":
				restore := replaceDurableTestFile(t, filepath.Join(dir, "durable-ownership.json"), map[string]string{"corrupt": "true"})
				defer restore()
				_, e = ReconcileDurable(ctx, dir)
			case "cleanup-auth":
				var g durableCleanupGrant
				localstate.Read(filepath.Join(dir, "durable-cleanup-capability.json"), &g)
				g.Signature = nil
				restore := replaceDurableTestFile(t, filepath.Join(dir, "durable-cleanup-capability.json"), g)
				defer restore()
				r, err := ReconcileDurable(ctx, dir)
				if err != nil {
					t.Fatal(err)
				}
				if r.Complete {
					t.Fatal("unauthenticated cleanup succeeded")
				}
				e = errors.New(r.Reason)
			case "cleanup-expired":
				// Controlled signed expiry fixture; no host-clock change or wait.
				v := i
				v.CreatedAt = time.Now().UTC().Add(-time.Hour)
				v.CleanupBefore = time.Now().UTC().Add(-time.Second)
				var k durableKeys
				if e = localstate.Read(filepath.Join(dir, "durable-keys.json"), &k); e != nil {
					t.Fatal(e)
				}
				h := digest("themis.postgres.durable.inventory.v1", v)
				seal := inventorySeal{DurableVersion, h, ed25519.Sign(k.Cleanup, []byte(h))}
				g := durableCleanupGrant{Version: DurableVersion, Inventory: h, NotAfter: v.CleanupBefore}
				g.Signature = ed25519.Sign(k.Cleanup, cleanupGrantMessage(g))
				for name, val := range map[string]any{"durable-ownership.json": v, "durable-ownership-seal.json": seal, "durable-cleanup-capability.json": g} {
					restore := replaceDurableTestFile(t, filepath.Join(dir, name), val)
					defer restore()
				}
				r, err := ReconcileDurable(ctx, dir)
				if err != nil {
					t.Fatal(err)
				}
				if r.Complete || !strings.Contains(r.Reason, "expired") {
					t.Fatal("expired cleanup authority admitted")
				}
				e = errors.New(r.Reason)
			case "unrelated-delete":
				v := i
				v.Source.ID = strings.Repeat("f", 64)
				r := durableCleanup(ctx, v, false)
				if r.Complete || len(r.Actions) != 0 {
					t.Fatal("unrelated deletion accepted")
				}
				e = errors.New(r.Reason)
			}
			if e == nil {
				t.Fatal("negative admission accepted")
			}
			t.Logf("refused %s: %v", kind, e)
			c, err := d.durableContainer(ctx, i, i.Source, true)
			if err != nil || !c.State.Running {
				t.Fatal("admission negative changed original source")
			}
		})
	}
	path := filepath.Join(i.BackupDirectory, i.BackupID+".dump")
	original, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"truncated", "modified", "identical-substitute", "missing", "receipt-signature", "prepared-signature"} {
		t.Run(kind, func(t *testing.T) {
			var restore func()
			switch kind {
			case "truncated":
				if e := os.Truncate(path, 8); e != nil {
					t.Fatal(e)
				}
				restore = func() { os.WriteFile(path, original, 0600) }
			case "modified":
				v := bytes.Clone(original)
				v[len(v)-3] ^= 1
				if e := os.WriteFile(path, v, 0600); e != nil {
					t.Fatal(e)
				}
				restore = func() { os.WriteFile(path, original, 0600) }
			case "identical-substitute", "missing":
				if e := os.Rename(path, path+".held"); e != nil {
					t.Fatal(e)
				}
				if kind == "identical-substitute" {
					if e := os.WriteFile(path, original, 0600); e != nil {
						t.Fatal(e)
					}
				}
				restore = func() {
					os.Remove(path)
					if e := os.Rename(path+".held", path); e != nil {
						t.Fatal(e)
					}
				}
			case "receipt-signature":
				var b DurableBackup
				localstate.Read(filepath.Join(dir, "durable-backup-receipt.json"), &b)
				b.Signature = nil
				restore = replaceDurableTestFile(t, filepath.Join(dir, "durable-backup-receipt.json"), b)
			case "prepared-signature":
				s, e := loadPrepared(p)
				if e != nil {
					t.Fatal(e)
				}
				s.Signature = nil
				restore = replaceDurableTestFile(t, filepath.Join(dir, "durable-prepared.json"), s)
			}
			defer restore()
			f, _, e := openDurableBackup(p)
			if e == nil {
				f.Close()
				t.Fatal("untrusted archive admitted")
			}
			if _, e = RunDurable(ctx, dir); e == nil {
				t.Fatal("untrusted backup reached fault invocation")
			}
			if _, e = os.Stat(filepath.Join(dir, "durable-invocation.json")); !os.IsNotExist(e) {
				t.Fatal("backup failure consumed fault authority")
			}
			t.Logf("refused actual host artifact %s", kind)
		})
	}
	// Exercise the actual kernel per-file limit with one bounded owned file.
	for _, kind := range []string{"expired-fault", "invalid-fault-signature", "preparation-reuse", "t30-grant-reuse"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(dir, "durable-failure-authorization.json")
			var g DurableGrant
			if e := localstate.Read(path, &g); e != nil {
				t.Fatal(e)
			}
			var val any = g
			switch kind {
			case "expired-fault":
				var k durableKeys
				localstate.Read(filepath.Join(dir, "durable-keys.json"), &k)
				g.StartBefore = time.Now().UTC().Add(-121 * time.Second)
				g.ExecuteBefore = time.Now().UTC().Add(-time.Second)
				g.Signature = ed25519.Sign(k.Approver, durableGrantMessage(g))
				val = g
			case "invalid-fault-signature":
				g.Signature = nil
				val = g
			case "preparation-reuse":
				var prep DurableGrant
				localstate.Read(filepath.Join(dir, "durable-prepare-authorization.json"), &prep)
				val = prep
			case "t30-grant-reuse":
				val = Grant{Version: Version, Plan: p.Digest, Run: i.Run, Database: Database, Operations: "seed,commit,backup,stop-source,restore,verify"}
			}
			restore := replaceDurableTestFile(t, path, val)
			defer restore()
			if _, e := RunDurable(ctx, dir); e == nil {
				t.Fatal("invalid/reused authority admitted")
			}
			if _, e := os.Stat(filepath.Join(dir, "durable-invocation.json")); !os.IsNotExist(e) {
				t.Fatal("invalid authority consumed invocation")
			}
			t.Logf("actual run admission refused %s without fault effect", kind)
		})
	}
	_, e = d.output(ctx, nil, "exec", "--user", "999:999", i.Source.ID, "dd", "if=/dev/zero", "of=/var/lib/postgresql/themis-limit-check", "bs=1048576", "count=9")
	if e == nil {
		t.Fatal("per-file hard budget did not stop actual write")
	}
	size, err := d.output(ctx, nil, "exec", "--user", "999:999", i.Source.ID, "stat", "-c", "%s", "/var/lib/postgresql/themis-limit-check")
	if err != nil || strings.TrimSpace(string(size)) != "8388608" {
		t.Fatalf("file limit not observed: %v", err)
	}
	if _, err = d.output(ctx, nil, "exec", "--user", "999:999", i.Source.ID, "rm", "--", "/var/lib/postgresql/themis-limit-check"); err != nil {
		t.Fatal(err)
	}
	exit := toolExit(e)
	if exit == nil || *exit == 0 {
		t.Fatal("file budget refusal did not have an observed nonzero native child exit")
	}
	t.Logf("actual kernel file-size budget refused byte 8388609, native child exit=%d", *exit)
	// An actual restart changes the original postmaster identity. It is denied
	// for experiments while exact-ID cleanup remains independently authorized.
	if _, e = d.output(ctx, nil, "restart", "--time", "1", i.Source.ID); e != nil {
		t.Fatal(e)
	}
	if e = d.durableTarget(ctx, i, i.Source); e == nil {
		t.Fatal("real restarted source admitted")
	}
	t.Log("actual restart refused; exact originally owned cleanup remains permitted")
}

func TestRealDurableNegativeRecovery(t *testing.T) {
	for _, kind := range []string{"nonempty", "corrupt-row", "duplicate-row", "forged-receipt", "missing-plus-loss", "before-intent", "backup-missing-after-source-removal", "journal-corruption"} {
		t.Run(kind, func(t *testing.T) {
			scenario := "healthy"
			if kind == "missing-plus-loss" {
				scenario = "ack-loss"
			}
			dir, p := durableLivePrepare(t, scenario)
			d := Docker{p.Inventory.Endpoint, p.Inventory.Engine}
			opts := durableOptions{after: func(stage string, p DurablePlan) error {
				switch {
				case kind == "nonempty" && stage == "before-failure-intent":
					_, e := d.sql(context.Background(), p.Inventory.Restore.ID, "CREATE TABLE public.unexpected(id int);")
					return e
				case kind == "before-intent" && stage == "before-failure-intent":
					return localstate.WriteNew(filepath.Join(dir, "durable-failure-intent.json"), map[string]string{"blocked": "controlled publication conflict"})
				case kind == "backup-missing-after-source-removal" && stage == "source-observed":
					if _, e := d.durableContainer(context.Background(), p.Inventory, p.Inventory.Source, false); e != nil {
						return e
					}
					if _, e := d.output(context.Background(), nil, "container", "rm", p.Inventory.Source.ID); e != nil {
						return e
					}
					if e := os.Remove(filepath.Join(p.Inventory.BackupDirectory, p.Inventory.BackupID+".dump")); e != nil {
						return e
					}
					return os.Remove(p.Inventory.BackupDirectory)
				case kind == "corrupt-row" && stage == "restored":
					_, e := d.sql(context.Background(), p.Inventory.Restore.ID, "UPDATE themis_app.transactions SET payload=repeat('a',64) WHERE id=1;")
					return e
				case kind == "duplicate-row" && stage == "restored":
					_, e := d.sql(context.Background(), p.Inventory.Restore.ID, "ALTER TABLE themis_app.transactions DROP CONSTRAINT transactions_pkey; INSERT INTO themis_app.transactions SELECT * FROM themis_app.transactions WHERE id=1;")
					return e
				case kind == "forged-receipt" && stage == "restored":
					var r DurableReceipt
					if e := localstate.Read(filepath.Join(dir, "durable-receipt-08.json"), &r); e != nil {
						return e
					}
					r.Signature[0] ^= 1
					b, _ := json.Marshal(r)
					return os.WriteFile(filepath.Join(dir, "durable-receipt-08.json"), b, 0600)
				case kind == "missing-plus-loss" && stage == "restored":
					return os.Remove(filepath.Join(dir, "durable-receipt-08.json"))
				case kind == "journal-corruption" && stage == "source-observed":
					f, e := os.OpenFile(filepath.Join(dir, "durable-journal.jsonl"), os.O_APPEND|os.O_WRONLY, 0600)
					if e != nil {
						return e
					}
					defer f.Close()
					_, e = f.WriteString("partial")
					return e
				}
				return nil
			}}
			r, e := runDurable(context.Background(), dir, opts)
			if e != nil {
				t.Fatal(e)
			}
			exportDurable(t, dir, r)
			if r.Verdict == result.Pass || !r.Cleanup.Complete {
				t.Fatalf("unsafe negative %s cleanup=%v %s", r.Verdict, r.Cleanup.Complete, r.Problem)
			}
			if (kind == "corrupt-row" || kind == "duplicate-row" || kind == "missing-plus-loss") && r.Verdict != result.Fail {
				t.Fatal("credible guarantee violation lost FAIL")
			}
			if kind == "before-intent" && r.Measurements.FailureObserved {
				t.Fatal("failure occurred without durable intent")
			}
			if kind == "backup-missing-after-source-removal" {
				if _, e := os.Stat(filepath.Join(p.Inventory.BackupDirectory, p.Inventory.BackupID+".dump")); !os.IsNotExist(e) {
					t.Fatal("missing-backup negative did not actually remove the archive")
				}
				if !r.Measurements.FailureObserved || r.Measurements.RestoreExit != nil {
					t.Fatal("missing archive was not refused after actual source termination/removal")
				}
			}
			if kind == "journal-corruption" {
				before, _ := os.ReadFile(filepath.Join(dir, "durable-journal.jsonl"))
				c, e := ReconcileDurable(context.Background(), dir)
				after, _ := os.ReadFile(filepath.Join(dir, "durable-journal.jsonl"))
				if e != nil || !c.Complete || !bytes.Equal(before, after) {
					t.Fatal("journal corruption prevented independent cleanup or history changed")
				}
			}
		})
	}
}

// Ensure an interrupted actual write cannot publish a prepared backup, and a
// lost acknowledgement after an actual COMMIT cannot publish its host receipt.
func TestRealDurablePreparationFailures(t *testing.T) {
	for _, kind := range []string{"interrupted-write", "lost-ack", "before-publication"} {
		t.Run(kind, func(t *testing.T) {
			dir, p := durableLiveSetup(t, "healthy")
			opts := durableOptions{}
			switch kind {
			case "interrupted-write":
				opts.backupOutput = func(w io.Writer) io.Writer { return &failAfterBytes{w: w, left: 100} }
			case "lost-ack":
				opts.acknowledgement = func(id int, v string, e error) (string, error) {
					if id == 3 && e == nil {
						return "", errors.New("observed COMMIT acknowledgement deliberately discarded")
					}
					return v, e
				}
			case "before-publication":
				opts.after = func(stage string, p DurablePlan) error {
					if stage == "backup-validated" {
						return errors.New("controlled interruption before exclusive publication")
					}
					return nil
				}
			}
			if _, e := prepareDurable(context.Background(), dir, opts); e == nil {
				t.Fatal("incomplete preparation succeeded")
			}
			if _, e := os.Stat(filepath.Join(dir, "durable-prepared.json")); !os.IsNotExist(e) {
				t.Fatal("incomplete backup acquired preparation seal")
			}
			if _, e := ApproveFailure(dir, p.Digest, strings.Repeat("a", 64)); e == nil {
				t.Fatal("incomplete backup authorized SIGKILL")
			}
			d := Docker{p.Inventory.Endpoint, p.Inventory.Engine}
			if _, e := d.durableContainer(context.Background(), p.Inventory, p.Inventory.Source, true); e != nil {
				t.Fatal("preparation failure terminated source")
			}
			if kind == "lost-ack" {
				if _, e := os.Stat(filepath.Join(dir, "durable-receipt-03.json")); !os.IsNotExist(e) {
					t.Fatal("lost acknowledgement manufactured receipt")
				}
				v, e := d.sql(context.Background(), p.Inventory.Source.ID, "SELECT count(*) FROM themis_app.transactions WHERE id=3;")
				if e != nil || v != "1" {
					t.Fatal("lost-ack test did not commit actual PostgreSQL row")
				}
			}
			t.Logf("actual %s denied failure authority, source remains available", kind)
		})
	}
}

type failAfterBytes struct {
	w    io.Writer
	left int
}

func (w *failAfterBytes) Write(p []byte) (int, error) {
	if len(p) > w.left {
		n, e := w.w.Write(p[:w.left])
		w.left = 0
		if e != nil {
			return n, e
		}
		return n, errors.New("controlled interrupted archive write")
	}
	n, e := w.w.Write(p)
	w.left -= n
	return n, e
}

func TestDurableArchiveExpansionLimit(t *testing.T) {
	w := &boundedDiscard{left: 3}
	if n, e := w.Write([]byte("1234")); e == nil || n != 0 {
		t.Fatal("expansion budget ignored")
	}
	if _, e := fmt.Fprint(w, "123"); e != nil {
		t.Fatal(e)
	}
}

func TestRealDurableRecoveryTimeThreshold(t *testing.T) {
	c := DurableExample("healthy")
	c.MaxRecoveryMillis = 1
	dir, p := durableLiveSetupContract(t, c)
	s, e := PrepareDurable(context.Background(), dir)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ApproveFailure(dir, p.Digest, s.BackupSHA256); e != nil {
		t.Fatal(e)
	}
	r, e := RunDurable(context.Background(), dir)
	if e != nil {
		t.Fatal(e)
	}
	exportDurable(t, dir, r)
	if r.Verdict != result.Fail || r.Measurements.Timeline.RecoveryUpperNS <= int64(time.Millisecond) || !r.Measurements.ReadWriteReady || !r.Cleanup.Complete {
		t.Fatal("actual violated recovery duration did not FAIL")
	}
}
