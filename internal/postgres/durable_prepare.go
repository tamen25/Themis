package postgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"path/filepath"
	"time"

	"github.com/tamen25/themis/internal/localstate"
)

// These hooks are private test instrumentation around real operations. They do
// not expose arbitrary SQL, commands, file paths or alternate providers.
type durableOptions struct {
	after           func(string, DurablePlan) error
	backupOutput    func(io.Writer) io.Writer
	restoreInput    func(io.Reader) io.Reader
	acknowledgement func(int, string, error) (string, error)
}

func durableSigner(p DurablePlan) (ed25519.PrivateKey, error) {
	var k durableKeys
	if e := localstate.Read(filepath.Join(p.Inventory.Directory, "durable-keys.json"), &k); e != nil {
		return nil, e
	}
	if len(k.Ledger) != 64 || !bytes.Equal(ed25519.PrivateKey(k.Ledger).Public().(ed25519.PublicKey), p.Inventory.LedgerKey) {
		return nil, errors.New("durable receipt signer mismatch")
	}
	return k.Ledger, nil
}
func PrepareDurable(ctx context.Context, dir string) (PreparedBackup, error) {
	return prepareDurable(ctx, dir, durableOptions{})
}
func prepareDurable(ctx context.Context, dir string, opts durableOptions) (s PreparedBackup, err error) {
	p, e := loadDurablePlan(dir)
	if e != nil {
		return s, e
	}
	i := p.Inventory
	l, e := acquire(i.Directory)
	if e != nil {
		return s, e
	}
	defer l.Close()
	var g DurableGrant
	if e = localstate.Read(filepath.Join(i.Directory, "durable-prepare-authorization.json"), &g); e != nil {
		return s, e
	}
	if e = validateDurableGrant(p, g, "prepare", nil, time.Now(), true); e != nil {
		return s, e
	}
	k, e := durableSigner(p)
	if e != nil {
		return s, e
	}
	if e = localstate.WriteNew(filepath.Join(i.Directory, "durable-prepare-invocation.json"), map[string]string{"plan": p.Digest}); e != nil {
		return s, errors.New("preparation invocation consumed; no retry")
	}
	f, e := localstate.OpenNew(filepath.Join(i.Directory, "durable-prepare.jsonl"))
	if e != nil {
		return s, e
	}
	defer f.Close()
	if e = localstate.SyncDirectory(i.Directory); e != nil {
		return s, e
	}
	j := journal{w: f, start: time.Now(), plan: p.Digest, version: DurableVersion}
	deadline := j.start.Add(120 * time.Second)
	if g.ExecuteBefore.Before(deadline) {
		deadline = g.ExecuteBefore
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	d := Docker{i.Endpoint, i.Engine}
	defer func() {
		if err != nil {
			_ = j.append("PREPARATION_INCOMPLETE", map[string]string{"reason": "operation incomplete; failure not authorized"})
		}
	}()
	for _, r := range []Resource{i.Source, i.Restore} {
		if e = d.durableTarget(ctx, i, r); e != nil {
			return s, e
		}
		if _, e = d.durableBudget(ctx, r); e != nil {
			return s, e
		}
		v, e := d.sql(ctx, r.ID, emptySQL)
		if e != nil || v != "0" {
			return s, errors.New("preparation requires independently fresh source and destination")
		}
	}
	if e = j.append("SEED_INTENT", map[string]string{"source": i.Source.ID}); e != nil {
		return s, e
	}
	if _, e = d.sql(ctx, i.Source.ID, seedSQL); e != nil {
		return s, e
	}
	session := localstate.RandomID()
	previous := ""
	for id := 1; id <= BaselineCommits; id++ {
		if e = validateDurableGrant(p, g, "prepare", nil, time.Now(), false); e != nil {
			return s, e
		}
		r, e := durableCommit(ctx, d, p, k, &j, session, previous, id, opts)
		if e != nil {
			return s, e
		}
		previous = digest("durable-receipt", r)
	}
	s.Schema, e = d.sql(ctx, i.Source.ID, schemaSQL)
	if e != nil {
		return s, e
	}
	s.Storage, e = d.durableBudget(ctx, i.Source)
	if e != nil {
		return s, e
	}
	if e = d.durableTarget(ctx, i, i.Source); e != nil {
		return s, e
	}
	if e = d.durableTarget(ctx, i, i.Restore); e != nil {
		return s, e
	}
	if e = validateDurableGrant(p, g, "prepare", nil, time.Now(), false); e != nil {
		return s, e
	}
	b, e := publishDurableBackup(ctx, d, p, k, &j, opts)
	if e != nil {
		return s, e
	}
	if e = j.append("BACKUP_PUBLISHED", b); e != nil {
		return s, e
	}
	s.Version = DurableVersion
	s.Plan = p.Digest
	s.BackupSHA256 = b.SHA256
	s.Receipts = BaselineCommits
	s.ReceiptHead = previous
	s.JournalHead = j.previous
	s.Signature = ed25519.Sign(k, preparedMessage(s))
	err = localstate.WriteNew(filepath.Join(i.Directory, "durable-prepared.json"), s)
	return s, err
}
