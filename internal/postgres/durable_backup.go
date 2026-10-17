package postgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tamen25/themis/internal/localstate"
)

const dumpTool = "pg_dump (PostgreSQL) 18.6 (Debian 18.6-1.pgdg12+2)"
const restoreTool = "pg_restore (PostgreSQL) 18.6 (Debian 18.6-1.pgdg12+2)"

type DurableBackup struct {
	Version, Plan, Run, BackupID, Source, SourceSystem, Restore string
	SHA256, FileIdentity, Format, DumpVersion, RestoreVersion   string
	Bytes                                                       int64
	PublishedAt                                                 time.Time
	Signature                                                   []byte
}

func durableBackupMessage(b DurableBackup) []byte {
	b.Signature = nil
	return []byte(digest("themis.postgres.durable.backup.v1", b))
}

type PreparedBackup struct {
	Version, Plan, BackupSHA256, Schema, ReceiptHead, JournalHead string
	Receipts                                                      int
	Storage                                                       StorageObservation
	Signature                                                     []byte
}

func preparedMessage(b PreparedBackup) []byte {
	b.Signature = nil
	return []byte(digest("themis.postgres.durable.prepared.v1", b))
}
func loadPrepared(p DurablePlan) (PreparedBackup, error) {
	var s PreparedBackup
	if e := localstate.Read(filepath.Join(p.Inventory.Directory, "durable-prepared.json"), &s); e != nil {
		return s, e
	}
	if s.Version != DurableVersion || s.Plan != p.Digest || !hexID.MatchString(s.BackupSHA256) || s.Schema == "" || s.Receipts != BaselineCommits || !hexID.MatchString(s.ReceiptHead) || !hexID.MatchString(s.JournalHead) || !ed25519.Verify(p.Inventory.LedgerKey, preparedMessage(s), s.Signature) {
		return s, errors.New("prepared backup seal invalid")
	}
	return s, nil
}

func openDurableBackup(p DurablePlan) (*os.File, DurableBackup, error) {
	var b DurableBackup
	if e := localstate.Read(filepath.Join(p.Inventory.Directory, "durable-backup-receipt.json"), &b); e != nil {
		return nil, b, e
	}
	i := p.Inventory
	if b.Version != DurableVersion || b.Plan != p.Digest || b.Run != i.Run || b.BackupID != i.BackupID || b.Source != i.Source.ID || b.SourceSystem != i.Source.DB.System || b.Restore != i.Restore.ID || b.Bytes < 32 || b.Bytes > BackupBytes || b.Format != "PGDMP-1.16.0" || b.DumpVersion != dumpTool || b.RestoreVersion != restoreTool || b.PublishedAt.IsZero() || !hexID.MatchString(b.SHA256) || b.FileIdentity == "" || !ed25519.Verify(i.LedgerKey, durableBackupMessage(b), b.Signature) {
		return nil, b, errors.New("durable backup receipt invalid")
	}
	s, e := loadPrepared(p)
	if e != nil || s.BackupSHA256 != b.SHA256 {
		return nil, b, errors.New("backup publication incomplete or prepared seal mismatch")
	}
	path := filepath.Join(i.BackupDirectory, i.BackupID+".dump")
	if e = localstate.Check(i.BackupDirectory); e != nil {
		return nil, b, e
	}
	if e = localstate.Check(path); e != nil {
		return nil, b, e
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, b, e
	}
	if e = validateDurableFile(f, b); e != nil {
		f.Close()
		return nil, b, e
	}
	// Detect replacement between pathname validation and opening the handle.
	st, e := os.Lstat(path)
	if e != nil {
		f.Close()
		return nil, b, e
	}
	opened, e := f.Stat()
	if e != nil || !os.SameFile(st, opened) {
		f.Close()
		return nil, b, errors.New("backup pathname replaced")
	}
	return f, b, nil
}
func validateDurableFile(f *os.File, b DurableBackup) error {
	id, e := backupFileIdentity(f)
	if e != nil {
		return e
	}
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() != b.Bytes || id != b.FileIdentity {
		return errors.New("backup file identity or size changed")
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return e
	}
	var header [8]byte
	if _, e = io.ReadFull(f, header[:]); e != nil || !bytes.Equal(header[:], []byte{'P', 'G', 'D', 'M', 'P', 1, 16, 0}) {
		return errors.New("unexpected custom archive format")
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return e
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, BackupBytes+1))
	if e != nil || n != b.Bytes || hex.EncodeToString(h.Sum(nil)) != b.SHA256 {
		return errors.New("backup content digest mismatch")
	}
	_, e = f.Seek(0, io.SeekStart)
	return e
}

type boundedDiscard struct{ left int64 }

func (w *boundedDiscard) Write(p []byte) (int, error) {
	if int64(len(p)) > w.left {
		return 0, errors.New("archive expansion exceeds budget")
	}
	w.left -= int64(len(p))
	return len(p), nil
}

// Publication is deliberately ordered: sync complete bytes, validate the full
// custom archive through the pinned tool, link without replacement, sync the
// directory, then publish signed metadata and finally the preparation seal.
// A crash at any intermediate boundary cannot produce an eligible backup.
func publishDurableBackup(ctx context.Context, d Docker, p DurablePlan, k ed25519.PrivateKey, j *journal, opts durableOptions) (DurableBackup, error) {
	i := p.Inventory
	b := DurableBackup{Version: DurableVersion, Plan: p.Digest, Run: i.Run, BackupID: i.BackupID, Source: i.Source.ID, SourceSystem: i.Source.DB.System, Restore: i.Restore.ID, Format: "PGDMP-1.16.0", DumpVersion: dumpTool, RestoreVersion: restoreTool}
	for _, tool := range []struct{ name, want string }{{"pg_dump", dumpTool}, {"pg_restore", restoreTool}} {
		v, e := d.output(ctx, nil, "exec", "--user", "999:999", i.Source.ID, tool.name, "--version")
		if e != nil || strings.TrimSpace(string(v)) != tool.want {
			return b, errors.New("pinned PostgreSQL tool version mismatch")
		}
	}
	path := filepath.Join(i.BackupDirectory, ".partial-"+localstate.RandomID())
	f, e := localstate.OpenNew(path)
	if e != nil {
		return b, e
	}
	defer f.Close()
	defer os.Remove(path)
	var w io.Writer = f
	if opts.backupOutput != nil {
		w = opts.backupOutput(w)
	}
	if e = j.append("BACKUP_WRITE_INTENT", map[string]string{"backupId": i.BackupID}); e != nil {
		return b, e
	}
	e = d.command(ctx, nil, w, BackupBytes, "exec", "--user", "999:999", i.Source.ID, "pg_dump", "-w", "-h", "127.0.0.1", "-U", "themis", "-d", Database, "--format=custom", "--compress=none", "--no-owner", "--no-acl", "--lock-wait-timeout=2000")
	exit := toolExit(e)
	if e == nil {
		zero := 0
		exit = &zero
	}
	if je := j.append("DUMP_TOOL_EXIT", map[string]any{"exitCode": exit}); je != nil {
		return b, je
	}
	if e != nil {
		return b, e
	}
	if e = f.Sync(); e != nil {
		return b, e
	}
	if e = f.Close(); e != nil {
		return b, e
	}
	f, e = os.Open(path)
	if e != nil {
		return b, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return b, e
	}
	b.Bytes = st.Size()
	b.FileIdentity, e = backupFileIdentity(f)
	if e != nil {
		return b, e
	}
	h := sha256.New()
	if _, e = io.Copy(h, io.LimitReader(f, BackupBytes+1)); e != nil {
		return b, e
	}
	b.SHA256 = hex.EncodeToString(h.Sum(nil))
	if e = validateDurableFile(f, b); e != nil {
		return b, e
	}
	// --file=- reads and expands data blocks, unlike a TOC-only --list probe.
	e = d.command(ctx, f, &boundedDiscard{left: 32 << 20}, 32<<20, "exec", "--user", "999:999", "-i", i.Restore.ID, "pg_restore", "--no-owner", "--no-acl", "--file=-")
	if e != nil {
		return b, errors.New("custom archive full-read validation failed")
	}
	if e = validateDurableFile(f, b); e != nil {
		return b, e
	}
	if opts.after != nil {
		if e = opts.after("backup-validated", p); e != nil {
			return b, e
		}
	}
	if e = d.durableTarget(ctx, i, i.Source); e != nil {
		return b, errors.New("source changed before backup publication")
	}
	final := filepath.Join(i.BackupDirectory, i.BackupID+".dump")
	if e = os.Link(path, final); e != nil {
		return b, e
	}
	if e = localstate.SyncDirectory(i.BackupDirectory); e != nil {
		return b, e
	}
	b.PublishedAt = time.Now().UTC()
	b.Signature = ed25519.Sign(k, durableBackupMessage(b))
	e = localstate.WriteNew(filepath.Join(i.Directory, "durable-backup-receipt.json"), b)
	return b, e
}
