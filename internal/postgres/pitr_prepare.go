package postgres

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tamen25/themis/internal/localstate"
)

// Hooks wrap actual operations only, for interruption and ambiguity tests.
type pitrOptions struct {
	after           func(string, PITRPlan) error
	backupOutput    func(io.Writer) io.Writer
	walCopyInput    func(io.Reader) io.Reader
	restoreInput    func(io.Reader) io.Reader
	acknowledgement func(int, string, error) (string, error)
}

func lsnFromNumber(n uint64) string { return fmt.Sprintf("%X/%X", n>>32, n&0xffffffff) }
func pitrAfter(opts pitrOptions, stage string, p PITRPlan) error {
	if opts.after != nil {
		return opts.after(stage, p)
	}
	return nil
}
func pitrWaitArchive(ctx context.Context, d Docker, i PITRInventory, names []string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		all := true
		for _, name := range names {
			if !pitrWALPattern.MatchString(name) {
				return errors.New("invalid required WAL name")
			}
			b, err := pitrExec(ctx, d, i.Archive.ID, "stat", "-c", "%s:%u:%g:%a", "--", "/var/lib/postgresql/wal/"+name)
			if err != nil || strings.TrimSpace(string(b)) != "1048576:999:999:600" {
				all = false
				break
			}
		}
		if all {
			b, err := pitrExec(ctx, d, i.Archive.ID, "find", "/var/lib/postgresql/wal", "-maxdepth", "1", "-name", ".partial-*", "-print")
			if err != nil || len(b) != 0 {
				return errors.New("partial WAL publication remains")
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("required WAL archival lag exceeds ten seconds")
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func pitrSourceConfiguration(ctx context.Context, d Docker, i PITRInventory) error {
	v, err := d.sql(ctx, i.Source.ID, "SELECT current_setting('archive_mode')||'|'||current_setting('archive_command')||'|'||current_setting('wal_level')||'|'||current_setting('fsync')||'|'||current_setting('synchronous_commit')||'|'||current_setting('full_page_writes')||'|'||current_setting('wal_segment_size')||'|'||(SELECT count(*) FROM pg_tablespace)||'|'||(SELECT timeline_id FROM pg_control_checkpoint());")
	if err != nil {
		return err
	}
	if v != "on|"+pitrArchiveCommand+"|replica|on|on|on|1MB|2|1" {
		return errors.New("source WAL configuration, tablespaces or timeline mismatch")
	}
	b, err := pitrExec(ctx, d, i.Source.ID, "cat", "/var/lib/postgresql/themis-tools/archive-wal")
	if err != nil || string(b) != pitrArchiveScript {
		return errors.New("fixed archive script changed")
	}
	return nil
}
func PreparePITR(ctx context.Context, dir string) (PITRPrepared, error) {
	return preparePITR(ctx, dir, pitrOptions{})
}
func preparePITR(ctx context.Context, dir string, opts pitrOptions) (s PITRPrepared, err error) {
	p, err := loadPITRPlan(dir)
	if err != nil {
		return s, err
	}
	i := p.Inventory
	l, err := acquire(i.Directory)
	if err != nil {
		return s, err
	}
	defer l.Close()
	var g PITRGrant
	if err = localstate.Read(filepath.Join(i.Directory, "pitr-prepare-authorization.json"), &g); err != nil {
		return s, err
	}
	if err = validatePITRGrant(p, g, "prepare", "", time.Now(), true); err != nil {
		return s, err
	}
	k, err := pitrLoadKeys(i)
	if err != nil {
		return s, err
	}
	if err = localstate.WriteNew(filepath.Join(i.Directory, "pitr-prepare-invocation.json"), map[string]string{"plan": p.Digest}); err != nil {
		return s, errors.New("PITR preparation already consumed; no retry")
	}
	f, err := localstate.OpenNew(filepath.Join(i.Directory, "pitr-prepare.jsonl"))
	if err != nil {
		return s, err
	}
	defer f.Close()
	j := journal{w: f, start: time.Now(), plan: p.Digest, version: PITRVersion}
	deadline := j.start.Add(120 * time.Second)
	if g.ExecuteBefore.Before(deadline) {
		deadline = g.ExecuteBefore
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	d := Docker{i.Endpoint, i.Engine}
	if err = d.pitrSource(ctx, i); err != nil {
		return s, err
	}
	for _, r := range []Resource{i.Restore, i.Archive} {
		if _, err = d.pitrContainer(ctx, i, r, true, true); err != nil {
			return s, err
		}
	}
	if err = pitrSourceConfiguration(ctx, d, i); err != nil {
		return s, err
	}
	if _, err = d.durableBudget(ctx, i.Source); err != nil {
		return s, err
	}
	v, err := d.sql(ctx, i.Source.ID, emptySQL)
	if err != nil || v != "0" {
		return s, errors.New("PITR source must be fresh")
	}
	if _, err = pitrExec(ctx, d, i.Restore.ID, "test", "!", "-e", "/var/lib/postgresql/18/docker"); err != nil {
		return s, errors.New("physical destination already initialized")
	}
	// Verify an actual closed archive segment before admitting workload commits.
	lsn, err := d.sql(ctx, i.Source.ID, "SELECT pg_current_wal_insert_lsn();")
	if err != nil {
		return s, err
	}
	a, err := pitrLSN(lsn)
	if err != nil {
		return s, err
	}
	if _, err = d.sql(ctx, i.Source.ID, "SELECT pg_switch_wal();"); err != nil {
		return s, err
	}
	names, err := pitrWALNames(lsn, lsnFromNumber(a+1))
	if err != nil {
		return s, err
	}
	if err = pitrWaitArchive(ctx, d, i, names); err != nil {
		return s, err
	}
	if _, err = pitrExec(ctx, d, i.Archive.ID, "pg_waldump", "--quiet", "--limit=1", "--path=/var/lib/postgresql/wal", names[0]); err != nil {
		return s, errors.New("initial archived WAL cannot be parsed")
	}
	if err = j.append("ARCHIVE_HEALTH_OBSERVED", names); err != nil {
		return s, err
	}
	if _, err = d.sql(ctx, i.Source.ID, seedSQL); err != nil {
		return s, err
	}
	session, previous := localstate.RandomID(), ""
	commit := func(id int) error {
		r, e := pitrCommit(ctx, d, p, k.Ledger, &j, session, previous, id, opts)
		if e == nil {
			previous = digest("pitr-receipt", r)
		}
		return e
	}
	for id := 1; id <= BaselineCommits; id++ {
		if err = commit(id); err != nil {
			return s, err
		}
	}
	s.Schema, err = d.sql(ctx, i.Source.ID, schemaSQL)
	if err != nil {
		return s, err
	}
	if err = j.append("PHYSICAL_BACKUP_INTENT", map[string]string{"method": "pg_basebackup tar fetch SHA256"}); err != nil {
		return s, err
	}
	basePath := pitrCapsule(i, "base.tar")
	base, err := localstate.OpenNew(basePath + ".partial")
	if err != nil {
		return s, err
	}
	var output io.Writer = base
	if opts.backupOutput != nil {
		output = opts.backupOutput(base)
	}
	err = d.command(ctx, nil, output, PITRBackupBytes, "exec", "--user", "999:999", i.Source.ID, "pg_basebackup", "-w", "-h", "127.0.0.1", "-U", "themis", "-D", "-", "-Ft", "-Xfetch", "--checkpoint=fast", "--manifest-checksums=SHA256")
	if err == nil {
		err = base.Sync()
	}
	ce := base.Close()
	if err == nil {
		err = ce
	}
	if err != nil {
		return s, err
	}
	base, err = os.Open(basePath + ".partial")
	if err != nil {
		return s, err
	}
	raw, manifest, err := pitrReadTar(base, i.Source.DB.System)
	if err != nil {
		base.Close()
		return s, err
	}
	if _, err = pitrExec(ctx, d, i.Archive.ID, "mkdir", "-m", "700", "/var/lib/postgresql/base"); err != nil {
		base.Close()
		return s, err
	}
	err = pitrExtract(ctx, d, i.Archive.ID, "/var/lib/postgresql/base", base)
	base.Close()
	if err != nil {
		return s, err
	}
	b, err := pitrExec(ctx, d, i.Archive.ID, "pg_verifybackup", "--exit-on-error", "/var/lib/postgresql/base")
	if err != nil {
		return s, errors.New("full physical backup and required WAL verification failed")
	}
	s.VerifyBackupOutput = string(b)
	if err = pitrAfter(opts, "BASE_VERIFIED", p); err != nil {
		return s, err
	}
	if err = os.Link(basePath+".partial", basePath); err != nil {
		return s, err
	}
	if err = localstate.SyncDirectory(filepath.Dir(basePath)); err != nil {
		return s, err
	}
	if err = os.Remove(basePath + ".partial"); err != nil {
		return s, err
	}
	s.Base, err = pitrFile(basePath, "base.tar", PITRBackupBytes)
	if err != nil {
		return s, err
	}
	if err = pitrPublish(pitrCapsule(i, "backup_manifest"), strings.NewReader(string(raw)), 1<<20); err != nil {
		return s, err
	}
	h := sha256.Sum256(raw)
	s.ManifestSHA256 = hex.EncodeToString(h[:])
	s.System = i.Source.DB.System
	s.StartLSN = manifest.WAL[0].Start
	s.EndLSN = manifest.WAL[0].End
	if err = j.append("BASE_BACKUP_COMPLETE", s.Base); err != nil {
		return s, err
	}
	// Force the target into a later segment that was not included in the base.
	if _, err = d.sql(ctx, i.Source.ID, "SELECT pg_switch_wal();"); err != nil {
		return s, err
	}
	for id := BaselineCommits + 1; id <= PITRBoundary; id++ {
		if err = commit(id); err != nil {
			return s, err
		}
	}
	s.TargetLSN, err = d.sql(ctx, i.Source.ID, "SELECT pg_create_restore_point('"+p.TargetName+"');")
	if err != nil {
		return s, err
	}
	s.Receipts = PITRBoundary
	if p.Contract.Scenario == "ack-loss" {
		for id := PITRBoundary + 1; id <= PITRBoundary+3; id++ {
			if err = commit(id); err != nil {
				return s, err
			}
		}
		s.Receipts += 3
	}
	s.SentinelLSN, err = d.sql(ctx, i.Source.ID, "SELECT pg_create_restore_point('"+p.TargetName+"_end');")
	if err != nil {
		return s, err
	}
	if _, err = d.sql(ctx, i.Source.ID, "SELECT pg_switch_wal();"); err != nil {
		return s, err
	}
	names, err = pitrWALNames(s.StartLSN, s.SentinelLSN)
	if err != nil {
		return s, err
	}
	if err = pitrAfter(opts, "WAL_COPY_INTENT", p); err != nil {
		return s, err
	}
	if err = pitrWaitArchive(ctx, d, i, names); err != nil {
		return s, err
	}
	for _, name := range names {
		w, e := pitrCaptureWAL(ctx, d, i, name, opts)
		if e != nil {
			return s, e
		}
		s.WAL = append(s.WAL, w)
	}
	b, err = pitrExec(ctx, d, i.Archive.ID, "pg_waldump", "--rmgr=XLOG", "--path=/var/lib/postgresql/wal", "--start="+s.EndLSN, "--end="+s.SentinelLSN)
	if err != nil {
		return s, errors.New("PITR suffix WAL parse failed")
	}
	s.WALDump = string(b)
	if !strings.Contains(s.WALDump, p.TargetName) {
		return s, errors.New("named target not observed in archived WAL")
	}
	if _, err = d.durableBudget(ctx, i.Source); err != nil {
		return s, err
	}
	if err = d.pitrSource(ctx, i); err != nil {
		return s, err
	}
	if err = validatePITRGrant(p, g, "prepare", "", time.Now(), false); err != nil {
		return s, err
	}
	if err = j.append("REQUIRED_WAL_RETAINED", s.WAL); err != nil {
		return s, err
	}
	s.Version = PITRVersion
	s.Plan = p.Digest
	s.Inventory = pitrInventoryHash(i)
	s.TargetName = p.TargetName
	s.Timeline = 1
	s.Boundary = PITRBoundary
	s.ReceiptHead = previous
	s.PrepareJournalHead = j.previous
	s.Digest = pitrPreparedHash(s)
	s.Signature = ed25519.Sign(k.Ledger, []byte(s.Digest))
	if err = verifyPITRCapsule(p, s); err != nil {
		return s, err
	}
	if err = pitrCheckArchive(ctx, d, p, s); err != nil {
		return s, err
	}
	if err = pitrAfter(opts, "PREPARED_PUBLICATION", p); err != nil {
		return s, err
	}
	if err = localstate.WriteNew(filepath.Join(i.Directory, "pitr-prepared.json"), s); err != nil {
		return s, err
	}
	_, err = loadPITRPrepared(p)
	return s, err
}
