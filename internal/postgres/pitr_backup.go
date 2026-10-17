package postgres

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/tamen25/themis/internal/localstate"
)

type PITRFile struct {
	Name, SHA256, Identity, ArchiveIdentity string
	Bytes                                   int64
}
type PITRManifest struct {
	Version int         `json:"PostgreSQL-Backup-Manifest-Version"`
	System  json.Number `json:"System-Identifier"`
	Files   []struct {
		Path      string
		Size      int64
		Algorithm string `json:"Checksum-Algorithm"`
		Checksum  string
	} `json:"Files"`
	WAL []struct {
		Timeline int
		Start    string `json:"Start-LSN"`
		End      string `json:"End-LSN"`
	} `json:"WAL-Ranges"`
	Checksum string `json:"Manifest-Checksum"`
}
type PITRPrepared struct {
	Version, Plan, Inventory, Digest         string
	Base                                     PITRFile
	ManifestSHA256, System, StartLSN, EndLSN string
	TargetName, TargetLSN, SentinelLSN       string
	Timeline, Boundary, Receipts             int
	ReceiptHead, Schema, PrepareJournalHead  string
	WAL                                      []PITRFile
	VerifyBackupOutput, WALDump              string
	Signature                                []byte
}

func pitrPreparedHash(s PITRPrepared) string {
	s.Signature = nil
	s.Digest = ""
	return digest("themis.postgres.pitr.execution-plan.v1", s)
}
func pitrCapsule(i PITRInventory, name string) string {
	return filepath.Join(i.Directory, "capsule", filepath.FromSlash(name))
}
func pitrFile(pathname, name string, limit int64) (m PITRFile, err error) {
	if err = localstate.Check(pathname); err != nil {
		return m, err
	}
	f, err := os.Open(pathname)
	if err != nil {
		return m, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return m, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return m, errors.New("PITR file type or size invalid")
	}
	identity, err := backupFileIdentity(f)
	if err != nil {
		return m, err
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil {
		return m, err
	}
	after, err := f.Stat()
	if err != nil {
		return m, err
	}
	if n != info.Size() || n != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		return m, errors.New("PITR artifact changed while reading")
	}
	return PITRFile{Name: name, SHA256: hex.EncodeToString(h.Sum(nil)), Identity: identity, Bytes: n}, nil
}

// Validate the exact handle consumed by restoration, rather than only checking
// a pathname earlier. Recheck the pathname and handle after consumption too.
func pitrValidateHandle(f *os.File, want PITRFile, limit int64) error {
	if err := localstate.Check(f.Name()); err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		return err
	}
	named, err := os.Lstat(f.Name())
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || !os.SameFile(st, named) || st.Size() != want.Bytes || st.Size() <= 0 || st.Size() > limit {
		return errors.New("opened PITR artifact identity or size changed")
	}
	id, err := backupFileIdentity(f)
	if err != nil {
		return err
	}
	if id != want.Identity {
		return errors.New("opened PITR artifact replaced")
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil {
		return err
	}
	if n != want.Bytes || hex.EncodeToString(h.Sum(nil)) != want.SHA256 {
		return errors.New("opened PITR artifact content changed")
	}
	after, err := f.Stat()
	if err != nil {
		return err
	}
	if after.Size() != st.Size() || !after.ModTime().Equal(st.ModTime()) {
		return errors.New("opened PITR artifact changed during hashing")
	}
	_, err = f.Seek(0, io.SeekStart)
	return err
}
func pitrReadWAL(i PITRInventory, w PITRFile) ([]byte, error) {
	if !pitrWALPattern.MatchString(strings.TrimPrefix(w.Name, "wal/")) || w.Bytes != PITRSegmentBytes {
		return nil, errors.New("invalid approved WAL artifact")
	}
	f, err := os.Open(pitrCapsule(i, w.Name))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err = pitrValidateHandle(f, w, PITRSegmentBytes); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, PITRSegmentBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != w.Bytes {
		return nil, errors.New("partial approved WAL read")
	}
	if err = pitrValidateHandle(f, w, PITRSegmentBytes); err != nil {
		return nil, err
	}
	return b, nil
}
func pitrPublish(pathname string, input io.Reader, limit int64) (err error) {
	f, err := localstate.OpenNew(pathname + ".partial")
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(input, limit+1))
	if err == nil && (n <= 0 || n > limit) {
		err = errors.New("PITR artifact exceeds budget")
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Link(pathname+".partial", pathname); err != nil {
		return err
	}
	if err = localstate.SyncDirectory(filepath.Dir(pathname)); err != nil {
		return err
	}
	return os.Remove(pathname + ".partial")
}
func pitrReadTar(f io.ReadSeeker, system string) (raw []byte, m PITRManifest, err error) {
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return nil, m, err
	}
	tr := tar.NewReader(f)
	seen := map[string]bool{}
	var total int64
	for count := 0; ; count++ {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, m, e
		}
		// PostgreSQL emits ./pg_wal directory headers; normalize this one safe
		// prefix before duplicate/path checks, without cleaning traversal away.
		name := strings.TrimSuffix(strings.TrimPrefix(h.Name, "./"), "/")
		if count >= 4096 || name == "" || len(name) > 192 || path.Clean(name) != name || strings.ContainsAny(name, "\\:\x00\r\n") || strings.HasPrefix(name, "/") || name == ".." || strings.HasPrefix(name, "../") || seen[name] || (h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir) || h.Size < 0 || h.Size > FileBytes || h.Mode&0077 != 0 || (h.Mode&07000) != 0 {
			return nil, m, fmt.Errorf("unsafe physical backup tar entry name=%q type=%d mode=%o size=%d duplicate=%t", name, h.Typeflag, h.Mode, h.Size, seen[name])
		}
		for _, r := range name {
			if r < 32 || r > 126 {
				return nil, m, errors.New("non-ASCII backup path")
			}
		}
		seen[name] = true
		total += h.Size
		if total > PITRBackupBytes {
			return nil, m, errors.New("physical backup expansion exceeds budget")
		}
		if name == "standby.signal" || name == "recovery.signal" || name == "postmaster.pid" || strings.HasPrefix(name, "pg_tblspc/") {
			return nil, m, errors.New("unsupported physical backup recovery state or tablespace")
		}
		if name == "backup_manifest" {
			if h.Size > 1<<20 {
				return nil, m, errors.New("backup manifest exceeds budget")
			}
			raw, err = io.ReadAll(tr)
			if err != nil {
				return nil, m, err
			}
		}
	}
	if len(raw) == 0 || json.Unmarshal(raw, &m) != nil || m.Version != 2 || m.System.String() != system || len(m.WAL) != 1 || m.WAL[0].Timeline != 1 || len(m.Files) == 0 || !hexID.MatchString(strings.ToLower(m.Checksum)) {
		return nil, m, errors.New("physical backup manifest missing or source system/timeline mismatch")
	}
	a, e := pitrLSN(m.WAL[0].Start)
	if e != nil {
		return nil, m, e
	}
	b, e := pitrLSN(m.WAL[0].End)
	if e != nil || a >= b {
		return nil, m, errors.New("invalid physical backup WAL range")
	}
	for _, file := range m.Files {
		if file.Path == "" || file.Size < 0 || file.Size > FileBytes || file.Algorithm != "SHA256" || !hexID.MatchString(strings.ToLower(file.Checksum)) {
			return nil, m, errors.New("physical backup file checksum or size invalid")
		}
	}
	_, err = f.Seek(0, io.SeekStart)
	return raw, m, err
}

var pitrLSNPattern = regexp.MustCompile(`^[0-9A-F]{1,8}/[0-9A-F]{1,8}$`)
var pitrWALPattern = regexp.MustCompile(`^00000001[0-9A-F]{16}$`)

func pitrLSN(s string) (uint64, error) {
	if !pitrLSNPattern.MatchString(s) {
		return 0, errors.New("invalid WAL LSN")
	}
	parts := strings.Split(s, "/")
	a, _ := strconv.ParseUint(parts[0], 16, 32)
	b, _ := strconv.ParseUint(parts[1], 16, 32)
	return a<<32 | b, nil
}
func pitrWALNames(start, end string) ([]string, error) {
	a, err := pitrLSN(start)
	if err != nil {
		return nil, err
	}
	b, err := pitrLSN(end)
	if err != nil || a >= b {
		return nil, errors.New("invalid retained WAL range")
	}
	first, last := a/uint64(PITRSegmentBytes), (b-1)/uint64(PITRSegmentBytes)
	if last-first >= 31 {
		return nil, errors.New("required WAL exceeds budget")
	}
	var names []string
	for n := first; n <= last; n++ {
		names = append(names, fmt.Sprintf("00000001%08X%08X", n/4096, n%4096))
	}
	return names, nil
}
func loadPITRPrepared(p PITRPlan) (s PITRPrepared, err error) {
	if err = localstate.Read(filepath.Join(p.Inventory.Directory, "pitr-prepared.json"), &s); err != nil {
		return s, err
	}
	if s.Version != PITRVersion || s.Plan != p.Digest || s.Inventory != pitrInventoryHash(p.Inventory) || s.System != p.Inventory.Source.DB.System || s.TargetName != p.TargetName || s.Timeline != 1 || s.Boundary != PITRBoundary || s.Base.Name != "base.tar" || s.Base.Bytes <= 0 || s.Base.Bytes > PITRBackupBytes || !hexID.MatchString(s.Base.SHA256) || s.Base.Identity == "" || !hexID.MatchString(s.ManifestSHA256) || !hexID.MatchString(s.ReceiptHead) || !hexID.MatchString(s.PrepareJournalHead) || s.Schema == "" || s.Digest != pitrPreparedHash(s) || !ed25519.Verify(p.Inventory.LedgerKey, []byte(s.Digest), s.Signature) {
		return s, errors.New("PITR prepared execution plan invalid")
	}
	end, e := pitrLSN(s.EndLSN)
	if e != nil {
		return s, e
	}
	target, e := pitrLSN(s.TargetLSN)
	if e != nil || target <= end {
		return s, errors.New("recovery target must follow backup completion")
	}
	sentinel, e := pitrLSN(s.SentinelLSN)
	if e != nil || sentinel <= target {
		return s, errors.New("PITR archive sentinel missing")
	}
	names, e := pitrWALNames(s.StartLSN, s.SentinelLSN)
	if e != nil {
		return s, e
	}
	if len(names) != len(s.WAL) {
		return s, errors.New("PITR WAL coverage incomplete")
	}
	for n, w := range s.WAL {
		if w.Name != "wal/"+names[n] || w.Bytes != PITRSegmentBytes || !hexID.MatchString(w.SHA256) || w.Identity == "" || w.ArchiveIdentity == "" {
			return s, errors.New("PITR WAL identity/order invalid")
		}
	}
	count := PITRBoundary
	if p.Contract.Scenario == "ack-loss" {
		count += 3
	}
	if s.Receipts != count {
		return s, errors.New("PITR receipt coverage invalid")
	}
	return s, nil
}
func verifyPITRCapsule(p PITRPlan, s PITRPrepared) error {
	data, err := readBounded(filepath.Join(p.Inventory.Directory, "pitr-prepare.jsonl"))
	if err != nil {
		return err
	}
	if err = verifyJournal(data, p.Digest, PITRVersion); err != nil {
		return err
	}
	lines := bytes.Split(bytes.TrimSuffix(data, []byte{'\n'}), []byte{'\n'})
	var last Event
	if len(lines) == 0 || localstate.Unmarshal(lines[len(lines)-1], &last) != nil || last.Hash != s.PrepareJournalHead || last.Kind != "REQUIRED_WAL_RETAINED" {
		return errors.New("PITR preparation history incomplete or changed")
	}
	for _, want := range append([]PITRFile{s.Base}, s.WAL...) {
		limit := PITRSegmentBytes
		if want.Name == "base.tar" {
			limit = PITRBackupBytes
		} else if !pitrWALPattern.MatchString(strings.TrimPrefix(want.Name, "wal/")) {
			return errors.New("unsafe retained WAL path")
		}
		got, err := pitrFile(pitrCapsule(p.Inventory, want.Name), want.Name, limit)
		if err != nil {
			return err
		}
		want.ArchiveIdentity = ""
		if got != want {
			return errors.New("PITR retained artifact replaced, truncated or corrupt")
		}
	}
	f, err := os.Open(pitrCapsule(p.Inventory, "base.tar"))
	if err != nil {
		return err
	}
	defer f.Close()
	raw, m, err := pitrReadTar(f, s.System)
	if err != nil {
		return err
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != s.ManifestSHA256 || m.WAL[0].Start != s.StartLSN || m.WAL[0].End != s.EndLSN {
		return errors.New("PITR retained manifest changed")
	}
	manifest, err := readBounded(pitrCapsule(p.Inventory, "backup_manifest"))
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, manifest) {
		return errors.New("retained backup manifest missing or modified")
	}
	rs, err := loadPITRReceipts(p, s.Receipts)
	if err != nil {
		return err
	}
	if digest("pitr-receipt", rs[len(rs)-1]) != s.ReceiptHead {
		return errors.New("PITR original receipt ledger changed")
	}
	return nil
}
func loadPITRReceipts(p PITRPlan, count int) ([]PITRReceipt, error) {
	var rs []PITRReceipt
	for id := 1; id <= count; id++ {
		var r PITRReceipt
		if err := localstate.Read(filepath.Join(p.Inventory.Directory, fmt.Sprintf("pitr-receipt-%02d.json", id)), &r); err != nil {
			return nil, err
		}
		rs = append(rs, r)
	}
	return rs, verifyPITRReceipts(rs, p, count)
}
func pitrExtract(ctx context.Context, d Docker, id, root string, f io.ReadSeeker) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	_, err := d.output(ctx, f, "exec", "-i", "--user", "999:999", id, "tar", "-xmf", "-", "--no-same-owner", "--keep-old-files", "-C", root)
	return err
}
func pitrCaptureWAL(ctx context.Context, d Docker, i PITRInventory, name string, opts pitrOptions) (PITRFile, error) {
	if !pitrWALPattern.MatchString(name) {
		return PITRFile{}, errors.New("invalid fixed WAL segment name")
	}
	// stdout is bounded to one full segment; partial output never publishes.
	var b bytes.Buffer
	before, err := pitrExec(ctx, d, i.Archive.ID, "stat", "-c", "%u:%g:%a:%s:%d:%i", "--", "/var/lib/postgresql/wal/"+name)
	if err != nil {
		return PITRFile{}, err
	}
	if !strings.HasPrefix(string(before), "999:999:600:1048576:") {
		return PITRFile{}, errors.New("archived WAL ownership or size invalid")
	}
	if err := d.command(ctx, nil, &b, PITRSegmentBytes, "exec", "--user", "999:999", i.Archive.ID, "cat", "--", "/var/lib/postgresql/wal/"+name); err != nil {
		return PITRFile{}, err
	}
	if int64(b.Len()) != PITRSegmentBytes {
		return PITRFile{}, errors.New("partial archived WAL segment")
	}
	pathname := pitrCapsule(i, "wal/"+name)
	var input io.Reader = &b
	if opts.walCopyInput != nil {
		input = opts.walCopyInput(input)
	}
	if err := pitrPublish(pathname, input, PITRSegmentBytes); err != nil {
		return PITRFile{}, err
	}
	m, err := pitrFile(pathname, "wal/"+name, PITRSegmentBytes)
	if err != nil {
		return m, err
	}
	after, err := pitrExec(ctx, d, i.Archive.ID, "stat", "-c", "%u:%g:%a:%s:%d:%i", "--", "/var/lib/postgresql/wal/"+name)
	if err != nil || !bytes.Equal(before, after) {
		return m, errors.New("archived WAL replaced during capture")
	}
	m.ArchiveIdentity = strings.TrimSpace(string(before))
	return m, nil
}

func pitrCheckArchive(ctx context.Context, d Docker, p PITRPlan, s PITRPrepared) error {
	i := p.Inventory
	if _, err := d.pitrContainer(ctx, i, i.Archive, true, true); err != nil {
		return err
	}
	b, err := pitrExec(ctx, d, i.Archive.ID, "du", "-sb", "/var/lib/postgresql")
	if err != nil {
		return err
	}
	fields := strings.Fields(string(b))
	if len(fields) != 2 {
		return errors.New("archive volume usage unknown")
	}
	n, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || n <= 0 || n > VolumeBytes {
		return errors.New("archive volume exceeds measured budget")
	}
	for _, w := range s.WAL {
		name := strings.TrimPrefix(w.Name, "wal/")
		if !pitrWALPattern.MatchString(name) {
			return errors.New("invalid approved WAL name")
		}
		b, err = pitrExec(ctx, d, i.Archive.ID, "stat", "-c", "%u:%g:%a:%s:%d:%i", "--", "/var/lib/postgresql/wal/"+name)
		if err != nil || strings.TrimSpace(string(b)) != w.ArchiveIdentity {
			return errors.New("approved archive WAL missing, partial or replaced")
		}
		b, err = pitrExec(ctx, d, i.Archive.ID, "sha256sum", "--", "/var/lib/postgresql/wal/"+name)
		fields = strings.Fields(string(b))
		if err != nil || len(fields) != 2 || fields[0] != w.SHA256 {
			return errors.New("approved archive WAL corrupt")
		}
	}
	return nil
}
