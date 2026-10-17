package evidence

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"unicode/utf8"
)

var credentialPattern = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|(?:gh[opusr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|(?i:(?:https?|postgres(?:ql)?|redis|mongodb)://[^\s/"<>:]+:[^\s/@"<>]+@)`)

// CheckPublicArtifact rejects known operational-secret structures. This is a
// minimization guard, not a general secret detector or an automatic redactor.
// Operators must curate synthetic public exports, never arbitrary run trees.
func CheckPublicArtifact(path string, b []byte) error {
	if !pathPattern.MatchString(path) || len(b) > MaxFile || !utf8.Valid(b) || credentialPattern.Match(b) {
		return errors.New("unsafe public artifact; contents suppressed")
	}
	check := func(raw []byte) error {
		var v any
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if d.Decode(&v) != nil {
			return errors.New("public artifact is not JSON")
		}
		if d.Decode(new(any)) != io.EOF {
			return errors.New("trailing public artifact JSON")
		}
		var visit func(any, int) error
		visit = func(v any, depth int) error {
			if depth > 48 {
				return errors.New("public artifact nesting exceeds limit")
			}
			switch x := v.(type) {
			case map[string]any:
				for k, v := range x {
					switch strings.ToLower(k) {
					case "inventory":
						commitment, ok := v.(string)
						if !ok || !hexDigest.MatchString(commitment) {
							return errors.New("private ownership inventory in public artifact; contents suppressed")
						}
					case "privatekey", "invocationprivatekey", "cleanupprivatekey", "controltoken", "datatoken", "password", "replicationpassword", "client-key-data", "token", "client-certificate-data", "directory":
						return errors.New("private operational field in public artifact; contents suppressed")
					}
					if err := visit(v, depth+1); err != nil {
						return err
					}
				}
			case []any:
				for _, v := range x {
					if err := visit(v, depth+1); err != nil {
						return err
					}
				}
			}
			return nil
		}
		return visit(v, 0)
	}
	if strings.HasSuffix(path, ".jsonl") {
		if len(b) == 0 || b[len(b)-1] != '\n' {
			return errors.New("torn public journal")
		}
		for _, line := range bytes.Split(b[:len(b)-1], []byte{'\n'}) {
			if len(line) > 65536 {
				return errors.New("journal line budget")
			}
			if err := check(line); err != nil {
				return err
			}
		}
		return nil
	}
	return check(b)
}

type snapshotFile struct {
	data []byte
	info os.FileInfo
}

func readSource(root *os.Root, path string) (snapshotFile, error) {
	var out snapshotFile
	// Archive path grammar already limits this to artifacts/<flat filename>.
	for _, name := range []string{"artifacts", path} {
		i, e := root.Lstat(name)
		if e != nil || i.Mode()&os.ModeSymlink != 0 {
			return out, errors.New("source contains a missing file or symlink")
		}
	}
	f, err := root.Open(path)
	if err != nil {
		return out, errors.New("source open failed")
	}
	defer f.Close()
	a, err := f.Stat()
	if err != nil || !a.Mode().IsRegular() || a.Size() < 1 || a.Size() > MaxFile {
		return out, errors.New("unsafe source type or size")
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxFile+1))
	if err != nil || int64(len(b)) != a.Size() {
		return out, errors.New("source read changed or exceeded budget")
	}
	z, err := f.Stat()
	if err != nil || !os.SameFile(a, z) || a.Size() != z.Size() || a.ModTime() != z.ModTime() {
		return out, errors.New("source changed while read")
	}
	p, err := root.Lstat(path)
	if err != nil || !p.Mode().IsRegular() || !os.SameFile(a, p) {
		return out, errors.New("source file was substituted")
	}
	return snapshotFile{b, z}, nil
}

// Snapshot freezes only explicitly named public artifacts. No discovery or
// infrastructure connection occurs. Two sweeps reject observed publication races.
func Snapshot(dir string, artifacts []Artifact) (map[string][]byte, error) {
	return snapshot(dir, artifacts, nil)
}

func snapshot(dir string, artifacts []Artifact, between func()) (map[string][]byte, error) {
	if len(artifacts) < 1 || len(artifacts) > MaxArtifacts {
		return nil, errors.New("snapshot artifact budget")
	}
	i, err := os.Lstat(dir)
	if err != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("source root must be a real directory")
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	first := map[string]snapshotFile{}
	var total int64
	for _, a := range artifacts {
		if !pathPattern.MatchString(a.Path) {
			return nil, errors.New("invalid source path")
		}
		if _, ok := first[a.Path]; ok {
			return nil, errors.New("duplicate source")
		}
		f, e := readSource(r, a.Path)
		if e != nil {
			return nil, e
		}
		total += int64(len(f.data))
		if total > MaxTotal {
			return nil, errors.New("source total size exceeded")
		}
		first[a.Path] = f
	}
	if between != nil {
		between()
	}
	files := map[string][]byte{}
	for _, a := range artifacts {
		f, e := readSource(r, a.Path)
		old := first[a.Path]
		if e != nil || !os.SameFile(f.info, old.info) || f.info.ModTime() != old.info.ModTime() || !bytes.Equal(f.data, old.data) {
			return nil, errors.New("source changed during publication")
		}
		if e = CheckPublicArtifact(a.Path, f.data); e != nil {
			return nil, e
		}
		files[a.Path] = f.data
	}
	return files, nil
}

// Publish signs a frozen snapshot and exclusively publishes one complete file.
// The output must be outside the historical source directory. The output parent
// is operator controlled and must already exist. No existing file is replaced.
func Publish(source, output string, m Manifest, signer crypto.Signer) error {
	base, e := filepath.Abs(source)
	if e != nil {
		return e
	}
	dst, e := filepath.Abs(output)
	if e != nil {
		return e
	}
	rel, e := filepath.Rel(base, dst)
	if e != nil || rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return errors.New("publication must be outside source directory")
	}
	files, e := Snapshot(source, m.Artifacts)
	if e != nil {
		return e
	}
	b, e := Sign(m, files, signer)
	if e != nil {
		return e
	}
	return PublishBytes(dst, b)
}

// PublishBytes is an exclusive local-file publication primitive. Callers must
// pass completed data; partial archives are never written to the final path.
func PublishBytes(output string, data []byte) error {
	return publishBytes(output, data, nil)
}

// checkpoint is confined to tests of actual local publication crash boundaries.
func publishBytes(output string, data []byte, checkpoint func(string) error) error {
	if len(data) == 0 || len(data) > MaxArchive {
		return errors.New("publication byte limit")
	}
	f, e := os.CreateTemp(filepath.Dir(output), ".themis-evidence-pending-")
	if e != nil {
		return errors.New("cannot create publication temporary file")
	}
	name := f.Name()
	defer os.Remove(name)
	defer f.Close()
	if n, e := f.Write(data); e != nil || n != len(data) {
		return errors.New("publication write incomplete")
	}
	if checkpoint != nil {
		if e = checkpoint("written"); e != nil {
			return e
		}
	}
	if e = f.Sync(); e != nil {
		return errors.New("publication sync failed")
	}
	if e = f.Close(); e != nil {
		return e
	}
	if checkpoint != nil {
		if e = checkpoint("synced"); e != nil {
			return e
		}
	}
	if e = os.Link(name, output); e != nil {
		return errors.New("exclusive publication failed; output may already exist")
	}
	if runtime.GOOS != "windows" {
		d, e := os.Open(filepath.Dir(output))
		if e != nil {
			return e
		}
		defer d.Close()
		if e = d.Sync(); e != nil {
			return errors.New("published complete file; directory durability uncertain")
		}
	}
	return nil
}
