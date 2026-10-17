// Package evidencecli exposes explicit local export, publication and offline
// verification. No command runs an experiment or authorizes infrastructure work.
package evidencecli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tamen25/themis/internal/evidencesource"
	"github.com/tamen25/themis/internal/kubeexperiment"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/postgres"
	"github.com/tamen25/themis/pkg/evidence"
	"github.com/tamen25/themis/pkg/evidenceverify"
)

type keyRecord struct {
	Version    string `json:"version"`
	Publisher  string `json:"publisher"`
	PrivateKey []byte `json:"privateKey"`
}
type failure struct {
	Version  string `json:"version"`
	Category string `json:"category"`
	Message  string `json:"message"`
}

func Run(args []string, output io.Writer) int { return run(args, output, time.Now().UTC()) }
func run(args []string, output io.Writer, now time.Time) int {
	emit := func(v any) bool { return json.NewEncoder(output).Encode(v) == nil }
	fail := func(category, message string, code int) int {
		emit(failure{evidence.ResultVersion, category, message})
		return code
	}
	if len(args) == 0 {
		return fail("USAGE", "use keygen, export, bundle, verify or inspect", 2)
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var engine, source, state, out, keyDir, publisher, bundle, trust, proposal, recordPath, journalPath string
	switch args[0] {
	case "keygen":
		f.StringVar(&keyDir, "key-dir", "", "new protected signer directory")
		f.StringVar(&publisher, "publisher", "", "operator provisioned publisher name")
	case "export":
		f.StringVar(&engine, "engine", "", "postgres-replication or kubernetes-synthetic")
		f.StringVar(&state, "state", "", "original run directory")
		f.StringVar(&out, "out", "", "new curated public export directory")
		f.StringVar(&proposal, "proposal", "", "explicit public coordination proposal")
		f.StringVar(&recordPath, "record", "", "public T2.3 coordination record instead of private run directory")
		f.StringVar(&journalPath, "journal", "", "explicit matching historical journal for record export")
	case "bundle":
		f.StringVar(&engine, "engine", "", "source mapping")
		f.StringVar(&source, "source", "", "curated public export directory")
		f.StringVar(&out, "out", "", "new signed bundle path")
		f.StringVar(&keyDir, "key-dir", "", "protected signer directory")
		f.StringVar(&publisher, "publisher", "", "exact provisioned publisher name")
	case "verify", "inspect":
		f.StringVar(&bundle, "bundle", "", "signed bundle path")
		if args[0] == "verify" {
			f.StringVar(&trust, "trust-policy", "", "independently provisioned trust policy")
		}
	default:
		return fail("USAGE", "unsupported evidence command", 2)
	}
	if f.Parse(args[1:]) != nil || f.NArg() != 0 {
		return fail("USAGE", "invalid command arguments", 2)
	}
	switch args[0] {
	case "keygen":
		if keyDir == "" || publisher == "" {
			return fail("USAGE", "key-dir and publisher are required", 2)
		}
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fail("KEY", "OS signing entropy unavailable", 3)
		}
		// Validate identity before creating any private files.
		p := evidence.Policy{Version: evidence.PolicyVersion, Keys: []evidence.TrustedKey{{Publisher: publisher, KeyID: evidence.Fingerprint(pub), PublicKey: pub, Algorithm: evidence.Algorithm, Engines: []string{evidencesource.Kubernetes, evidencesource.Postgres}, NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}}}
		if p.Validate() != nil {
			return fail("USAGE", "invalid publisher identity", 2)
		}
		dir, err := localstate.CreateDirectory(keyDir)
		if err != nil {
			return fail("KEY", "cannot create protected exclusive signer directory", 3)
		}
		if localstate.WriteNew(filepath.Join(dir, "signer-key.json"), keyRecord{"themis.evidence-signing-key/v1alpha1", publisher, key}) != nil {
			return fail("KEY", "cannot publish protected signing key", 3)
		}
		if !emit(evidence.Publisher{Name: publisher, KeyID: evidence.Fingerprint(pub), PublicKey: pub, Algorithm: evidence.Algorithm, Domain: evidence.Domain}) {
			return 3
		}
		return 0
	case "export":
		if out == "" || len(evidencesource.Inventory(engine)) == 0 || (state == "") == (recordPath == "") || recordPath != "" && (engine != evidencesource.Kubernetes || journalPath == "") {
			return fail("USAGE", "explicit supported engine, state and out are required", 2)
		}
		var files map[string][]byte
		var err error
		if recordPath != "" {
			files, err = exportCoordination(recordPath, journalPath)
		} else {
			files, err = exportRun(engine, state, proposal)
		}
		if err != nil {
			return fail("SOURCE", err.Error(), 6)
		}
		s, c, err := evidencesource.Describe(engine, files)
		if err != nil {
			return fail("SOURCE", err.Error(), 6)
		}
		if err = writeExport(out, files); err != nil {
			return fail("IO", err.Error(), 3)
		}
		if !emit(struct {
			Source evidence.Source       `json:"source"`
			Checks evidence.SourceChecks `json:"sourceChecks"`
		}{s, c}) {
			return 3
		}
		return 0
	case "bundle":
		if source == "" || out == "" || keyDir == "" || publisher == "" || len(evidencesource.Inventory(engine)) == 0 {
			return fail("USAGE", "explicit supported engine, source, out, key-dir and publisher are required", 2)
		}
		var k keyRecord
		if localstate.Read(filepath.Join(keyDir, "signer-key.json"), &k) != nil || k.Version != "themis.evidence-signing-key/v1alpha1" || k.Publisher != publisher || len(k.PrivateKey) != 64 || !bytes.Equal(k.PrivateKey, ed25519.NewKeyFromSeed(k.PrivateKey[:32])) {
			return fail("KEY", "protected signer identity or key invalid", 3)
		}
		artifacts := []evidence.Artifact{}
		for _, a := range evidencesource.Inventory(engine) {
			_, e := os.Lstat(filepath.Join(source, filepath.FromSlash(a.Path)))
			if e == nil {
				artifacts = append(artifacts, a)
			} else if !os.IsNotExist(e) {
				return fail("IO", "source metadata unavailable", 3)
			}
		}
		files, err := evidence.Snapshot(source, artifacts)
		if err != nil {
			return fail("PUBLICATION", err.Error(), 3)
		}
		s, c, err := evidencesource.Describe(engine, files)
		if err != nil || c.Status == "FAILED" {
			return fail("SOURCE", "source evidence is inconsistent; publication refused", 6)
		}
		key := ed25519.PrivateKey(k.PrivateKey)
		pub := key.Public().(ed25519.PublicKey)
		m := evidence.Manifest{Source: s, Publisher: evidence.Publisher{Name: publisher, KeyID: evidence.Fingerprint(pub), PublicKey: pub, Algorithm: evidence.Algorithm, Domain: evidence.Domain}, PublishedAt: now.UTC().Format(time.RFC3339), Artifacts: artifacts}
		data, err := evidence.Sign(m, files, key)
		if err != nil {
			return fail("PUBLICATION", err.Error(), 3)
		}
		o, err := evidenceverify.Verify(bytes.NewReader(data), int64(len(data)), nil, now)
		if err != nil || o.Result.SourceChecks.Status == "FAILED" {
			return fail("SOURCE", "publisher/source authority separation or source checks failed", 6)
		}
		base, _ := filepath.Abs(source)
		dst, _ := filepath.Abs(out)
		rel, e := filepath.Rel(base, dst)
		if e != nil || rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return fail("PUBLICATION", "output must be outside the public source export", 3)
		}
		if err = evidence.PublishBytes(out, data); err != nil {
			return fail("PUBLICATION", err.Error(), 3)
		}
		if !emit(struct {
			Version   string             `json:"version"`
			BundleID  string             `json:"bundleId"`
			Source    evidence.Source    `json:"source"`
			Publisher evidence.Publisher `json:"publisher"`
		}{evidence.Version, o.Manifest.BundleID, s, m.Publisher}) {
			return 3
		}
		return 0
	case "verify", "inspect":
		if bundle == "" {
			return fail("USAGE", "bundle path is required", 2)
		}
		var policy *evidence.Policy
		if args[0] == "verify" {
			if trust == "" {
				return fail("TRUST", "an independent trust-policy path is required", 5)
			}
			b, err := readFile(trust, evidence.MaxManifest)
			if err != nil {
				return fail("TRUST", "external trust policy unavailable", 5)
			}
			p, err := evidence.ReadPolicy(b)
			if err != nil {
				return fail("TRUST", "external trust policy invalid", 5)
			}
			policy = &p
		}
		b, err := readFile(bundle, evidence.MaxArchive)
		if err != nil {
			return fail("IO", "bundle unavailable or oversized", 3)
		}
		o, err := evidenceverify.Verify(bytes.NewReader(b), int64(len(b)), policy, now)
		if err != nil {
			emit(struct {
				Verification evidence.Result `json:"verification"`
				Error        failure         `json:"error"`
			}{o.Result, failure{evidence.ResultVersion, "INTEGRITY_OR_SIGNATURE", err.Error()}})
			return 4
		}
		if !emit(o.Result) {
			return 3
		}
		if args[0] == "inspect" {
			return 0
		}
		if o.Result.PublisherTrust != "TRUSTED" {
			return 5
		}
		switch o.Result.SourceChecks.Status {
		case "FAILED":
			return 6
		case "UNSUPPORTED", "NOT_CHECKED":
			return 7
		case "INCOMPLETE":
			return 8
		}
		return 0
	}
	return 2
}

func readFile(path string, limit int64) ([]byte, error) {
	i, e := os.Lstat(path)
	if e != nil || !i.Mode().IsRegular() || i.Size() > limit {
		return nil, errors.New("invalid file type or size")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, errors.New("file read limit")
	}
	return b, nil
}

// exportRun reads a fixed allowlist twice. It never reads ownership inventories,
// grants, capabilities, credentials, database files or signing keys.
func exportRun(engine, dir, proposal string) (map[string][]byte, error) {
	rootInfo, rootErr := os.Lstat(dir)
	if rootErr != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("source root must be a real directory")
	}
	names := map[string]string{}
	if engine == evidencesource.Postgres {
		for _, n := range []string{"replication-plan.json", "replication-report.json", "replication-prepare.jsonl", "replication-prepared.json", "replication-journal.jsonl"} {
			names[n] = "artifacts/" + n
		}
	} else {
		names["events.jsonl"] = "artifacts/kubernetes-journal.jsonl"
		names["report.json"] = "artifacts/kubernetes-report.json"
	}
	files := map[string][]byte{}
	infos := map[string]os.FileInfo{}
	for sweep := 0; sweep < 2; sweep++ {
		for src, dst := range names {
			p := filepath.Join(dir, src)
			before, e := os.Lstat(p)
			if os.IsNotExist(e) {
				if _, wasPresent := files[dst]; !wasPresent {
					continue
				}
			}
			if e != nil {
				return nil, errors.New("source disappeared during export")
			}
			b, e := readFile(p, evidence.MaxFile)
			if e != nil {
				return nil, e
			}
			after, e := os.Lstat(p)
			if e != nil || !os.SameFile(before, after) || before.ModTime() != after.ModTime() {
				return nil, errors.New("source changed during export")
			}
			if sweep == 0 {
				files[dst] = b
				infos[dst] = after
			} else if !bytes.Equal(files[dst], b) || !os.SameFile(infos[dst], after) {
				return nil, errors.New("source snapshot changed during export")
			}
		}
	}
	if engine == evidencesource.Postgres {
		var original postgres.ReplicationPlan
		if localstate.Unmarshal(files["artifacts/replication-plan.json"], &original) != nil {
			return nil, errors.New("original replication plan unavailable")
		}
		public := postgres.PublicReplicationPlanFrom(original)
		planBytes, e := json.Marshal(public)
		if e != nil {
			return nil, e
		}
		files["artifacts/replication-plan.json"] = planBytes
		var receipts []json.RawMessage
		for _, line := range bytes.Split(bytes.TrimSpace(files["artifacts/replication-prepare.jsonl"]), []byte{'\n'}) {
			var e postgres.Event
			if localstate.Unmarshal(line, &e) != nil {
				return nil, errors.New("invalid preparation journal")
			}
			if e.Kind == "COMMIT_ACKNOWLEDGED" {
				receipts = append(receipts, e.Detail)
			}
		}
		if len(receipts) > 0 {
			b, e := json.Marshal(receipts)
			if e != nil {
				return nil, e
			}
			files["artifacts/replication-receipts.json"] = b
		}
	} else if proposal != "" {
		b, e := readFile(proposal, evidence.MaxFile)
		if e != nil {
			return nil, e
		}
		again, e := readFile(proposal, evidence.MaxFile)
		if e != nil || !bytes.Equal(b, again) {
			return nil, errors.New("proposal changed during export")
		}
		files["artifacts/kubernetes-proposal.json"] = b
	}
	for n, b := range files {
		if e := evidence.CheckPublicArtifact(n, b); e != nil {
			return nil, e
		}
	}
	return files, nil
}

func writeExport(out string, files map[string][]byte) error {
	if e := os.Mkdir(out, 0700); e != nil {
		return errors.New("export directory must be new")
	}
	if e := os.Mkdir(filepath.Join(out, "artifacts"), 0700); e != nil {
		return e
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if e := evidence.PublishBytes(filepath.Join(out, filepath.FromSlash(n)), files[n]); e != nil {
			return e
		}
	}
	return nil
}

func exportCoordination(recordPath, journalPath string) (map[string][]byte, error) {
	data, e := readFile(recordPath, evidence.MaxFile)
	if e != nil {
		return nil, e
	}
	r, e := kubeexperiment.DecodeCoordinationRecord(data)
	if e != nil || r.LiveResult == nil {
		return nil, errors.New("completed public coordination result required")
	}
	j, e := readFile(journalPath, evidence.MaxFile)
	if e != nil {
		return nil, e
	}
	for path, old := range map[string][]byte{recordPath: data, journalPath: j} {
		fresh, e := readFile(path, evidence.MaxFile)
		if e != nil || !bytes.Equal(old, fresh) {
			return nil, errors.New("public coordination source changed during export")
		}
	}
	report, e := json.Marshal(r.LiveResult)
	if e != nil {
		return nil, e
	}
	proposal, e := json.Marshal(r.Proposal)
	if e != nil {
		return nil, e
	}
	files := map[string][]byte{"artifacts/kubernetes-journal.jsonl": j, "artifacts/kubernetes-report.json": report, "artifacts/kubernetes-proposal.json": proposal}
	for n, b := range files {
		if e = evidence.CheckPublicArtifact(n, b); e != nil {
			return nil, e
		}
	}
	return files, nil
}
