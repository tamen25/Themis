package evidence

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sort"
	"time"
)

func archiveBytes(manifest, signature []byte, files map[string][]byte) ([]byte, error) {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	names = append([]string{"manifest.json", "signature.json"}, names...)
	for _, name := range names {
		data := files[name]
		if name == "manifest.json" {
			data = manifest
		}
		if name == "signature.json" {
			data = signature
		}
		h := zip.FileHeader{Name: name, Method: zip.Store, ModifiedDate: 33}
		h.SetMode(0444)
		entry, err := w.CreateHeader(&h)
		if err != nil {
			return nil, err
		}
		if _, err = entry.Write(data); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if b.Len() > MaxArchive {
		return nil, errors.New("archive budget exceeded")
	}
	return b.Bytes(), nil
}

// Sign explicitly publishes a caller-curated in-memory snapshot. It does not
// read a private key, execute a source, authorize a fault or infer execution truth.
func Sign(m Manifest, files map[string][]byte, signer crypto.Signer) ([]byte, error) {
	m.Artifacts = append([]Artifact(nil), m.Artifacts...)
	if signer == nil {
		return nil, errors.New("explicit signing authority required")
	}
	pub, ok := signer.Public().(ed25519.PublicKey)
	if !ok || len(pub) != 32 || !bytes.Equal(pub, m.Publisher.PublicKey) {
		return nil, errors.New("signer differs from declared Ed25519 publisher key")
	}
	if len(m.Artifacts) != len(files) {
		return nil, errors.New("artifact inventory differs from snapshot")
	}
	if len(files) < 1 || len(files) > MaxArtifacts {
		return nil, errors.New("artifact count budget")
	}
	var total int64
	for i, a := range m.Artifacts {
		b, ok := files[a.Path]
		if !ok || len(b) < 1 || len(b) > MaxFile {
			return nil, errors.New("artifact missing or oversized")
		}
		total += int64(len(b))
		if total > MaxTotal {
			return nil, errors.New("artifact total byte budget")
		}
		if err := CheckPublicArtifact(a.Path, b); err != nil {
			return nil, err
		}
		m.Artifacts[i].Bytes = int64(len(b))
		m.Artifacts[i].SHA256 = Hash(b)
	}
	m.Version = Version
	m.Serialization = "go-json-struct-v1"
	m.BundleID = bundleID(m)
	if err := m.validate(); err != nil {
		return nil, err
	}
	b := canonical(m)
	if len(b) > MaxManifest {
		return nil, errors.New("manifest size exceeded")
	}
	sig, err := signer.Sign(rand.Reader, message(b), crypto.Hash(0))
	if err != nil {
		return nil, errors.New("signing failed")
	}
	if !ed25519.Verify(pub, message(b), sig) {
		return nil, errors.New("signer produced invalid signature")
	}
	s := Signature{Version, Algorithm, Domain, m.Publisher.Name, m.Publisher.KeyID, sig}
	return archiveBytes(b, canonical(s), files)
}

// Verify requires only a ReaderAt, external trust policy and explicit clock.
// Source checks are deliberately NOT_CHECKED here; the concrete offline source
// checker must be called separately. There is never a trusted execution PASS.
func Verify(input io.ReaderAt, size int64, policy *Policy, now time.Time) (Opened, error) {
	o := Opened{Result: Result{Version: ResultVersion, ArtifactIntegrity: "INVALID", Signature: "NOT_CHECKED", PublisherTrust: "UNTRUSTED", ExecutionAttestation: "NOT_INDEPENDENTLY_ATTESTED", TrustedExecutionVerdict: "INCONCLUSIVE", RemainingUncertainty: []string{"A publisher signature authenticates an assertion about bytes, not execution truth.", "Embedded observation keys, client timing and unsigned journals are not external execution attestation.", "Conditional source predicates do not authenticate sensors or independently remeasure unsigned SQL, resource and clock summaries."}, SourceChecks: SourceChecks{Status: "NOT_CHECKED", RecomputedCandidate: "INCONCLUSIVE", Checks: []string{}, Problems: []string{}}}}
	if size < 1 || size > MaxArchive || now.IsZero() {
		return o, errors.New("invalid archive size or verification clock")
	}
	if policy != nil {
		if err := policy.Validate(); err != nil {
			return o, err
		}
	}
	data, err := io.ReadAll(io.NewSectionReader(input, 0, size))
	if err != nil || int64(len(data)) != size {
		return o, errors.New("archive read failed")
	}
	if err = preflightZIP(data); err != nil {
		return o, err
	}
	z, err := zip.NewReader(bytes.NewReader(data), size)
	if err != nil {
		return o, errors.New("invalid ZIP")
	}
	if len(z.File) < 3 || len(z.File) > MaxArtifacts+2 || z.Comment != "" {
		return o, errors.New("invalid archive entry count or comment")
	}
	files := map[string][]byte{}
	var total int64
	for _, f := range z.File {
		limit := int64(MaxFile)
		switch f.Name {
		case "manifest.json":
			limit = MaxManifest
		case "signature.json":
			limit = MaxSignature
		default:
			if !pathPattern.MatchString(f.Name) {
				return o, errors.New("unsafe archive path")
			}
		}
		if _, ok := files[f.Name]; ok {
			return o, errors.New("duplicate archive entry")
		}
		if f.Method != zip.Store || !f.Mode().IsRegular() || f.UncompressedSize64 > uint64(limit) || f.CompressedSize64 != f.UncompressedSize64 {
			return o, errors.New("unsafe archive type, compression or size")
		}
		total += int64(f.UncompressedSize64)
		if total > MaxTotal+MaxManifest+MaxSignature {
			return o, errors.New("archive byte budget exhausted")
		}
		r, e := f.Open()
		if e != nil {
			return o, errors.New("cannot open archive entry")
		}
		b, e := io.ReadAll(io.LimitReader(r, limit+1))
		closeErr := r.Close()
		if e != nil || closeErr != nil || int64(len(b)) > limit || uint64(len(b)) != f.UncompressedSize64 {
			return o, errors.New("damaged or oversized archive entry")
		}
		files[f.Name] = b
	}
	mb, sb := files["manifest.json"], files["signature.json"]
	var m Manifest
	if err = decodeCanonical(mb, &m); err != nil {
		return o, err
	}
	if err = m.validate(); err != nil {
		return o, err
	}
	var sig Signature
	if err = decodeCanonical(sb, &sig); err != nil {
		return o, err
	}
	if sig.Version != Version || sig.Algorithm != Algorithm || sig.Domain != Domain || sig.Publisher != m.Publisher.Name || sig.KeyID != m.Publisher.KeyID || len(sig.Signature) != ed25519.SignatureSize {
		return o, errors.New("detached signature identity or algorithm mismatch")
	}
	delete(files, "manifest.json")
	delete(files, "signature.json")
	if len(files) != len(m.Artifacts) {
		return o, errors.New("missing or undeclared artifacts")
	}
	for _, a := range m.Artifacts {
		b, ok := files[a.Path]
		if !ok || int64(len(b)) != a.Bytes || Hash(b) != a.SHA256 {
			return o, errors.New("artifact digest or length mismatch")
		}
	}
	encoded, e := archiveBytes(mb, sb, files)
	if e != nil || !bytes.Equal(data, encoded) {
		return o, errors.New("noncanonical or ambiguous ZIP encoding")
	}
	o.Manifest = m
	o.Artifacts = files
	o.Result.BundleID = m.BundleID
	o.Result.Source = m.Source
	o.Result.ArtifactIntegrity = "VALID"
	o.Result.ArtifactComplete = true
	o.Result.Signature = "INVALID"
	if !ed25519.Verify(m.Publisher.PublicKey, message(mb), sig.Signature) {
		return o, errors.New("invalid manifest signature")
	}
	o.Result.Signature = "VALID"
	o.Result.PublisherTrust, o.Result.TrustReason = publisherTrust(m, policy, now)
	o.Result.AuthenticatedPublisherAssertion = o.Result.PublisherTrust == "TRUSTED"
	return o, nil
}

// Bound central-directory allocation before archive/zip constructs File objects.
// This version never emits ZIP64, split archives, offsets with a prepended base,
// comments, or hidden central entries. The canonical re-encode is a second gate.
func preflightZIP(b []byte) error {
	if len(b) < 22 {
		return errors.New("truncated ZIP")
	}
	e := b[len(b)-22:]
	if !bytes.Equal(e[:4], []byte{'P', 'K', 5, 6}) || binary.LittleEndian.Uint16(e[4:6]) != 0 || binary.LittleEndian.Uint16(e[6:8]) != 0 || binary.LittleEndian.Uint16(e[20:22]) != 0 {
		return errors.New("unsupported ZIP footer")
	}
	count := int(binary.LittleEndian.Uint16(e[10:12]))
	if count < 3 || count > MaxArtifacts+2 || int(binary.LittleEndian.Uint16(e[8:10])) != count {
		return errors.New("ZIP entry budget or split archive")
	}
	start := uint64(binary.LittleEndian.Uint32(e[16:20]))
	length := uint64(binary.LittleEndian.Uint32(e[12:16]))
	end := uint64(len(b) - 22)
	if start+length != end || start > end {
		return errors.New("ambiguous ZIP central directory")
	}
	pos := start
	for i := 0; i < count; i++ {
		if pos+46 > end || !bytes.Equal(b[pos:pos+4], []byte{'P', 'K', 1, 2}) {
			return errors.New("invalid ZIP central record")
		}
		h := b[pos : pos+46]
		name := uint64(binary.LittleEndian.Uint16(h[28:30]))
		extra := uint64(binary.LittleEndian.Uint16(h[30:32]))
		comment := uint64(binary.LittleEndian.Uint16(h[32:34]))
		if name > 96 || extra != 0 || comment != 0 || binary.LittleEndian.Uint32(h[24:28]) > MaxFile {
			return errors.New("ZIP central metadata budget")
		}
		pos += 46 + name + extra + comment
		if pos > end {
			return errors.New("truncated ZIP central metadata")
		}
	}
	if pos != end {
		return errors.New("undeclared ZIP central records")
	}
	return nil
}
