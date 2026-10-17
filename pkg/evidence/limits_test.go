package evidence

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func TestCentralDirectoryCountIsBoundedBeforeZIPAllocation(t *testing.T) {
	m, f, k, _ := fixture(t)
	b, e := Sign(m, f, k)
	if e != nil {
		t.Fatal(e)
	}
	for _, count := range []uint16{0, 2, MaxArtifacts + 3, 65535} {
		copy := append([]byte{}, b...)
		footer := copy[len(copy)-22:]
		binary.LittleEndian.PutUint16(footer[8:10], count)
		binary.LittleEndian.PutUint16(footer[10:12], count)
		if preflightZIP(copy) == nil {
			t.Fatal("unsafe central count accepted", count)
		}
	}
}

func TestManifestIndividualAndAggregateBudgets(t *testing.T) {
	m, f, k, _ := fixture(t)
	b, e := Sign(m, f, k)
	if e != nil {
		t.Fatal(e)
	}
	o, e := verifyTest(b, nil)
	if e != nil {
		t.Fatal(e)
	}
	m = o.Manifest
	m.Artifacts[0].Bytes = MaxFile + 1
	m.BundleID = bundleID(m)
	if m.validate() == nil {
		t.Fatal("individual file budget ignored")
	}
	m = o.Manifest
	m.Artifacts = []Artifact{}
	for n := 0; n < 5; n++ {
		m.Artifacts = append(m.Artifacts, Artifact{Path: fmt.Sprintf("artifacts/file-%02d.json", n), Role: "source-report", Version: "test/v1", SHA256: Hash([]byte("test")), Bytes: 7 << 20})
	}
	m.BundleID = bundleID(m)
	if m.validate() == nil {
		t.Fatal("total byte budget ignored")
	}
	m = o.Manifest
	m.Artifacts = []Artifact{}
	files := map[string][]byte{}
	for n := 0; n < MaxArtifacts+1; n++ {
		path := fmt.Sprintf("artifacts/file-%02d.json", n)
		m.Artifacts = append(m.Artifacts, Artifact{Path: path, Role: "source-report", Version: "test/v1"})
		files[path] = []byte(`{}`)
	}
	if _, e = Sign(m, files, k); e == nil {
		t.Fatal("artifact count budget ignored")
	}
}
