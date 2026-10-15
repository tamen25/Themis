package experiment

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Derive the old wire format from actual observations collected by the live
// test. Real archived T1.1 artifacts are additionally replayed in the handoff.
func testLegacyCompatibility(t *testing.T, directory string, current Report) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(directory, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var legacy bytes.Buffer
	sequence := 0
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatal(err)
		}
		if e.State == BaselineCompleted || e.State == Revalidating || e.State == Cleaning {
			continue
		}
		e.Version = LegacyJournalVersion
		e.Operation = ""
		e.Failure = nil
		sequence++
		e.Sequence = sequence
		if err := json.NewEncoder(&legacy).Encode(e); err != nil {
			t.Fatal(err)
		}
	}
	r, err := Replay(bytes.NewReader(legacy.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	expected := current
	expected.Version = LegacyVersion
	expected.Provenance = nil
	expected.Deadlines = nil
	expected.Failure = nil
	expected.JournalDigest = fmt.Sprintf("sha256:%x", sha256.Sum256(legacy.Bytes()))
	want, _ := json.Marshal(expected)
	got, _ := json.Marshal(r)
	if !bytes.Equal(want, got) {
		t.Fatalf("legacy report semantics changed\nwant %s\ngot %s", want, got)
	}
	if _, err := DecodeReport(got); err != nil {
		t.Fatalf("published report schema rejected: %v", err)
	}
	imported, err := ReplayImported(bytes.NewReader(legacy.Bytes()))
	if err != nil || imported.RecordedReport.Version != LegacyVersion || imported.RecordedReport.Provenance != nil || imported.Provenance.Source != ImportedEvidence || imported.Provenance.ClientTiming != "UNAUTHENTICATED_CLIENT_TIMING" {
		t.Fatalf("legacy import classification: %+v %v", imported, err)
	}
	newData, _ := json.Marshal(current)
	if _, err := DecodeReport(newData); err != nil {
		t.Fatal(err)
	}
	changed := current
	changed.Version = LegacyVersion
	changedData, _ := json.Marshal(changed)
	if _, err := DecodeReport(changedData); err == nil {
		t.Fatal("new report fields accepted under old artifact version")
	}
}
