package experiment

import "io"

type ReplayEnvelope struct {
	Version        string      `json:"version"`
	RecordedReport Report      `json:"recordedReport"`
	Provenance     *Provenance `json:"provenance"`
}

// Import is explicit classification, not approval of an external experiment.
// The nested legacy report retains its published schema and historical verdict.
func ReplayImported(reader io.Reader) (ReplayEnvelope, error) {
	scan := &journalScan{}
	r, err := replay(reader, scan)
	if err != nil {
		return ReplayEnvelope{}, err
	}
	provenance := classifyProvenance(r, scan.Manifest, ImportedEvidence)
	if r.Version == Version {
		r.Provenance = provenance
	}
	return ReplayEnvelope{Version: "themis.experiment-replay/v1alpha1", RecordedReport: r, Provenance: provenance}, nil
}
