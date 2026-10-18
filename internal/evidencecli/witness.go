package evidencecli

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/tamen25/themis/internal/localstate"
	obs "github.com/tamen25/themis/pkg/liveobservation"
	"path/filepath"
)

// Only two public session files are read. Witness keys and Kubernetes credentials
// are never exported; exact raw journal bytes survive wrapping, including tears.
func exportWitness(files map[string][]byte, session string) error {
	regPath := filepath.Join(session, "registration.json")
	journalPath := filepath.Join(session, "observations.jsonl")
	reg, e := readFile(regPath, obs.MaxRecord)
	if e != nil {
		return e
	}
	raw, e := readFile(journalPath, obs.MaxJournal)
	if e != nil {
		return e
	}
	for path, before := range map[string][]byte{regPath: reg, journalPath: raw} {
		after, e := readFile(path, obs.MaxJournal)
		if e != nil || !bytes.Equal(before, after) {
			return errors.New("witness source changed during export")
		}
	}
	var registration obs.Registration
	if localstate.Unmarshal(reg, &registration) != nil || registration.Validate() != nil {
		return errors.New("invalid public witness registration")
	}
	canonical, e := json.Marshal(registration)
	if e != nil {
		return e
	}
	journal, e := obs.EncodeJournal(raw)
	if e != nil {
		return e
	}
	files["artifacts/witness-registration.json"] = canonical
	files["artifacts/witness-journal.json"] = journal
	return nil
}
