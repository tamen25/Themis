package experiment

import (
	"bytes"
	"errors"
	"io"
	"os"

	"github.com/tamen25/themis/internal/localstate"
)

type JournalIntegrity string

const (
	JournalComplete    JournalIntegrity = "COMPLETE"
	JournalInterrupted JournalIntegrity = "INTERRUPTED"
	JournalTorn        JournalIntegrity = "TORN_FINAL_RECORD"
	JournalCorrupt     JournalIntegrity = "CORRUPT"
	JournalMissing     JournalIntegrity = "MISSING"
)

type JournalInspection struct {
	Version      string           `json:"version,omitempty"`
	Integrity    JournalIntegrity `json:"integrity"`
	LastState    State            `json:"lastValidState,omitempty"`
	LastSequence int              `json:"lastValidSequence"`
	Operation    Operation        `json:"lastRecordedOperation,omitempty"`
	Error        string           `json:"error,omitempty"`
	scan         journalScan
	report       *Report
}

// Only status consumes a validated prefix. Ordinary replay still rejects torn
// records; neither a prefix nor a saved report authorizes resource mutations.
func inspectJournalFile(path string) JournalInspection {
	result := JournalInspection{Integrity: JournalMissing}
	if err := localstate.Check(path); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			result.Integrity = JournalCorrupt
			result.Error = "journal is inaccessible or not protected"
		}
		return result
	}
	f, err := os.Open(path)
	if err != nil {
		result.Integrity = JournalCorrupt
		result.Error = "journal cannot be opened"
		return result
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxJournal+1))
	if err != nil || len(data) > maxJournal {
		result.Integrity = JournalCorrupt
		result.Error = "journal read failed or exceeded size bound"
		return result
	}
	torn := len(data) > 0 && data[len(data)-1] != '\n'
	if torn {
		if end := bytes.LastIndexByte(data, '\n'); end >= 0 {
			data = data[:end+1]
		} else {
			data = nil
		}
	}
	r, parseErr := replay(bytes.NewReader(data), &result.scan)
	result.Version = result.scan.Version
	if len(result.scan.Events) > 0 {
		last := result.scan.Events[len(result.scan.Events)-1]
		result.LastState = last.State
		result.LastSequence = last.Sequence
		result.Operation = last.Operation
		if result.Operation == "" {
			result.Operation = operationFor(last.State)
		}
	}
	switch {
	case parseErr != nil && len(data) > 0:
		result.Integrity = JournalCorrupt
		result.Error = parseErr.Error()
	case torn:
		result.Integrity = JournalTorn
		result.Error = "final journal record is incomplete; only the valid prefix is shown"
	case parseErr != nil:
		result.Integrity = JournalCorrupt
		result.Error = "empty journal"
	case result.LastState != Finalized:
		result.Integrity = JournalInterrupted
	default:
		result.Integrity = JournalComplete
		result.report = &r
	}
	return result
}
