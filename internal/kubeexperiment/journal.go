package kubeexperiment

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/localstate"
)

const JournalVersion = "themis.kubernetes-experiment-journal/v1alpha1"
const LifecycleJournalVersion = "themis.kubernetes-experiment-journal/v1alpha2"

type Probe struct {
	Kind        string          `json:"kind"`
	StartedNS   int64           `json:"startedNS"`
	CompletedNS int64           `json:"completedNS"`
	HTTPCode    int             `json:"httpCode"`
	Response    *kubefault.Data `json:"response,omitempty"`
}
type Observation struct {
	Phase     string  `json:"phase"`
	Index     int     `json:"index"`
	RequestID string  `json:"requestID"`
	Probes    []Probe `json:"probes"`
}
type AuthorizationSummary struct {
	Version       string          `json:"version"`
	InvocationID  string          `json:"invocationID"`
	PlanDigest    string          `json:"planDigest"`
	Actor         kubefault.Actor `json:"actor"`
	IssuedAt      time.Time       `json:"issuedAt"`
	ApplyBefore   time.Time       `json:"applyBefore"`
	CleanupBefore time.Time       `json:"cleanupBefore"`
}
type Event struct {
	Version       string                `json:"version"`
	Sequence      int                   `json:"sequence"`
	AtNS          int64                 `json:"atNS"`
	Type          string                `json:"type"`
	Plan          *kubefault.Plan       `json:"plan,omitempty"`
	Authorization *AuthorizationSummary `json:"authorization,omitempty"`
	Observation   *Observation          `json:"observation,omitempty"`
	Status        *kubefault.Status     `json:"status,omitempty"`
	Attempted     *bool                 `json:"attempted,omitempty"`
	Execution     string                `json:"execution,omitempty"`
	Reason        string                `json:"reason,omitempty"`
	ActionID      string                `json:"actionID,omitempty"`
	Previous      string                `json:"previous"`
	Hash          string                `json:"hash"`
}

type journalFile interface {
	io.Writer
	Sync() error
	Close() error
}
type journal struct {
	file                  journalFile
	epoch                 time.Time
	events                []Event
	poisoned              bool
	version               string
	stop                  func() error
	coordinationDirectory string
	coordinationDigest    string
}

func (j *journal) append(e Event) error {
	if j.poisoned {
		return errors.New("journal writer is poisoned")
	}
	e.Version = j.version
	if e.Version == "" {
		e.Version = JournalVersion
	}
	e.Sequence = len(j.events)
	e.AtNS = int64(time.Since(j.epoch))
	if len(j.events) > 0 {
		e.Previous = j.events[len(j.events)-1].Hash
	}
	e.Hash = kubefault.Digest(e.Version, e)
	data, err := json.Marshal(e)
	if err == nil {
		data = append(data, '\n')
		var n int
		n, err = j.file.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		err = j.file.Sync()
	}
	if err != nil {
		j.poisoned = true
		return err
	}
	j.events = append(j.events, e)
	return nil
}

// ReadJournal validates a complete bounded stream. Hash chaining is corruption
// detection, not authentication. Imported event bytes can never establish PASS.
func ReadJournal(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 16<<20 {
		return nil, errors.New("invalid or oversized journal file")
	}
	data, err := io.ReadAll(io.LimitReader(f, (16<<20)+1))
	if err != nil {
		return nil, err
	}
	return ReadJournalBytes(data)
}

// ReadJournalBytes performs the same bounded historical parsing without opening
// any filesystem path or connecting to a cluster. T4 source checks use it.
func ReadJournalBytes(data []byte) ([]Event, error) {
	if len(data) == 0 || len(data) > 16<<20 {
		return nil, errors.New("invalid or oversized journal file")
	}
	if data[len(data)-1] != '\n' {
		return nil, errors.New("torn experiment journal")
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 65537)
	events := []Event{}
	bytes := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		bytes += len(line) + 1
		if bytes > 16<<20 || len(events) >= 256 {
			return nil, errors.New("experiment journal exceeds bounds")
		}
		var e Event
		if kubefault.Decode(line, &e) != nil {
			return nil, errors.New("experiment journal has invalid fields")
		}
		h := e.Hash
		e.Hash = ""
		if h != kubefault.Digest(e.Version, e) || (e.Version != JournalVersion && e.Version != LifecycleJournalVersion) || e.Sequence != len(events) || e.AtNS < 0 {
			return nil, errors.New("experiment journal identity/sequence/hash mismatch")
		}
		e.Hash = h
		if len(events) == 0 {
			if e.Type != "START" || e.Plan == nil || e.Authorization == nil || e.Plan.Validate() != nil || e.Authorization.PlanDigest != e.Plan.Digest() || e.Previous != "" {
				return nil, errors.New("invalid experiment start")
			}
		} else {
			last := events[len(events)-1]
			if e.Version != last.Version || e.Previous != last.Hash || e.AtNS < last.AtNS || last.Type == "FINAL" || e.Plan != nil || e.Authorization != nil {
				return nil, errors.New("invalid experiment event order")
			}
		}
		if !validEventType(e.Type) {
			return nil, errors.New("unsupported experiment event")
		}
		if (e.Type == "CANCEL_ACCEPTED" || e.ActionID != "") && e.Version != LifecycleJournalVersion {
			return nil, errors.New("lifecycle event in legacy journal")
		}
		if e.Type == "OBSERVATION" {
			if e.Observation == nil || e.Status != nil {
				return nil, errors.New("invalid observation event")
			}
		} else if e.Observation != nil {
			return nil, errors.New("observation in wrong event")
		}
		events = append(events, e)
	}
	if scanner.Err() != nil {
		return nil, scanner.Err()
	}
	if len(events) == 0 {
		return nil, errors.New("empty experiment journal")
	}
	return events, nil
}
func validEventType(t string) bool {
	switch t {
	case "START", "BASELINE", "INTENT", "APPLIED", "INTERVENTION", "REMOVED", "RECOVERY", "OBSERVATION", "ABORT", "CANCEL_ACCEPTED", "FINAL":
		return true
	}
	return false
}

func publicAuthorization(g kubefault.Grant) AuthorizationSummary {
	return AuthorizationSummary{g.Version, g.InvocationID, g.PlanDigest, g.Plan.Operator, g.IssuedAt, g.ApplyBefore, g.CleanupBefore}
}
func writePrivate(path string, value any) error { return localstate.WriteNew(path, value) }
