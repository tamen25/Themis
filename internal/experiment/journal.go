package experiment

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/tamen25/themis/internal/contract"
	"github.com/tamen25/themis/internal/localpolicy"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/plan"
	"github.com/tamen25/themis/internal/result"
	"github.com/tamen25/themis/internal/safety"
)

const maxJournal = 4 << 20

type journal struct {
	file      journalFile
	events    []Event
	runID     string
	epoch     time.Time
	state     State
	version   string
	failed    bool
	checkStop func() error
}

// This is the actual storage boundary used by controlled write/stall tests.
type journalFile interface {
	io.Writer
	Sync() error
	Close() error
}

type journalScan struct {
	Events   []Event
	Manifest Manifest
	Plan     plan.ExperimentPlan
	Version  string
}

func (j *journal) append(e Event) error {
	if j.failed {
		return errors.New("journal previously failed; append refused")
	}
	if j.version == "" {
		j.version = JournalVersion
	}
	if e.Observation == nil {
		if !transitionFor(j.version, j.state, e.State) {
			return errors.New("invalid experiment state transition")
		}
	} else if e.State != j.state || (j.state != Baseline && j.state != Intervention && j.state != Recovery) {
		return errors.New("observation outside phase")
	}
	e.Version = j.version
	if j.version == JournalVersion && e.Observation == nil {
		e.Operation = operationFor(e.State)
		if e.Failure != nil && e.State == Aborted {
			e.Operation = e.Failure.Operation
		}
	}
	e.RunID = j.runID
	e.Sequence = len(j.events) + 1
	e.AtNS = int64(time.Since(j.epoch))
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	n, err := j.file.Write(data)
	if err != nil {
		j.failed = true
		return err
	}
	if n != len(data) {
		j.failed = true
		return io.ErrShortWrite
	}
	if err := j.file.Sync(); err != nil {
		j.failed = true
		return err
	}
	j.events = append(j.events, e)
	j.state = e.State
	return nil
}

func decodePlan(raw []byte) (plan.ExperimentPlan, error) {
	var envelope struct {
		Digest string                  `json:"planDigest"`
		Plan   plan.ExperimentDocument `json:"plan"`
	}
	if err := localstate.Unmarshal(raw, &envelope); err != nil {
		return plan.ExperimentPlan{}, err
	}
	data, err := json.Marshal(envelope.Plan.Contract)
	if err != nil {
		return plan.ExperimentPlan{}, err
	}
	c, err := contract.ParseExperiment(bytes.NewReader(data))
	if err != nil {
		return plan.ExperimentPlan{}, err
	}
	p, err := plan.CompileExperiment(c, envelope.Plan.Target)
	if err != nil {
		return p, err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return plan.ExperimentPlan{}, err
	}
	if !bytes.Equal(compact.Bytes(), p.JSON()) || envelope.Digest != p.Digest() {
		return plan.ExperimentPlan{}, errors.New("experiment plan digest/content mismatch")
	}
	return p, nil
}

func validateManifest(m Manifest, runID string) (plan.ExperimentPlan, error) {
	p, err := decodePlan(m.Plan)
	if err != nil {
		return p, err
	}
	d := p.Snapshot()
	h := m.Handle
	a := m.Authorization
	if m.StartedAt.IsZero() || !plan.ValidInstanceID(runID) || h.RunID != runID || !plan.ValidInstanceID(h.FaultID) || h.AuthorizationID != a.ID || h.FixtureID != d.Target.InstanceID || h.ProxyID != d.Target.ProxyID || h.AdapterVersion != localpolicy.AdapterVersion || !m.StartedAt.Before(h.ExpiresAt) || h.ExpiresAt.After(d.Target.ExpiresAt) || a.Seal != "" {
		return p, errors.New("invalid manifest identity, expiry or secret")
	}
	if err := safety.CheckAuthorization(a, p, a.Actor, m.StartedAt); err != nil {
		return p, err
	}
	return p, nil
}

func ReplayFile(path string) (Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return Report{}, err
	}
	defer f.Close()
	return Replay(f)
}

// Replay never mutates resources or trusts saved verdicts. Response signatures
// are verified, but client clocks and the journal itself are not authenticated.
func Replay(r io.Reader) (Report, error) {
	return replay(r, &journalScan{})
}

func replay(r io.Reader, scan *journalScan) (Report, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxJournal+1))
	if err != nil {
		return Report{}, err
	}
	if len(data) == 0 || len(data) > maxJournal || data[len(data)-1] != '\n' {
		return Report{}, errors.New("empty, oversized or partially written experiment journal")
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 128<<10)
	var events []Event
	var state State
	var runID string
	var p plan.ExperimentPlan
	var manifest Manifest
	var lastAt int64
	var phaseAt int64
	lastIndex := -1
	seen := map[string]bool{}
	for scanner.Scan() {
		var e Event
		if err := localstate.Unmarshal(scanner.Bytes(), &e); err != nil {
			return Report{}, fmt.Errorf("experiment journal: %w", err)
		}
		if (e.Version != JournalVersion && e.Version != LegacyJournalVersion) || (scan.Version != "" && scan.Version != e.Version) || e.Sequence != len(events)+1 || e.AtNS < lastAt || e.AtNS < 0 || state == Finalized || (runID != "" && e.RunID != runID) {
			return Report{}, errors.New("invalid journal version, ordering, clock or run identity")
		}
		if len(events) == 0 {
			if e.Manifest == nil || e.State != Authorized {
				return Report{}, errors.New("missing authorized manifest")
			}
			manifest = *e.Manifest
			runID = e.RunID
			p, err = validateManifest(manifest, runID)
			if err != nil {
				return Report{}, err
			}
		} else if e.Manifest != nil {
			return Report{}, errors.New("duplicate manifest")
		}
		if e.Version == LegacyJournalVersion && (e.Operation != "" || e.Failure != nil) {
			return Report{}, errors.New("T1.2 fields in a T1.1 journal")
		}
		if e.Version == JournalVersion && e.Observation == nil {
			if e.State == Aborted {
				if e.Failure == nil || !validOperation(e.Failure.Operation) || e.Failure.Code == "" || e.Failure.Reason == "" || e.Operation != e.Failure.Operation {
					return Report{}, errors.New("abort lacks explicit operation/failure")
				}
			}
			if e.Failure != nil && e.State != Aborted && e.State != Finalized && e.State != Pending {
				return Report{}, errors.New("failure payload outside abort/finalization")
			}
			if e.State != Aborted && e.Operation != operationFor(e.State) {
				return Report{}, errors.New("invalid operation/state mapping")
			}
			if e.Failure != nil {
				intent, ack := false, false
				for _, prior := range events {
					intent = intent || prior.State == Intent
					ack = ack || prior.State == Applied
				}
				if !intent && (e.Failure.FaultAttempted == nil || *e.Failure.FaultAttempted) {
					return Report{}, errors.New("application uncertainty before any fault intent")
				}
				if ack && (e.Failure.FaultAttempted == nil || !*e.Failure.FaultAttempted) {
					return Report{}, errors.New("failure contradicts acknowledged application")
				}
			}
		}
		if e.Observation != nil {
			if e.State != state || (state != Baseline && state != Intervention && state != Recovery) || e.Receipt != nil || e.Status != "" {
				return Report{}, errors.New("invalid observation state or payload")
			}
			phase, duration, count := phaseConfig(p, state)
			o := *e.Observation
			if o.Phase != phase || o.Index <= lastIndex || o.Index >= count || !plan.ValidInstanceID(o.RequestID) || seen[o.RequestID] || len(o.Probes) != 3 {
				return Report{}, errors.New("invalid observation identity, count or phase")
			}
			seen[o.RequestID] = true
			slot := int64(duration / time.Duration(count))
			start := phaseAt + int64(o.Index)*slot
			end := phaseAt + int64(duration)
			for i, probe := range o.Probes {
				if probe.Kind != []string{"direct", "proxy", "application"}[i] || probe.StartedNS < start || probe.StartedNS >= start+slot || probe.CompletedNS < probe.StartedNS || probe.CompletedNS > e.AtNS || probe.CompletedNS > end+int64(50*time.Millisecond) {
					return Report{}, errors.New("invalid observation timing or kind")
				}
				if probe.Outcome == "http" {
					if probe.StatusCode < 100 || probe.StatusCode > 599 || probe.Response == nil {
						return Report{}, errors.New("invalid HTTP observation")
					}
				} else if probe.Outcome != "request-error" || probe.StatusCode != 0 || probe.Response != nil {
					return Report{}, errors.New("invalid request error observation")
				}
			}
			lastIndex = o.Index
		} else {
			if !transitionFor(e.Version, state, e.State) {
				return Report{}, errors.New("invalid journal state transition")
			}
			if e.State == Applied {
				if e.Receipt == nil || e.Receipt.Handle != manifest.Handle || e.Receipt.AppliedAt.Before(manifest.StartedAt) || e.Receipt.FaultExpiresAt.After(manifest.Handle.ExpiresAt) || !e.Receipt.AppliedAt.Before(e.Receipt.FaultExpiresAt) {
					return Report{}, errors.New("invalid application receipt")
				}
			} else if e.Receipt != nil {
				return Report{}, errors.New("unexpected receipt")
			}
			if e.State == Finalized {
				if e.Status != result.Succeeded && e.Status != result.Cancelled && e.Status != result.TimedOut && e.Status != result.Error && e.Status != result.CleanupPending {
					return Report{}, errors.New("invalid terminal status")
				}
			} else if e.State == Aborted {
				if e.Status != result.Cancelled && e.Status != result.TimedOut && e.Status != result.Error {
					return Report{}, errors.New("invalid abort status")
				}
			} else if e.Status != "" {
				return Report{}, errors.New("unexpected execution status")
			}
			if e.State == Baseline || e.State == Intervention || e.State == Recovery {
				phaseAt = e.AtNS
				lastIndex = -1
			}
		}
		if e.State == Cleaned || e.State == Pending {
			target := p.Snapshot().Target
			if len(e.Residuals) != 3 {
				return Report{}, errors.New("missing residual checks")
			}
			for i, endpoint := range []string{target.ServiceURL, target.ProxyURL, target.ControlURL} {
				probe := e.Residuals[i]
				if probe.Endpoint != endpoint || (probe.Outcome != "connection-refused" && probe.Outcome != "listening" && probe.Outcome != "unknown") {
					return Report{}, errors.New("invalid residual check")
				}
			}
			pendingPersistence := e.Version == JournalVersion && e.State == Pending && e.Failure != nil && e.Failure.Operation == OpReceipt && e.Failure.Code == "CLEANUP_RECEIPT_WRITE_FAILED"
			if (e.State == Cleaned) != residualsClosed(e.Residuals) && !pendingPersistence {
				return Report{}, errors.New("cleanup state differs from residual checks")
			}
		} else if len(e.Residuals) != 0 {
			return Report{}, errors.New("unexpected residual checks")
		}
		state = e.State
		lastAt = e.AtNS
		events = append(events, e)
		scan.Events = events
		scan.Manifest = manifest
		scan.Plan = p
		scan.Version = e.Version
	}
	if err := scanner.Err(); err != nil {
		return Report{}, err
	}
	report := evaluate(p, manifest, events)
	report.JournalDigest = fmt.Sprintf("sha256:%x", sha256.Sum256(data))
	return report, nil
}

func phaseConfig(p plan.ExperimentPlan, state State) (string, time.Duration, int) {
	s := p.Snapshot().Contract.Spec
	switch state {
	case Baseline:
		d, _ := time.ParseDuration(s.Baseline.Duration)
		return "baseline", d, s.Baseline.Samples
	case Intervention:
		d, _ := time.ParseDuration(s.Fault.Duration)
		return "intervention", d, s.Observation.Samples
	default:
		d, _ := time.ParseDuration(s.Recovery.Duration)
		return "recovery", d, s.Recovery.Samples
	}
}
