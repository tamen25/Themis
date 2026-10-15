package run

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/tamen25/themis/internal/contract"
	"github.com/tamen25/themis/internal/localpolicy"
	"github.com/tamen25/themis/internal/plan"
	"github.com/tamen25/themis/internal/probe"
	"github.com/tamen25/themis/internal/result"
)

type terminal struct {
	Status    result.ExecutionStatus `json:"status"`
	ElapsedNS int64                  `json:"elapsedNS"`
}

type event struct {
	SchemaVersion string             `json:"schemaVersion"`
	RunID         string             `json:"runID"`
	Sequence      int                `json:"sequence"`
	Type          string             `json:"type"`
	Manifest      *Manifest          `json:"manifest,omitempty"`
	Sample        *probe.Observation `json:"sample,omitempty"`
	Terminal      *terminal          `json:"terminal,omitempty"`
}

func ReplayFile(path string) (Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return Report{}, err
	}
	defer f.Close()
	return Replay(f)
}

// Replay revalidates frozen inputs and observations, then recomputes coverage and
// verdicts. No persisted assertion verdict is trusted, and no network is used.
// This is consistency checking of unsigned evidence, not proof of authenticity.
func Replay(reader io.Reader) (Report, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxJournalBytes+1))
	if err != nil {
		return Report{}, err
	}
	if len(data) > maxJournalBytes {
		return Report{}, errors.New("journal exceeds 16 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var m Manifest
	var c contract.Validated
	var runID string
	var slots []slot
	var duration time.Duration
	var samples []probe.Observation
	var end *terminal
	sequence, lastIndex := 0, -1
	var lastCompletion int64
	for {
		var e event
		if err := decoder.Decode(&e); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return Report{}, fmt.Errorf("decode journal event: %w", err)
		}
		sequence++
		if e.SchemaVersion != SchemaVersion || e.Sequence != sequence || (sequence > 1 && e.RunID != runID) || end != nil {
			return Report{}, errors.New("invalid journal version, identity, sequence or terminal ordering")
		}
		switch e.Type {
		case "started":
			if sequence != 1 || e.Manifest == nil || e.Sample != nil || e.Terminal != nil || !validRunID(e.RunID) {
				return Report{}, errors.New("invalid started event")
			}
			runID, m = e.RunID, *e.Manifest
			if m.PolicyVersion != PolicyVersion || m.StartedAt.IsZero() {
				return Report{}, errors.New("unsupported policy or missing start time")
			}
			c, err = contract.Parse(bytes.NewReader(m.Contract))
			if err != nil {
				return Report{}, fmt.Errorf("journal contract: %w", err)
			}
			p, err := plan.Compile(c)
			if err != nil {
				return Report{}, err
			}
			if c.Digest() != m.ContractDigest || p.Digest() != m.PlanDigest || !bytes.Equal(c.NormalizedJSON(), m.Contract) || !bytes.Equal(p.JSON(), m.Plan) {
				return Report{}, errors.New("journal contract or plan digest/content mismatch")
			}
			if err := admit(c, p, m.ApprovedPlan); err != nil {
				return Report{}, err
			}
			slots, duration, err = schedule(c)
			if err != nil {
				return Report{}, err
			}
		case "sample":
			if sequence == 1 || e.Sample == nil || e.Manifest != nil || e.Terminal != nil {
				return Report{}, errors.New("invalid sample event")
			}
			o := *e.Sample
			if o.Index <= lastIndex || o.Index >= len(slots) {
				return Report{}, errors.New("duplicate or out-of-range sample index")
			}
			s := slots[o.Index]
			if o.Phase != s.phase || o.StartedNS < int64(s.at) || o.StartedNS >= int64(min(s.at+Interval, s.end)) || o.StartedNS < lastCompletion || o.CompletedNS < o.StartedNS {
				return Report{}, errors.New("sample timing or phase does not match policy")
			}
			if (o.Outcome == "http" && (o.StatusCode < 200 || o.StatusCode > 599)) || (o.Outcome != "http" && o.StatusCode != 0) {
				return Report{}, errors.New("invalid observed HTTP status")
			}
			if !observed(o) && o.Outcome != "cancelled" {
				return Report{}, errors.New("unsupported observation outcome")
			}
			if (observed(o) && o.CompletedNS > int64(s.end)) || (o.Outcome == "http" && o.CompletedNS-o.StartedNS > int64(localpolicy.RequestTimeout)) {
				return Report{}, errors.New("completed observation exceeds phase or request deadline")
			}
			samples = append(samples, o)
			lastIndex, lastCompletion = o.Index, o.CompletedNS
		case "finished":
			if sequence == 1 || e.Terminal == nil || e.Manifest != nil || e.Sample != nil {
				return Report{}, errors.New("invalid finished event")
			}
			end = e.Terminal
			if end.ElapsedNS < lastCompletion || (end.Status != result.Succeeded && end.Status != result.Cancelled && end.Status != result.TimedOut) || (end.Status == result.Succeeded && end.ElapsedNS < int64(duration)) {
				return Report{}, errors.New("invalid terminal status or timing")
			}
		default:
			return Report{}, fmt.Errorf("unsupported journal event type %q", e.Type)
		}
	}
	if sequence == 0 {
		return Report{}, errors.New("empty journal")
	}
	if end == nil {
		end = &terminal{Status: result.Error, ElapsedNS: lastCompletion}
	}
	return evaluate(runID, c, m, slots, duration, samples, *end, fmt.Sprintf("sha256:%x", sha256.Sum256(data))), nil
}

func validRunID(id string) bool {
	if !strings.HasPrefix(id, "run-") || len(id) < 5 || len(id) > 64 {
		return false
	}
	for _, c := range id[4:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}
