package livewitness

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/pkg/evidence"
	obs "github.com/tamen25/themis/pkg/liveobservation"
)

type journalFile interface {
	io.Writer
	Sync() error
	Close() error
}
type journal struct {
	file     journalFile
	reg      obs.Registration
	key      ed25519.PrivateKey
	epoch    time.Time
	process  string
	records  []obs.Record
	bytes    int
	poisoned bool
}

func (j *journal) append(kind, phase, outcome string, probes []obs.Probe, nonce string, start int64) (obs.Record, error) {
	var r obs.Record
	if j.poisoned || len(j.records) >= obs.MaxRecords {
		return r, errors.New("witness writer poisoned or exhausted")
	}
	if start < 0 {
		start = int64(time.Since(j.epoch))
	}
	if nonce == "" {
		nonce = localstate.RandomID()
	}
	if probes == nil {
		probes = []obs.Probe{}
	}
	r = obs.Record{Version: obs.Version, Domain: obs.Domain, Witness: j.reg.Witness, KeyID: j.reg.KeyID, Session: j.reg.Session, Process: j.process, PID: os.Getpid(), RegistrationDigest: obs.RegistrationDigest(j.reg), RunID: j.reg.Plan.RunUID, PlanDigest: j.reg.Plan.Digest(), InvocationID: j.reg.InvocationID, Target: j.reg.Plan.Target.Fixture, Sequence: len(j.records), Type: kind, Phase: phase, Nonce: nonce, UTC: time.Now().UTC().Format(time.RFC3339Nano), StartedNS: start, CompletedNS: int64(time.Since(j.epoch)), Outcome: outcome, Probes: probes}
	if len(j.records) > 0 {
		r.Previous = j.records[len(j.records)-1].Hash
	}
	r = obs.Seal(r, j.key)
	raw, e := json.Marshal(r)
	if e != nil {
		return r, e
	}
	raw = append(raw, '\n')
	if len(raw) > obs.MaxRecord || j.bytes+len(raw) > obs.MaxJournal {
		return r, errors.New("witness journal byte budget")
	}
	n, e := j.file.Write(raw)
	if e == nil && n != len(raw) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = j.file.Sync()
	}
	if e != nil {
		j.poisoned = true
		return r, e
	}
	j.bytes += len(raw)
	j.records = append(j.records, r)
	return r, nil
}

func measure(ctx context.Context, c *kubefault.Client, epoch time.Time, nonce string) []obs.Probe {
	probes := make([]obs.Probe, 3)
	var tasks sync.WaitGroup
	for i, kind := range []string{"direct", "proxy", "application"} {
		tasks.Go(func() {
			p := obs.Probe{Kind: kind, StartedNS: int64(time.Since(epoch)), Outcome: "REQUEST_FAILED"}
			data, code, e := c.Data(ctx, kind, nonce)
			p.CompletedNS = int64(time.Since(epoch))
			if e == nil {
				p.Response = &data
				p.HTTPCode = code
				p.Outcome = "MEASURED"
			}
			probes[i] = p
		})
	}
	tasks.Wait()
	return probes
}

// Observe starts a new process-local epoch and an exclusive journal. No session
// is resumed, and this package never opens a runner inventory or authorization.
func Observe(ctx context.Context, state, session, keyDir string) (obs.Finding, error) {
	reg, e := ReadRegistration(session)
	if e != nil {
		return obs.NewFinding(), e
	}
	k, e := readKey(keyDir)
	if e != nil {
		return obs.NewFinding(), e
	}
	key := ed25519.PrivateKey(k.PrivateKey)
	if k.Witness != reg.Witness || evidence.Fingerprint(key.Public().(ed25519.PublicKey)) != reg.KeyID {
		return obs.NewFinding(), errors.New("registered witness key mismatch")
	}
	now := time.Now()
	begin, _ := obs.UTC(reg.NotBefore)
	end, _ := obs.UTC(reg.NotAfter)
	if now.Before(begin) || !now.Before(end.Add(-obs.MaxDuration)) {
		return obs.NewFinding(), errors.New("witness registration must start in its original bounded window")
	}
	if e = localstate.WriteNew(filepath.Join(session, "observe-claim.json"), struct {
		Session string `json:"session"`
	}{reg.Session}); e != nil {
		return obs.NewFinding(), errors.New("witness session cannot be reused")
	}
	file, e := localstate.OpenNew(filepath.Join(session, "observations.jsonl"))
	if e != nil {
		return obs.NewFinding(), e
	}
	defer file.Close()
	epoch := time.Now()
	j := &journal{file: file, reg: reg, key: key, epoch: epoch, process: localstate.RandomID()}
	if _, e = j.append("START", "", "LIVE_SESSION_STARTED", nil, "", -1); e != nil {
		return obs.NewFinding(), e
	}
	ctx, cancel := context.WithTimeout(ctx, obs.MaxDuration)
	defer cancel()
	terminal := func(reason string) (obs.Finding, error) {
		_, err := j.append("INTERRUPTED", "", reason, nil, "", -1)
		if err != nil {
			return obs.NewFinding(), err
		}
		return inspect(session, nil, time.Now())
	}
	target, e := openTarget(ctx, state, reg.Plan)
	if e != nil {
		return terminal("IDENTITY_UNAVAILABLE")
	}
	conn, e := target.connect(ctx, reg.Plan)
	if e != nil {
		return terminal("IDENTITY_UNAVAILABLE")
	}
	defer conn.Close()
	baseline, intervention, recovery := 0, 0, 0
	active, ready := false, false
	for count := 0; count < reg.MaxSamples; count++ {
		if ctx.Err() != nil {
			if errors.Is(ctx.Err(), context.Canceled) {
				return terminal("CANCELLED")
			}
			return terminal("WINDOW_EXHAUSTED")
		}
		if count%4 == 0 {
			if e = target.check(ctx, reg.Plan); e != nil {
				return terminal("IDENTITY_UNAVAILABLE")
			}
		}
		start := int64(time.Since(epoch))
		nonce := localstate.RandomID()
		probes := measure(ctx, conn.client, epoch, nonce)
		phase := obs.Phase(probes, reg, active)
		outcome := "MEASURED"
		for _, p := range probes {
			if p.Outcome != "MEASURED" {
				phase = "unknown"
				outcome = "MEASUREMENT_UNAVAILABLE"
			}
		}
		_, e = j.append("SAMPLE", phase, outcome, probes, nonce, start)
		if e != nil {
			return obs.NewFinding(), e
		}
		valid := true
		for _, p := range probes {
			if p.Response == nil || !kubefault.VerifyData(*p.Response, reg.Plan.Target.Fixture, nonce, p.Kind, p.HTTPCode) {
				valid = false
			}
		}
		if valid {
			switch phase {
			case "baseline":
				delay := int64(reg.Plan.Fault.DelayMS) * int64(time.Millisecond)
				direct := probes[0].CompletedNS - probes[0].StartedNS
				proxy := probes[1].CompletedNS - probes[1].StartedNS
				if probes[0].HTTPCode == 200 && probes[1].HTTPCode == 200 && probes[2].HTTPCode == 200 && !probes[2].Response.Degraded && proxy-direct <= delay/4 && direct < delay/2 {
					baseline++
				}
			case "intervention":
				active = true
				intervention++
			case "recovery":
				if probes[0].HTTPCode == 200 && probes[1].HTTPCode == 200 && probes[2].HTTPCode == 200 && !probes[2].Response.Degraded {
					recovery++
				}
			}
		}
		if !ready && baseline >= 3 && !active {
			record, e := j.append("READY", "baseline", "REGISTERED_BEFORE_INTERVENTION", nil, "", -1)
			if e != nil {
				return obs.NewFinding(), e
			}
			if e = localstate.WriteNew(filepath.Join(session, "ready.json"), record); e != nil {
				return obs.NewFinding(), e
			}
			ready = true
		}
		if active && !ready {
			return terminal("WINDOW_EXHAUSTED")
		}
		if ready && intervention >= 3 && recovery >= 3 {
			if _, e = j.append("END", "", "COMPLETED", nil, "", -1); e != nil {
				return obs.NewFinding(), e
			}
			return inspect(session, nil, time.Now())
		}
		// Rate bounds apply to the actual start of each measurement, including time
		// spent on identity checks. No catch-up burst is permitted.
		wait := time.Until(epoch.Add(time.Duration(start) + time.Duration(reg.IntervalMillis)*time.Millisecond))
		if wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
			}
		}
	}
	return terminal("WINDOW_EXHAUSTED")
}
func ReadRegistration(session string) (obs.Registration, error) {
	var r obs.Registration
	e := localstate.Read(filepath.Join(session, "registration.json"), &r)
	if e == nil {
		e = r.Validate()
	}
	return r, e
}
func inspect(session string, policy *obs.Policy, now time.Time) (obs.Finding, error) {
	r, e := ReadRegistration(session)
	if e != nil {
		return obs.NewFinding(), e
	}
	if localstate.Check(filepath.Join(session, "observations.jsonl")) != nil {
		return obs.NewFinding(), errors.New("protected witness journal unavailable")
	}
	file, e := os.Open(filepath.Join(session, "observations.jsonl"))
	if e != nil {
		return obs.NewFinding(), e
	}
	defer file.Close()
	data, e := io.ReadAll(io.LimitReader(file, obs.MaxJournal+1))
	if e != nil {
		return obs.NewFinding(), e
	}
	f, _ := obs.Analyze(r, data, policy, now)
	return f, nil
}
func Inspect(session string, policy *obs.Policy, now time.Time) (obs.Finding, error) {
	return inspect(session, policy, now)
}
