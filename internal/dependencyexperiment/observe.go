package dependencyexperiment

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	wire "github.com/tamen25/themis/internal/dependencyhttp"
	"github.com/tamen25/themis/internal/localstate"
)

type Probe struct {
	Kind        string      `json:"kind"`
	Nonce       string      `json:"nonce"`
	StartedNS   int64       `json:"startedNS"`
	CompletedNS int64       `json:"completedNS"`
	Response    *wire.Reply `json:"response,omitempty"`
	Error       string      `json:"error"`
}
type Observation struct {
	Version    string  `json:"version"`
	PlanDigest string  `json:"planDigest"`
	Session    string  `json:"session"`
	Sequence   int     `json:"sequence"`
	Kind       string  `json:"kind"`
	Probes     []Probe `json:"probes"`
	Previous   string  `json:"previous"`
	Hash       string  `json:"hash"`
}
type ObserverReport struct {
	Version    string        `json:"version"`
	PlanDigest string        `json:"planDigest"`
	Session    string        `json:"session"`
	Complete   bool          `json:"complete"`
	Records    []Observation `json:"records"`
	Provenance string        `json:"provenance"`
}

func publicRead(path string, out any) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if e != nil {
		return e
	}
	if len(b) > 1<<20 {
		return errors.New("input bound")
	}
	return localstate.Unmarshal(b, out)
}
func Observe(ctx context.Context, state string, p wire.Plan, directory string) (ObserverReport, error) {
	report := ObserverReport{Version: "themis.native-http-observations/v1alpha1", PlanDigest: p.Digest(), Session: wire.ID(), Records: []Observation{}, Provenance: "UNSIGNED_SEPARATE_PROCESS_CLIENT_MEASUREMENTS_NOT_EXECUTION_ATTESTATION"}
	if !p.Valid() {
		return report, wire.ErrDenied
	}
	c, e := Open(ctx, state, "observer")
	if e != nil {
		return report, e
	}
	if e = c.Check(ctx, p.Binding.Target); e != nil {
		return report, e
	}
	dir, e := localstate.CreateDirectory(directory)
	if e != nil {
		return report, e
	}
	journal, e := localstate.OpenNew(filepath.Join(dir, "observations.jsonl"))
	if e != nil {
		return report, e
	}
	defer journal.Close()
	appendRecord := func(kind string, probes []Probe) error {
		record := Observation{Version: report.Version, PlanDigest: p.Digest(), Session: report.Session, Sequence: len(report.Records), Kind: kind, Probes: probes}
		if len(report.Records) > 0 {
			record.Previous = report.Records[len(report.Records)-1].Hash
		}
		record.Hash = wire.Hash(record)
		b := append(wire.JSON(record), '\n')
		if len(b) > 32<<10 || len(report.Records) >= 64 {
			return errors.New("observation bound")
		}
		n, e := journal.Write(b)
		if e == nil && n != len(b) {
			e = io.ErrShortWrite
		}
		if e == nil {
			e = journal.Sync()
		}
		if e != nil {
			return e
		}
		report.Records = append(report.Records, record)
		return nil
	}
	a, e := c.Data("application")
	if e != nil {
		return report, e
	}
	defer a.Close()
	proxy, e := c.Data("proxy")
	if e != nil {
		return report, e
	}
	defer proxy.Close()
	dep, e := c.Data("dependency")
	if e != nil {
		return report, e
	}
	defer dep.Close()
	if e = appendRecord("START", []Probe{}); e != nil {
		return report, e
	}
	start := time.Now()
	baseline := 0
	ready := false
	for time.Since(start) < 6*time.Second && len(report.Records) < 55 {
		if ctx.Err() != nil {
			break
		}
		tick := time.Now()
		probes := make([]Probe, 3)
		done := make(chan int, 3)
		for i, item := range []struct {
			kind string
			conn *Connection
		}{{"direct", dep}, {"proxy", proxy}, {"application", a}} {
			go func(i int, kind string, conn *Connection) {
				nonce := wire.ID()
				probe := Probe{Kind: kind, Nonce: nonce, StartedNS: time.Since(start).Nanoseconds()}
				r, err := wire.Fetch(ctx, conn.Client, conn.Base+"/value?nonce="+nonce)
				probe.CompletedNS = time.Since(start).Nanoseconds()
				if err != nil {
					probe.Error = "missing-or-timed-out-probe"
				} else {
					probe.Response = &r
				}
				probes[i] = probe
				done <- i
			}(i, item.kind, item.conn)
		}
		for range 3 {
			<-done
		}
		if e = appendRecord("SAMPLE", probes); e != nil {
			return report, e
		}
		sample := classifySample(p, report.Records[len(report.Records)-1], "")
		if !ready && sample.phase == "baseline" && sample.valid && sample.applicationMS <= float64(p.MaxApplicationMS) {
			baseline++
		} else if !ready {
			baseline = 0
		}
		if baseline >= 3 && !ready {
			if e = localstate.WriteNew(filepath.Join(dir, "ready.json"), struct{ PlanDigest, Session string }{p.Digest(), report.Session}); e != nil {
				return report, e
			}
			ready = true
		}
		wait := 150*time.Millisecond - time.Since(tick)
		if wait > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(wait):
			}
		}
	}
	kind := "END"
	if ctx.Err() != nil {
		kind = "INTERRUPTED"
	}
	if e = appendRecord(kind, []Probe{}); e != nil {
		return report, e
	}
	report.Complete = kind == "END" && ready
	e = localstate.WriteNew(filepath.Join(dir, "observations.json"), report)
	return report, e
}

type sampleFinding struct {
	valid                            bool
	transition                       bool
	phase                            string
	applicationMS, proxyMS, directMS float64
	holdNS                           int64
	applicationCode                  int
	invocation                       string
}

func classifySample(p wire.Plan, o Observation, invocation string) sampleFinding {
	f := sampleFinding{}
	if o.Kind != "SAMPLE" || len(o.Probes) != 3 {
		return f
	}
	var replies [3]*wire.Reply
	var duration [3]float64
	identities := []wire.Process{p.Binding.Target.Dependency.Process, p.Binding.Target.Proxy.Process, p.Binding.Target.Application.Process}
	for i, kind := range []string{"direct", "proxy", "application"} {
		q := o.Probes[i]
		if q.Kind != kind || q.Error != "" || q.Response == nil || q.CompletedNS < q.StartedNS || q.CompletedNS-q.StartedNS > int64(time.Second) || !q.Response.Verified(identities[i], q.Nonce, "value") {
			return f
		}
		replies[i] = q.Response
		duration[i] = float64(q.CompletedNS-q.StartedNS) / 1e6
	}
	direct, proxy, app := replies[0], replies[1], replies[2]
	if direct.Code != 200 || direct.Value != "synthetic-dependency-v1" || proxy.Dependency == nil || !proxy.Dependency.Verified(identities[0], o.Probes[1].Nonce, "value") || proxy.Dependency.Code != 200 {
		return f
	}
	// The application must return the real nonce-bound proxy/dependency response.
	// An error response is still a credible application outcome, but is not effect proof.
	if app.Code == 200 && (app.Proxy == nil || !app.Proxy.Verified(identities[1], o.Probes[2].Nonce, "value") || app.Proxy.Dependency == nil || !app.Proxy.Dependency.Verified(identities[0], o.Probes[2].Nonce, "value") || app.Proxy.Dependency.Code != 200) {
		return f
	}
	f = sampleFinding{valid: true, applicationMS: duration[2], proxyMS: duration[1], directMS: duration[0], holdNS: proxy.HoldNS, applicationCode: app.Code, invocation: proxy.State.Invocation, phase: "baseline"}
	if proxy.State.Invocation != "" {
		if proxy.PlanDigest != p.Digest() {
			return sampleFinding{}
		}
		if !proxy.State.Applied || !proxy.State.Active || proxy.State.ApplyCount != 1 || proxy.State.StartedNS < 0 || proxy.State.DeadlineNS <= proxy.State.StartedNS || proxy.State.DeadlineNS-proxy.State.StartedNS > int64(p.LifetimeMS)*int64(time.Millisecond) {
			return sampleFinding{}
		}
		if invocation != "" && proxy.State.Invocation != invocation {
			return sampleFinding{}
		}
		f.phase = "active"
	}
	if app.Proxy != nil && app.Proxy.State.Invocation != proxy.State.Invocation {
		f.valid = false
		left, right := app.Proxy.State.Invocation, proxy.State.Invocation
		f.transition = (left == "" || left == invocation) && (right == "" || right == invocation)
	}
	if proxy.HoldNS < 0 || float64(proxy.HoldNS) > duration[1]*1e6 {
		f.valid = false
		f.transition = false
	}
	return f
}

type Evaluation struct {
	Verdict          string   `json:"verdict"`
	Baseline         int      `json:"baseline"`
	Active           int      `json:"active"`
	Effects          int      `json:"effects"`
	Recovery         int      `json:"recovery"`
	Violations       int      `json:"violations"`
	MaxApplicationMS float64  `json:"maxApplicationMS"`
	Problems         []string `json:"problems"`
}

func Evaluate(p wire.Plan, observations ObserverReport, invocation string, cleanup bool) Evaluation {
	out := Evaluation{Verdict: "INCONCLUSIVE", Problems: []string{}}
	if !p.Valid() || observations.Version != "themis.native-http-observations/v1alpha1" || observations.PlanDigest != p.Digest() || !observations.Complete || len(observations.Records) < 3 || len(observations.Records) > 64 {
		return out
	}
	seenNonces := map[string]bool{}
	previous := ""
	active := false
	baselineMax := float64(0)
	lastCompleted := int64(0)
	uncertainEvidence := false
	for i, o := range observations.Records {
		original := o.Hash
		o.Hash = ""
		if o.Version != observations.Version || o.PlanDigest != p.Digest() || o.Session != observations.Session || o.Sequence != i || o.Previous != previous || wire.Hash(o) != original {
			return Evaluation{Verdict: "INCONCLUSIVE", Problems: []string{"corrupt-observation-chain"}}
		}
		previous = original
		if i == 0 && o.Kind != "START" {
			return out
		}
		if i == len(observations.Records)-1 && o.Kind != "END" {
			return out
		}
		if o.Kind != "SAMPLE" {
			if i != 0 && i != len(observations.Records)-1 {
				return out
			}
			continue
		}
		for _, q := range o.Probes {
			if seenNonces[q.Nonce] || q.StartedNS < lastCompleted || q.CompletedNS > int64(7*time.Second) || q.CompletedNS < q.StartedNS {
				return Evaluation{Verdict: "INCONCLUSIVE", Problems: []string{"replayed-observation"}}
			}
			seenNonces[q.Nonce] = true
		}
		for _, q := range o.Probes {
			if q.CompletedNS > lastCompleted {
				lastCompleted = q.CompletedNS
			}
		}
		f := classifySample(p, o, invocation)
		if !f.valid {
			out.Problems = append(out.Problems, "missing-invalid-or-transition-sample")
			if !f.transition {
				uncertainEvidence = true
			}
			continue
		}
		if f.applicationMS > out.MaxApplicationMS {
			out.MaxApplicationMS = f.applicationMS
		}
		if f.phase == "active" {
			active = true
			out.Active++
			if out.Baseline >= 3 && f.proxyMS-f.directMS >= float64(p.DelayMS)*0.7 && float64(f.holdNS) >= float64(p.DelayMS)*0.7*1e6 && f.applicationMS-baselineMax >= float64(p.DelayMS)*0.6 && f.applicationCode == 200 {
				out.Effects++
			}
			if f.applicationCode != 200 || f.applicationMS > float64(p.MaxApplicationMS) {
				out.Violations++
			}
		} else if !active {
			if f.applicationCode == 200 && f.applicationMS <= float64(p.MaxApplicationMS) {
				out.Baseline++
				if f.applicationMS > baselineMax {
					baselineMax = f.applicationMS
				}
			}
		} else if f.applicationCode == 200 && f.applicationMS <= float64(p.MaxApplicationMS) && f.applicationMS <= baselineMax+40 {
			out.Recovery++
		}
	}
	if out.Violations > 0 && out.Active >= 3 && out.Effects >= 3 {
		out.Verdict = "FAIL"
	} else if out.Baseline >= 3 && out.Active >= 3 && out.Effects >= 3 && out.Recovery >= 3 && cleanup && !uncertainEvidence {
		out.Verdict = "PASS"
	}
	if !cleanup {
		out.Problems = append(out.Problems, "cleanup-unconfirmed")
	}
	return out
}
