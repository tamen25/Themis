package dependencyexperiment

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	wire "github.com/tamen25/themis/internal/dependencyhttp"
	"github.com/tamen25/themis/internal/localstate"
)

type Event struct {
	Version    string      `json:"version"`
	Sequence   int         `json:"sequence"`
	PlanDigest string      `json:"planDigest"`
	Invocation string      `json:"invocation"`
	Kind       string      `json:"kind"`
	Previous   string      `json:"previous"`
	Hash       string      `json:"hash"`
	Reply      *wire.Reply `json:"reply,omitempty"`
}
type Report struct {
	Version                 string         `json:"version"`
	Plan                    wire.Plan      `json:"plan"`
	PlanDigest              string         `json:"planDigest"`
	Invocation              string         `json:"invocation"`
	ApprovalDigest          string         `json:"approvalDigest"`
	Execution               string         `json:"execution"`
	Cleanup                 string         `json:"cleanup"`
	Verdict                 string         `json:"verdict"`
	Evaluation              Evaluation     `json:"evaluation"`
	Observations            ObserverReport `json:"observations"`
	Events                  []Event        `json:"events"`
	ExecutionAttestation    string         `json:"executionAttestation"`
	TrustedExecutionVerdict string         `json:"trustedExecutionVerdict"`
}

func Post(ctx context.Context, conn *Connection, route string, v any, nonce string, identity wire.Process) (wire.Reply, error) {
	var r wire.Reply
	req, e := http.NewRequestWithContext(ctx, "POST", conn.Base+route+"?nonce="+nonce, bytes.NewReader(wire.JSON(v)))
	if e != nil {
		return r, e
	}
	req.Header.Set("Content-Type", "application/json")
	resp, e := conn.Client.Do(req)
	if e != nil {
		return r, e
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, wire.MaxBody+1))
	if e != nil || len(b) > wire.MaxBody {
		return r, errors.New("bounded control response")
	}
	if e = wire.Decode(b, &r); e != nil {
		return r, e
	}
	kind := "control"
	if route == "/bind" {
		kind = "bind"
	}
	if !r.Verified(identity, nonce, kind) || r.Code != resp.StatusCode || r.Code != 200 {
		return r, wire.ErrDenied
	}
	return r, nil
}
func Control(ctx context.Context, conn *Connection, a wire.Authorization, action string) (wire.Reply, error) {
	return controlNonce(ctx, conn, a, action, "")
}

func controlNonce(ctx context.Context, conn *Connection, a wire.Authorization, action, nonce string) (wire.Reply, error) {
	cmd := wire.NewCommand(action, a, time.Now())
	if nonce != "" {
		cmd.Nonce = nonce
		cmd.Signature = ""
		cmd.Signature = wire.Sign(wire.CommandVersion, cmd, a.ApplyPrivate)
	}
	r, e := Post(ctx, conn, "/control", cmd, cmd.Nonce, a.Grant.Plan.Binding.Target.Proxy.Process)
	if e == nil && (r.PlanDigest != a.Grant.Digest || r.Action != action || r.State.Invocation != a.Grant.Invocation || r.State.ApplyCount > 1 || r.State.ApplyCount < 0 || r.State.DeadlineNS-r.State.StartedNS > int64(time.Duration(a.Grant.Plan.LifetimeMS)*time.Millisecond)) {
		e = wire.ErrDenied
	}
	if e == nil && action == "apply" && (!r.State.Applied || r.State.ApplyCount != 1) {
		e = wire.ErrDenied
	}
	return r, e
}
func readAuthorization(dir string) (wire.Authorization, error) {
	var a wire.Authorization
	e := localstate.Read(filepath.Join(dir, "authorization.json"), &a)
	if e != nil || wire.Public(a.ApplyPrivate) != a.Grant.ApplyKey || wire.Public(a.CleanupPrivate) != a.Grant.CleanupKey {
		return a, wire.ErrDenied
	}
	return a, nil
}
func gate(ctx context.Context, dir string) (*localstate.Lock, error) {
	l, e := localstate.OpenLock(filepath.Join(dir, "lifecycle.lock"), true)
	if e == nil {
		e = l.Acquire(ctx)
	}
	if e != nil && l != nil {
		_ = l.Close()
	}
	return l, e
}
func stopped(dir string) bool {
	_, e := os.Lstat(filepath.Join(dir, "cancel.json"))
	return !errors.Is(e, os.ErrNotExist)
}
func Run(ctx context.Context, state, dir, observations string) (Report, error) {
	return RunWithReadiness(ctx, state, dir, observations, "")
}

// RunWithReadiness keeps the original engine and authority unchanged. The new
// integration supplies a public signed-readiness commitment as its Apply nonce;
// the actuator authenticates and echoes that nonce under its existing protocol.
func RunWithReadiness(ctx context.Context, state, dir, observations, applyNonce string) (Report, error) {
	report := Report{Version: "themis.native-http-report/v1alpha1", Execution: "DENIED", Cleanup: "UNKNOWN", Verdict: "INCONCLUSIVE", Events: []Event{}, ExecutionAttestation: "NOT_INDEPENDENTLY_ATTESTED", TrustedExecutionVerdict: "INCONCLUSIVE"}
	if applyNonce != "" {
		decoded, err := hex.DecodeString(applyNonce)
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != applyNonce {
			return report, wire.ErrDenied
		}
	}
	a, e := readAuthorization(dir)
	if e != nil || !a.Grant.Valid(time.Now(), true) {
		return report, wire.ErrDenied
	}
	p := a.Grant.Plan
	report.Plan = p
	report.PlanDigest = p.Digest()
	report.Invocation = a.Grant.Invocation
	report.ApprovalDigest = wire.Hash(a.Grant)
	if e = localstate.WriteNew(filepath.Join(dir, "claim.json"), struct{ PlanDigest, Invocation string }{p.Digest(), a.Grant.Invocation}); e != nil {
		return report, wire.ErrDenied
	}
	journal, e := localstate.OpenNew(filepath.Join(dir, "events.jsonl"))
	if e != nil {
		return report, e
	}
	defer journal.Close()
	record := func(kind string, reply *wire.Reply) error {
		event := Event{Version: report.Version, Sequence: len(report.Events), PlanDigest: report.PlanDigest, Invocation: report.Invocation, Kind: kind, Reply: reply}
		if len(report.Events) > 0 {
			event.Previous = report.Events[len(report.Events)-1].Hash
		}
		event.Hash = wire.Hash(event)
		b := append(wire.JSON(event), '\n')
		if len(b) > 32<<10 || len(report.Events) >= 64 {
			return errors.New("execution journal bound")
		}
		n, e := journal.Write(b)
		if e == nil && n != len(b) {
			e = io.ErrShortWrite
		}
		if e == nil {
			e = journal.Sync()
		}
		if e == nil {
			report.Events = append(report.Events, event)
		}
		return e
	}
	if e = record("CLAIMED", nil); e != nil {
		return report, e
	}
	c, e := Open(ctx, state, "runner")
	if e != nil {
		return report, e
	}
	if c.Owner.Runner != p.Binding.Actor || c.Owner.RunnerUID != p.Binding.ActorUID || c.Owner.ApproverKey != p.Binding.ApproverKey || c.Owner.InstallerKey != p.Binding.InstallerKey {
		return report, wire.ErrDenied
	}
	if e = c.Check(ctx, p.Binding.Target); e != nil {
		return report, e
	}
	conn, e := c.Data("proxy")
	if e != nil {
		return report, e
	}
	defer conn.Close()
	// A separate observer must be ready; runner also makes fresh real preflight
	// requests so copied unsigned readiness cannot authorize an unhealthy baseline.
	var ready struct{ PlanDigest, Session string }
	if publicRead(filepath.Join(observations, "ready.json"), &ready) != nil || ready.PlanDigest != p.Digest() {
		return report, errors.New("independent observer not ready")
	}
	app, e := c.Data("application")
	if e != nil {
		return report, e
	}
	defer app.Close()
	for range 3 {
		nonce := wire.ID()
		start := time.Now()
		r, e := wire.Fetch(ctx, app.Client, app.Base+"/value?nonce="+nonce)
		if e != nil || !r.Verified(p.Binding.Target.Application.Process, nonce, "value") || r.Code != 200 || time.Since(start) > time.Duration(p.MaxApplicationMS)*time.Millisecond {
			return report, errors.New("fresh application baseline insufficient")
		}
	}
	g, e := gate(ctx, dir)
	if e != nil {
		return report, e
	}
	if stopped(dir) {
		_ = g.Close()
		report.Execution = "CANCELLED"
		return report, localstate.WriteNew(filepath.Join(dir, "report.json"), report)
	}
	if e = c.Check(ctx, p.Binding.Target); e != nil {
		_ = g.Close()
		return report, e
	}
	if e = record("APPLY_INTENT", nil); e != nil {
		_ = g.Close()
		return report, e
	}
	applied, applyError := controlNonce(ctx, conn, a, "apply", applyNonce)
	kind := "APPLIED"
	if applyError != nil {
		kind = "APPLY_UNCERTAIN"
	}
	if e = record(kind, &applied); e != nil {
		_ = g.Close()
		return report, e
	}
	_ = g.Close()
	// Neither observation nor storage participates in the actuator's timer.
	start := time.Now()
	cancelled := false
	for time.Since(start) < time.Duration(p.LifetimeMS+200)*time.Millisecond {
		if ctx.Err() != nil || stopped(dir) {
			cancelled = true
			break
		}
		select {
		case <-ctx.Done():
			cancelled = true
		case <-time.After(50 * time.Millisecond):
		}
		if cancelled {
			break
		}
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cleanupCancel()
	cleanupReply, cleanupError := Control(cleanupCtx, conn, a, "remove")
	report.Cleanup = "PENDING"
	report.Execution = "CLEANUP_PENDING"
	if cleanupError == nil && !cleanupReply.State.Active && cleanupReply.State.Fenced {
		report.Cleanup = "COMPLETE"
		report.Execution = "SUCCEEDED"
	}
	kind = "CLEANUP_PENDING"
	if report.Cleanup == "COMPLETE" {
		kind = "CLEANUP_CONFIRMED"
	}
	if e = record(kind, &cleanupReply); e != nil {
		return report, e
	}
	if cancelled {
		report.Execution = "CANCELLED"
	}
	var observed ObserverReport
	for wait := time.Now(); time.Since(wait) < 7*time.Second; {
		if publicRead(filepath.Join(observations, "observations.json"), &observed) == nil {
			break
		}
		if ctx.Err() != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	report.Evaluation = Evaluate(p, observed, a.Grant.Invocation, report.Cleanup == "COMPLETE")
	report.Observations = observed
	report.Verdict = report.Evaluation.Verdict
	identityConfirmed := c.Check(ctx, p.Binding.Target) == nil
	identityKind := "IDENTITY_CONFIRMED"
	if !identityConfirmed {
		identityKind = "IDENTITY_UNCERTAIN"
	}
	if e = record(identityKind, nil); e != nil {
		return report, e
	}
	if applyError != nil || cancelled || !identityConfirmed {
		report.Verdict = "INCONCLUSIVE"
	}
	if e = record("FINAL", nil); e != nil {
		return report, e
	}
	return report, localstate.WriteNew(filepath.Join(dir, "report.json"), report)
}

type Receipt struct {
	Version                  string      `json:"version"`
	PlanDigest               string      `json:"planDigest"`
	Invocation               string      `json:"invocation"`
	Cleanup                  string      `json:"cleanup"`
	Reply                    *wire.Reply `json:"reply,omitempty"`
	HistoricalBytesUnchanged bool        `json:"historicalBytesUnchanged"`
}

func Reconcile(ctx context.Context, state, dir string, cancelRun bool) (Receipt, error) {
	receipt := Receipt{Version: "themis.native-http-reconciliation/v1alpha1", Cleanup: "UNKNOWN", HistoricalBytesUnchanged: true}
	a, e := readAuthorization(dir)
	if e != nil || !a.Grant.Valid(time.Now(), false) {
		return receipt, wire.ErrDenied
	}
	receipt.PlanDigest = a.Grant.Digest
	receipt.Invocation = a.Grant.Invocation
	l, e := gate(ctx, dir)
	if e != nil {
		return receipt, e
	}
	defer l.Close()
	if cancelRun {
		if e = localstate.WriteNew(filepath.Join(dir, "cancel.json"), struct{ Invocation string }{a.Grant.Invocation}); e != nil && !errors.Is(e, os.ErrExist) {
			return receipt, e
		}
	}
	c, e := Open(ctx, state, "runner")
	if e != nil {
		return receipt, e
	}
	// Reconnection only to the exact original identity; replacement absence is not
	// inferred from a new proxy's response. No selector or fallback exists here.
	w, _, checkError := c.resolve(ctx, "proxy", a.Grant.Plan.Binding.Target.Proxy.Pod)
	if checkError != nil || w.Process != a.Grant.Plan.Binding.Target.Proxy.Process || w.ContainerID != a.Grant.Plan.Binding.Target.Proxy.ContainerID {
		e = wire.ErrDenied
		return receipt, e
	}
	conn, e := c.Data("proxy")
	if e != nil {
		return receipt, e
	}
	defer conn.Close()
	r, e := Control(ctx, conn, a, "remove")
	receipt.Reply = &r
	if e == nil && !r.State.Active && r.State.Fenced {
		receipt.Cleanup = "COMPLETE"
	} else {
		receipt.Cleanup = "PENDING"
	}
	writeError := localstate.WriteNew(filepath.Join(dir, "reconcile-"+wire.ID()+".json"), receipt)
	if writeError != nil {
		return receipt, writeError
	}
	return receipt, e
}
