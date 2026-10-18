package dependencyexperiment

import (
	"context"
	"flag"
	"io"
	"path/filepath"
	"time"

	wire "github.com/tamen25/themis/internal/dependencyhttp"
	"github.com/tamen25/themis/internal/localstate"
)

type Keys struct {
	Version          string `json:"version"`
	InstallerPrivate string `json:"installerPrivate"`
	ApproverPrivate  string `json:"approverPrivate"`
}

func CLI(ctx context.Context, args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		return 2
	}
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(errOut)
	state := flags.String("state", "", "explicit protected actor state")
	directory := flags.String("directory", "", "new plan/run directory")
	keys := flags.String("keys", "", "installer-owned approval key directory")
	digest := flags.String("approve-digest", "", "exact independently approved plan digest")
	observations := flags.String("observations", "", "separate observer output directory")
	planFile := flags.String("plan", "", "public immutable plan")
	scenario := flags.String("scenario", "delay", "delay, no-effect, cleanup-unconfirmed")
	ceiling := flags.Int("max-application-ms", 500, "inclusive application ceiling")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return 2
	}
	emit := func(v any, code int) int {
		b := append(wire.JSON(v), '\n')
		n, e := out.Write(b)
		if e != nil || n != len(b) {
			return 3
		}
		return code
	}
	denied := func() int {
		return emit(struct {
			Error string `json:"error"`
		}{"native dependency operation denied or incomplete; inspect protected state"}, 5)
	}
	switch command {
	case "init":
		dir, e := localstate.CreateDirectory(*state)
		if e != nil {
			return denied()
		}
		ip, ik, e := wire.NewKey()
		if e != nil {
			return denied()
		}
		ap, ak, e := wire.NewKey()
		if e != nil {
			return denied()
		}
		if localstate.WriteNew(filepath.Join(dir, "keys.json"), Keys{"themis.native-http-keys/v1alpha1", ik, ak}) != nil {
			return denied()
		}
		return emit(struct{ InstallerKey, ApproverKey string }{ip, ap}, 0)
	case "bind":
		c, e := Open(ctx, *state, "installer")
		if e != nil {
			return denied()
		}
		target, e := c.Resolve(ctx)
		if e != nil {
			return denied()
		}
		var k Keys
		if localstate.Read(filepath.Join(*keys, "keys.json"), &k) != nil || k.Version != "themis.native-http-keys/v1alpha1" || wire.Public(k.InstallerPrivate) != c.Owner.InstallerKey || wire.Public(k.ApproverPrivate) != c.Owner.ApproverKey {
			return denied()
		}
		b := wire.Binding{Version: wire.BindingVersion, Target: target, Actor: c.Owner.Runner, ActorUID: c.Owner.RunnerUID, ApproverKey: c.Owner.ApproverKey, InstallerKey: c.Owner.InstallerKey}
		b.Signature = wire.Sign(wire.BindingVersion, b, k.InstallerPrivate)
		if !b.Valid() {
			return denied()
		}
		conn, e := c.Forward(ctx, target.Proxy.Pod)
		if e != nil {
			return denied()
		}
		defer conn.Close()
		if _, e = Post(ctx, conn, "/bind", b, wire.ID(), target.Proxy.Process); e != nil {
			return denied()
		}
		return emit(b, 0)
	case "plan":
		c, e := Open(ctx, *state, "runner")
		if e != nil {
			return denied()
		}
		var b wire.Binding
		if localstate.Read(filepath.Join(*state, "binding.json"), &b) != nil || !b.Valid() || c.Check(ctx, b.Target) != nil {
			return denied()
		}
		p := wire.Plan{Version: wire.PlanVersion, Run: wire.ID(), Binding: b, DelayMS: 150, LifetimeMS: 1500, RequestMS: wire.RequestMS, MaxApplicationMS: *ceiling, Scenario: *scenario}
		if !p.Valid() {
			return denied()
		}
		dir, e := localstate.CreateDirectory(*directory)
		if e != nil || localstate.WriteNew(filepath.Join(dir, "plan.json"), p) != nil {
			return denied()
		}
		return emit(struct {
			Plan   wire.Plan `json:"plan"`
			Digest string    `json:"digest"`
		}{p, p.Digest()}, 0)
	case "approve":
		var p wire.Plan
		var k Keys
		if localstate.Read(filepath.Join(*directory, "plan.json"), &p) != nil || localstate.Read(filepath.Join(*keys, "keys.json"), &k) != nil || k.Version != "themis.native-http-keys/v1alpha1" {
			return denied()
		}
		a, e := wire.Approve(p, *digest, k.ApproverPrivate, time.Now())
		if e != nil || localstate.WriteNew(filepath.Join(*directory, "authorization.json"), a) != nil {
			return denied()
		}
		return emit(struct{ PlanDigest, Invocation, ApprovalDigest string }{a.Grant.Digest, a.Grant.Invocation, wire.Hash(a.Grant)}, 0)
	case "observe":
		var p wire.Plan
		if publicRead(*planFile, &p) != nil {
			return denied()
		}
		r, e := Observe(ctx, *state, p, *observations)
		if e != nil {
			return denied()
		}
		code := 0
		if !r.Complete {
			code = 8
		}
		return emit(r, code)
	case "run":
		r, e := Run(ctx, *state, *directory, *observations)
		if e != nil {
			return emit(r, 6)
		}
		code := 0
		if r.Verdict == "FAIL" {
			code = 4
		} else if r.Verdict != "PASS" {
			code = 8
		}
		if r.Cleanup == "PENDING" {
			code = 7
		}
		if r.Execution == "CANCELLED" {
			code = 9
		}
		return emit(r, code)
	case "cancel", "reconcile":
		r, e := Reconcile(ctx, *state, *directory, command == "cancel")
		code := 0
		if e != nil || r.Cleanup != "COMPLETE" {
			code = 7
		}
		return emit(r, code)
	case "inspect":
		a, e := readAuthorization(*directory)
		if e != nil || !a.Grant.Valid(time.Now(), false) {
			return denied()
		}
		c, e := Open(ctx, *state, "runner")
		if e != nil {
			return denied()
		}
		target := a.Grant.Plan.Binding.Target
		w, _, e := c.resolve(ctx, "proxy", target.Proxy.Pod)
		if e != nil || w.Process != target.Proxy.Process || w.ContainerID != target.Proxy.ContainerID {
			return denied()
		}
		conn, e := c.Data("proxy")
		if e != nil {
			return denied()
		}
		defer conn.Close()
		r, e := Control(ctx, conn, a, "status")
		if e != nil {
			return denied()
		}
		return emit(r, 0)
	case "replay":
		var r Report
		if publicRead(*planFile, &r) != nil || r.Version != "themis.native-http-report/v1alpha1" || !r.Plan.Valid() || r.PlanDigest != r.Plan.Digest() {
			return denied()
		}
		candidate, e := Replay(r)
		if e != nil {
			return denied()
		}
		r.ExecutionAttestation = "NOT_INDEPENDENTLY_ATTESTED"
		r.TrustedExecutionVerdict = "INCONCLUSIVE"
		return emit(struct {
			Version                 string     `json:"version"`
			Candidate               Evaluation `json:"candidate"`
			ExecutionAttestation    string     `json:"executionAttestation"`
			TrustedExecutionVerdict string     `json:"trustedExecutionVerdict"`
			Limitations             []string   `json:"limitations"`
		}{"themis.native-http-replay/v1alpha1", candidate, r.ExecutionAttestation, r.TrustedExecutionVerdict, []string{"Original client timing and phase placement are unsigned claims.", "Full authorization/witness/evidence bundle integration is deferred to T4.3."}}, 8)
	default:
		return 2
	}
}
