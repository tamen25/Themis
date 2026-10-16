// themis-kube is the owned Kind experiment runner. It has no Kubernetes
// provisioning command; the separate reviewed setup script installs workloads.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/tamen25/themis/internal/kubeexperiment"
	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func readPlan(path string) (kubefault.Plan, error) {
	f, err := os.Open(path)
	if err != nil {
		return kubefault.Plan{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil {
		return kubefault.Plan{}, err
	}
	var envelope struct {
		Digest string         `json:"digest"`
		Plan   kubefault.Plan `json:"plan"`
	}
	if err = kubefault.Decode(data, &envelope); err != nil {
		return envelope.Plan, err
	}
	if envelope.Digest != envelope.Plan.Digest() {
		return envelope.Plan, kubefault.ErrDenied
	}
	return envelope.Plan, envelope.Plan.Validate()
}

func run(parent context.Context, args []string, out, diagnostics io.Writer) int {
	if len(args) > 0 && args[0] == "coordinate" {
		return runCoordination(parent, args[1:], out, diagnostics)
	}
	if len(args) == 0 {
		fmt.Fprintln(diagnostics, "usage: themis-kube init | plan | approve | run | cancel | status | reconcile | replay | verify | coordinate")
		return 4
	}
	command := args[0]
	f := flag.NewFlagSet("themis-kube "+command, flag.ContinueOnError)
	f.SetOutput(diagnostics)
	state := f.String("state", ".themis/kind-t21", "explicit owned Kind private state")
	var file, runName, scenario, approved, output, authorization, directory *string
	var expectedDigest *string
	switch command {
	case "init":
	case "plan":
		runName = f.String("run", "latency-request", "exact VerificationRun name")
		scenario = f.String("scenario", "healthy", "approved synthetic scenario")
	case "approve":
		file = f.String("f", "", "complete versioned plan")
		approved = f.String("approve-digest", "", "explicit exact plan digest")
		output = f.String("out", "", "private authorization file")
	case "run":
		file = f.String("f", "", "complete versioned plan")
		authorization = f.String("authorization", "", "private authorization file")
		directory = f.String("runs", "", "private output parent")
	case "status", "reconcile", "cancel":
		directory = f.String("run-directory", "", "existing private run directory")
	case "replay", "verify":
		file = f.String("f", "", "public append-only event journal")
		if command == "verify" {
			expectedDigest = f.String("expect-plan-digest", "", "independently retained plan digest")
		}
	default:
		fmt.Fprintln(diagnostics, "unsupported owned Kind command")
		return 4
	}
	if err := f.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 4
	}
	if f.NArg() != 0 {
		return 4
	}
	emit := func(value any) int {
		e := json.NewEncoder(out)
		e.SetIndent("", "  ")
		if e.Encode(value) != nil {
			return 6
		}
		return 0
	}
	fail := func(err error) int {
		if errors.Is(err, kubefault.ErrDenied) {
			fmt.Fprintln(diagnostics, "owned Kind admission denied")
			return 5
		}
		fmt.Fprintln(diagnostics, "owned Kind operation failed; inspect private state and public journal")
		return 6
	}
	if command == "init" {
		if _, err := os.Stat(*state); errors.Is(err, os.ErrNotExist) {
			if _, err = localstate.CreateDirectory(*state); err != nil {
				return fail(err)
			}
		} else if err = localstate.Check(*state); err != nil {
			return fail(err)
		}
		public, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fail(err)
		}
		if err = localstate.WriteNew(filepath.Join(*state, "approver-key.json"), struct {
			Key string `json:"privateKey"`
		}{hex.EncodeToString(key)}); err != nil {
			return fail(err)
		}
		return emit(struct {
			Key string `json:"approverKey"`
		}{hex.EncodeToString(public)})
	}
	if command == "replay" {
		if *file == "" {
			return 4
		}
		r, err := kubeexperiment.Replay(*file)
		if err != nil {
			return fail(err)
		}
		if code := emit(r); code != 0 {
			return code
		}
		return reportExit(r)
	}
	if command == "verify" {
		if *file == "" {
			return 4
		}
		r, err := kubeexperiment.VerifyEvidence(*file, *expectedDigest)
		if err != nil {
			if code := emit(r); code != 0 {
				return code
			}
			return fail(err)
		}
		if code := emit(r); code != 0 {
			return code
		}
		if !r.BindingsValid {
			return 6
		}
		if r.CredibleSignedFailure {
			return 2
		}
		return 3
	}
	if (command == "approve" && (*file == "" || *approved == "" || *output == "")) || (command == "run" && (*file == "" || *authorization == "")) || ((command == "status" || command == "reconcile" || command == "cancel") && *directory == "") {
		return 4
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	var c *kubeexperiment.Cluster
	var err error
	if command == "status" || command == "reconcile" || command == "cancel" {
		explicitState := ""
		f.Visit(func(v *flag.Flag) {
			if v.Name == "state" {
				explicitState = *state
			}
		})
		c, err = kubeexperiment.OpenRun(ctx, *directory, explicitState)
	} else {
		c, err = kubeexperiment.Open(ctx, *state)
	}
	if err != nil {
		if command == "cancel" || command == "reconcile" {
			if code := emit(map[string]any{"version": "themis.kubernetes-cleanup-receipt/v1alpha2", "operationalState": "CLEANUP_PENDING", "currentState": "UNKNOWN", "actionAccepted": false, "failure": "ProtectedInventoryOrAdmissionUnavailable"}); code != 0 {
				return code
			}
			return 7
		}
		return fail(err)
	}
	switch command {
	case "plan":
		p, err := c.Plan(ctx, *runName, *scenario)
		if err != nil {
			return fail(err)
		}
		return emit(struct {
			Digest string         `json:"digest"`
			Plan   kubefault.Plan `json:"plan"`
		}{p.Digest(), p})
	case "approve":
		p, err := readPlan(*file)
		if err != nil {
			return fail(err)
		}
		a, err := c.Approve(ctx, p, *approved)
		if err != nil {
			return fail(err)
		}
		if err = localstate.WriteNew(*output, a); err != nil {
			return fail(err)
		}
		return emit(map[string]any{"invocationID": a.Grant.InvocationID, "planDigest": a.Grant.PlanDigest, "applyBefore": a.Grant.ApplyBefore, "cleanupBefore": a.Grant.CleanupBefore})
	case "run":
		p, err := readPlan(*file)
		if err != nil {
			return fail(err)
		}
		var a kubefault.Authorization
		if err = localstate.Read(*authorization, &a); err != nil {
			return fail(err)
		}
		if *directory == "" {
			*directory = filepath.Join(*state, "runs")
		}
		r, dir, err := c.Execute(ctx, p, a, *directory)
		if r.Version == "" {
			return fail(err)
		}
		if code := emit(struct {
			Directory string                `json:"directory"`
			Report    kubeexperiment.Report `json:"report"`
		}{dir, r}); code != 0 {
			return code
		}
		if err != nil && r.Execution != result.CleanupPending {
			return fail(err)
		}
		return reportExit(r)
	case "status":
		r, err := c.Inspect(ctx, *directory)
		if err != nil {
			return fail(err)
		}
		return emit(r)
	case "reconcile", "cancel":
		var r kubeexperiment.CleanupReceipt
		if command == "cancel" {
			r, err = c.Cancel(ctx, *directory)
		} else {
			r, err = c.Reconcile(ctx, *directory)
		}
		if err != nil && !errors.Is(err, kubeexperiment.ErrReceiptPublication) {
			if code := emit(map[string]any{"version": "themis.kubernetes-cleanup-receipt/v1alpha2", "operationalState": "CLEANUP_PENDING", "currentState": "UNKNOWN", "actionAccepted": false, "failure": "ActionAcceptanceOrCoordinationUnavailable"}); code != 0 {
				return code
			}
			return 7
		}
		if code := emit(r); code != 0 {
			return code
		}
		if err != nil || r.OperationalState != "CLEANUP_COMPLETE" {
			return 7
		}
		return 0
	}
	return 4
}

func reportExit(r kubeexperiment.Report) int {
	if r.Execution == result.CleanupPending {
		return 7
	}
	if r.Verdict == result.Fail {
		return 2
	}
	if r.Verdict == result.Pass && r.Execution == result.Succeeded {
		return 0
	}
	if r.Execution == result.Error {
		return 6
	}
	return 3
}
