package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/tamen25/themis/internal/postgres"
)

func executePITR(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: themis-postgres pitr setup|plan|approve-prepare|prepare|approve-failure|run|reconcile|replay")
		return 2
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	dir := f.String("state", "", "original private pitr experiment directory")
	endpoint := f.String("endpoint", "", "explicit local Docker socket (setup only)")
	engine := f.String("engine-id", "", "expected local Docker engine (setup only)")
	contract := f.String("contract", "", "pitr contract (plan only)")
	expected := f.String("expect-digest", "", "reviewed pitr plan digest")

	if f.Parse(args[1:]) != nil || f.NArg() != 0 || *dir == "" {
		return 2
	}
	var v any
	var err error
	code := 0
	switch args[0] {
	case "setup":
		v, err = postgres.SetupPITR(ctx, *dir, *endpoint, *engine)
	case "plan":
		var c postgres.PITRContract
		c, err = postgres.ReadPITRContract(*contract)
		if err == nil {
			v, err = postgres.PlanPITRFile(*dir, c)
		}
	case "approve-prepare", "approve-failure":
		var g postgres.PITRGrant
		if args[0] == "approve-prepare" {
			g, err = postgres.ApprovePITR(*dir, *expected, "prepare")
		} else {
			g, err = postgres.ApprovePITR(*dir, *expected, "sigkill-physical-target-once")
		}
		v = map[string]any{"plan": g.Plan, "scope": g.Scope, "executionPlan": g.Prepared, "startBefore": g.StartBefore, "executeBefore": g.ExecuteBefore, "authorization": "retained only in private state"}
	case "prepare":
		v, err = postgres.PreparePITR(ctx, *dir)
	case "run":
		var r postgres.PITRReport
		r, err = postgres.RunPITR(ctx, *dir)
		v = r
		code = postgres.PITRExitCode(r)
	case "reconcile":
		var r postgres.CleanupReceipt
		r, err = postgres.ReconcilePITR(ctx, *dir)
		v = r
		if !r.Complete {
			code = 7
		}
	case "replay":
		v, err = postgres.ReplayPITR(*dir)
		code = 4
	default:
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err = json.NewEncoder(os.Stdout).Encode(v); err != nil {
		return 2
	}
	return code
}
