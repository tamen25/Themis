package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/tamen25/themis/internal/postgres"
)

func executeDurable(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: themis-postgres durable setup|plan|approve-prepare|prepare|approve-failure|run|reconcile|replay")
		return 2
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	dir := f.String("state", "", "original private durable experiment directory")
	endpoint := f.String("endpoint", "", "explicit local Docker socket (setup only)")
	engine := f.String("engine-id", "", "expected local Docker engine (setup only)")
	contract := f.String("contract", "", "durable contract (plan only)")
	expected := f.String("expect-digest", "", "reviewed durable plan digest")
	backup := f.String("expect-backup-sha256", "", "reviewed published backup content digest (approve-failure only)")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 || *dir == "" {
		return 2
	}
	var v any
	var err error
	code := 0
	switch args[0] {
	case "setup":
		v, err = postgres.SetupDurable(ctx, *dir, *endpoint, *engine)
	case "plan":
		var c postgres.DurableContract
		c, err = postgres.ReadDurableContract(*contract)
		if err == nil {
			v, err = postgres.PlanDurableFile(*dir, c)
		}
	case "approve-prepare", "approve-failure":
		var g postgres.DurableGrant
		if args[0] == "approve-prepare" {
			g, err = postgres.ApprovePreparation(*dir, *expected)
		} else {
			g, err = postgres.ApproveFailure(*dir, *expected, *backup)
		}
		v = map[string]any{"plan": g.Plan, "scope": g.Scope, "backupSha256": g.BackupSHA256, "startBefore": g.StartBefore, "executeBefore": g.ExecuteBefore, "authorization": "retained only in private state"}
	case "prepare":
		v, err = postgres.PrepareDurable(ctx, *dir)
	case "run":
		var r postgres.DurableReport
		r, err = postgres.RunDurable(ctx, *dir)
		v = r
		code = postgres.DurableExitCode(r)
	case "reconcile":
		var r postgres.CleanupReceipt
		r, err = postgres.ReconcileDurable(ctx, *dir)
		v = r
		if !r.Complete {
			code = 7
		}
	case "replay":
		v, err = postgres.ReplayDurable(*dir)
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
