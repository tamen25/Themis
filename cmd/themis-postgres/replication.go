package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/tamen25/themis/internal/postgres"
)

func executeReplication(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: themis-postgres replication setup|plan|approve-prepare|prepare|approve-termination|approve-promotion|run|reconcile|replay")
		return 2
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	dir := f.String("state", "", "original private replication experiment directory")
	endpoint := f.String("endpoint", "", "explicit local Docker socket (setup only)")
	engine := f.String("engine-id", "", "expected local Docker engine (setup only)")
	contract := f.String("contract", "", "replication contract (plan only)")
	expected := f.String("expect-digest", "", "reviewed replication plan digest")

	if f.Parse(args[1:]) != nil || f.NArg() != 0 || *dir == "" {
		return 2
	}
	var v any
	var err error
	code := 0
	switch args[0] {
	case "setup":
		v, err = postgres.SetupReplication(ctx, *dir, *endpoint, *engine)
	case "plan":
		var c postgres.ReplicationContract
		c, err = postgres.ReadReplicationContract(*contract)
		if err == nil {
			v, err = postgres.PlanReplicationFile(*dir, c)
		}
	case "approve-prepare", "approve-termination", "approve-promotion":
		var g postgres.ReplicationGrant
		if args[0] == "approve-prepare" {
			g, err = postgres.ApproveReplication(*dir, *expected, "prepare")
		} else if args[0] == "approve-promotion" {
			g, err = postgres.ApproveReplication(*dir, *expected, "promote-fenced-standby")
		} else {
			g, err = postgres.ApproveReplication(*dir, *expected, "terminate-and-fence")
		}
		v = map[string]any{"plan": g.Plan, "scope": g.Scope, "executionPlan": g.Prepared, "startBefore": g.StartBefore, "executeBefore": g.ExecuteBefore, "authorization": "retained only in private state"}
	case "prepare":
		v, err = postgres.PrepareReplication(ctx, *dir)
	case "run":
		var r postgres.ReplicationReport
		r, err = postgres.RunReplication(ctx, *dir)
		v = r
		code = postgres.ReplicationExitCode(r)
	case "reconcile":
		var r postgres.CleanupReceipt
		r, err = postgres.ReconcileReplication(ctx, *dir)
		v = r
		if !r.Complete {
			code = 7
		}
	case "replay":
		v, err = postgres.ReplayReplication(*dir)
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
