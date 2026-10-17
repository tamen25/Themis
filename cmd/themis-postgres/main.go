// themis-postgres runs only Themis-owned disposable local PostgreSQL recovery tests.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/tamen25/themis/internal/postgres"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(execute(ctx, os.Args[1:]))
}
func execute(ctx context.Context, args []string) int {
	if len(args) > 0 && args[0] == "durable" {
		return executeDurable(ctx, args[1:])
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: themis-postgres setup|plan|approve|run|reconcile|replay")
		return 2
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	dir := f.String("state", "", "original private experiment directory")
	endpoint := f.String("endpoint", "", "explicit local Docker socket (setup only)")
	engine := f.String("engine-id", "", "expected local Docker engine ID (setup only)")
	contract := f.String("contract", "", "versioned recovery contract (plan only)")
	expected := f.String("expect-digest", "", "reviewed plan digest (approve only)")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 || *dir == "" {
		return 2
	}
	var v any
	var err error
	code := 0
	switch args[0] {
	case "setup":
		v, err = postgres.Setup(ctx, *dir, *endpoint, *engine)
	case "plan":
		var c postgres.Contract
		c, err = postgres.ReadContract(*contract)
		if err == nil {
			v, err = postgres.PlanFile(*dir, c)
		}
	case "approve":
		var g postgres.Grant
		g, err = postgres.Approve(*dir, *expected)
		v = map[string]any{"plan": g.Plan, "startBefore": g.StartBefore, "executeBefore": g.ExecuteBefore, "authorization": "retained only in private state"}
	case "reconcile":
		var r postgres.CleanupReceipt
		r, err = postgres.Reconcile(ctx, *dir)
		v = r
		if !r.Complete {
			code = 7
		}
	case "run":
		var r postgres.Report
		r, err = postgres.Run(ctx, *dir)
		v = r
		code = postgres.ExitCode(r)
	case "replay":
		v, err = postgres.Replay(*dir)
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
