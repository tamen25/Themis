// themis-chaosmesh exposes only non-mutating planning and closed admission.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/tamen25/themis/internal/chaosmesh"
	"github.com/tamen25/themis/internal/localstate"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, out, diagnostics io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(diagnostics, "usage: themis-chaosmesh plan | admit | provider; external execution disabled")
		return 4
	}
	f := flag.NewFlagSet("themis-chaosmesh "+args[0], flag.ContinueOnError)
	f.SetOutput(diagnostics)
	var state, approver, file, expected *string
	switch args[0] {
	case "plan":
		state = f.String("state", "", "original owned planning directory")
		approver = f.String("approver-public-key", "", "proposed separate external approver's public key; never an execution grant")
	case "admit":
		state = f.String("state", "", "optional original planning directory for fresh identity comparison")
		file = f.String("f", "", "versioned external plan JSON")
		expected = f.String("expect-digest", "", "exact reviewed external plan digest")
	case "provider":
	default:
		fmt.Fprintln(diagnostics, "unsupported operation; Chaos Mesh fault execution and approval issuance are disabled")
		return 4
	}
	if err := f.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 4
	}
	if f.NArg() != 0 {
		return 4
	}
	emit := func(v any) int {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		if encoder.Encode(v) != nil {
			return 6
		}
		return 0
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if args[0] == "provider" {
		return emit(struct {
			Version          string             `json:"version"`
			Provider         chaosmesh.Provider `json:"auditedArtifacts"`
			ExecutionAllowed bool               `json:"executionAllowed"`
		}{"themis.chaosmesh-provider-audit/v1alpha1", chaosmesh.PinnedProvider(), false})
	}
	if args[0] == "plan" {
		if *state == "" || *approver == "" {
			return 4
		}
		c, err := chaosmesh.Open(ctx, *state)
		if err != nil {
			fmt.Fprintln(diagnostics, "owned planning environment denied or unavailable")
			return 5
		}
		snapshot, err := c.Resolve(ctx)
		if err != nil {
			fmt.Fprintln(diagnostics, "independent request/preview/target resolution denied")
			return 5
		}
		p, err := chaosmesh.Compile(snapshot, localstate.RandomID(), *approver, time.Now())
		if err != nil {
			fmt.Fprintln(diagnostics, "external plan validation denied")
			return 5
		}
		return emit(p)
	}
	if *file == "" || *expected == "" {
		return 4
	}
	input, err := os.Open(*file)
	if err != nil {
		fmt.Fprintln(diagnostics, "external plan unavailable")
		return 6
	}
	defer input.Close()
	data, err := io.ReadAll(io.LimitReader(input, (1<<20)+1))
	if err != nil {
		return 6
	}
	p, err := chaosmesh.Decode(data)
	decision := chaosmesh.Admit(p, *expected, time.Now())
	if err != nil {
		decision.Reasons = append(decision.Reasons, "UnsupportedOrInvalidExternalFormat")
	}
	if *state != "" && err == nil {
		c, openErr := chaosmesh.Open(ctx, *state)
		if openErr != nil || c.Revalidate(ctx, p) != nil {
			decision.Reasons = append(decision.Reasons, "FreshIdentityDeniedOrUnavailable")
		}
	}
	if code := emit(decision); code != 0 {
		return code
	}
	return 5
}
