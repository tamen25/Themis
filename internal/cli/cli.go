// Package cli adapts command-line arguments and streams to the domain packages.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/tamen25/themis/internal/contract"
	"github.com/tamen25/themis/internal/plan"
	"github.com/tamen25/themis/internal/result"
	localrun "github.com/tamen25/themis/internal/run"
)

const (
	ExitOK             = 0
	ExitFail           = 2
	ExitInconclusive   = 3
	ExitInvalidConfig  = 4
	ExitAdmission      = 5
	ExitInfrastructure = 6
)

const usage = `Usage:
  themis version
  themis contract validate -f contract.yaml
  themis plan -f contract.yaml --output json
  themis run -f contract.yaml [--runs-dir .themis/runs] [--approve-plan sha256:...] [--output text|json]
  themis replay -f .themis/runs/run-.../events.jsonl [--output text|json]

Run sends bounded GET probes to the declared literal loopback endpoint.
T0 plans and offline replay send no requests. T0 run does not support faults.
Use "themis experiment --help" for experimental owned local fault experiments.
`

// Run returns an exit code. Business logic never terminates the process.
func Run(args []string, stdout, stderr io.Writer, version string) int {
	return RunContext(context.Background(), args, stdout, stderr, version)
}

// RunContext propagates process cancellation to an active observation run.
func RunContext(ctx context.Context, args []string, stdout, stderr io.Writer, version string) int {
	if len(args) == 0 || (len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h")) {
		if _, err := io.WriteString(stdout, usage); err != nil {
			return report(stderr, ExitInfrastructure, err)
		}
		if len(args) == 0 {
			return ExitInvalidConfig
		}
		return ExitOK
	}
	if args[0] == "version" {
		if len(args) != 1 {
			return report(stderr, ExitInvalidConfig, errors.New("version accepts no arguments"))
		}
		if _, err := fmt.Fprintf(stdout, "themis %s\n", version); err != nil {
			return report(stderr, ExitInfrastructure, err)
		}
		return ExitOK
	}
	if args[0] == "fixture" || args[0] == "experiment" {
		return experimental(ctx, args, stdout, stderr)
	}
	var command string
	var remaining []string
	switch {
	case args[0] == "plan" || args[0] == "run" || args[0] == "replay":
		command, remaining = args[0], args[1:]
	case len(args) >= 2 && args[0] == "contract" && args[1] == "validate":
		command, remaining = "contract validate", args[2:]
	default:
		return report(stderr, ExitInvalidConfig, errors.New("unknown command; use themis --help"))
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	file := flags.String("f", "", "contract file")
	var output string
	var runsDir, approval string
	if command == "plan" {
		flags.StringVar(&output, "output", "json", "output format (json)")
	}
	if command == "run" || command == "replay" {
		flags.StringVar(&output, "output", "text", "output format (text or json)")
	}
	if command == "run" {
		flags.StringVar(&runsDir, "runs-dir", "", "directory for new run journals and reports")
		flags.StringVar(&approval, "approve-plan", "", "explicitly approved plan digest")
	}
	if err := flags.Parse(remaining); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, err := io.WriteString(stdout, usage); err != nil {
				return report(stderr, ExitInfrastructure, err)
			}
			return ExitOK
		}
		return report(stderr, ExitInvalidConfig, err)
	}
	if flags.NArg() != 0 || *file == "" {
		return report(stderr, ExitInvalidConfig, errors.New("expected -f <contract file> and no positional arguments"))
	}
	if command == "plan" && output != "json" {
		return report(stderr, ExitInvalidConfig, fmt.Errorf("unsupported output %q; supported: json", output))
	}
	if (command == "run" || command == "replay") && output != "text" && output != "json" {
		return report(stderr, ExitInvalidConfig, fmt.Errorf("unsupported output %q; supported: text, json", output))
	}
	if command == "replay" {
		r, err := localrun.ReplayFile(*file)
		if err != nil {
			return report(stderr, ExitInfrastructure, err)
		}
		return renderRun(stdout, stderr, r, output)
	}
	f, err := os.Open(*file)
	if err != nil {
		return report(stderr, ExitInfrastructure, fmt.Errorf("open contract: %w", err))
	}
	c, parseErr := contract.Parse(f)
	closeErr := f.Close()
	if parseErr != nil {
		code := ExitInvalidConfig
		if errors.Is(parseErr, contract.ErrRead) || errors.Is(parseErr, contract.ErrSchema) {
			code = ExitInfrastructure
		}
		return report(stderr, code, parseErr)
	}
	if closeErr != nil {
		return report(stderr, ExitInfrastructure, fmt.Errorf("close contract: %w", closeErr))
	}
	if command == "run" {
		r, dir, err := localrun.Execute(ctx, c, localrun.Options{Directory: runsDir, ApprovedPlanDigest: approval})
		if err != nil {
			code := ExitInfrastructure
			if errors.Is(err, localrun.ErrAdmission) {
				code = ExitAdmission
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				code = ExitInconclusive
			}
			if dir != "" {
				err = fmt.Errorf("%w (partial journal: %s)", err, filepath.Join(dir, "events.jsonl"))
			}
			return report(stderr, code, err)
		}
		return renderRun(stdout, stderr, r, output)
	}
	if command == "contract validate" {
		if _, err := fmt.Fprintf(stdout, "VALID %s %s\n", c.Snapshot().Metadata.Name, c.Digest()); err != nil {
			return report(stderr, ExitInfrastructure, err)
		}
		return ExitOK
	}
	p, err := plan.Compile(c)
	if err != nil {
		return report(stderr, ExitInvalidConfig, err)
	}
	var formatted bytes.Buffer
	if err := json.Indent(&formatted, p.JSON(), "", "  "); err != nil {
		return report(stderr, ExitInfrastructure, fmt.Errorf("format plan: %w", err))
	}
	formatted.WriteByte('\n')
	if _, err := stdout.Write(formatted.Bytes()); err != nil {
		return report(stderr, ExitInfrastructure, err)
	}
	return ExitOK
}

func report(stderr io.Writer, code int, err error) int {
	// Contract keys, paths and parser diagnostics may contain terminal controls.
	fmt.Fprintf(stderr, "themis: %s\n", strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return '\uFFFD'
		}
		return r
	}, err.Error()))
	return code
}

func renderRun(stdout, stderr io.Writer, r localrun.Report, output string) int {
	var err error
	if output == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(r)
	} else {
		var b strings.Builder
		fmt.Fprintf(&b, "Contract: %s\nRun:      %s\nSamples:  %d\nCoverage: %s\n\n", r.ContractName, r.RunID, r.Samples, strings.ToLower(string(r.Coverage)))
		for _, a := range r.Assertions {
			label := a.ID
			if a.ID == "readiness" {
				label = "Readiness"
			}
			if a.ID == "error-rate" {
				label = "Error rate"
			}
			fmt.Fprintf(&b, "%s: %s\n", label, a.Verdict)
		}
		fmt.Fprintf(&b, "\nVerdict: %s\n", r.Verdict)
		_, err = io.WriteString(stdout, b.String())
	}
	if err != nil {
		return report(stderr, ExitInfrastructure, err)
	}
	if r.Execution.Status == result.Error {
		return ExitInfrastructure
	}
	if r.Execution.Status != result.Succeeded {
		return ExitInconclusive
	}
	switch r.Verdict {
	case result.Pass:
		return ExitOK
	case result.Fail:
		return ExitFail
	default:
		return ExitInconclusive
	}
}
