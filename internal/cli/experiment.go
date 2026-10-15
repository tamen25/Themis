package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/tamen25/themis/internal/contract"
	"github.com/tamen25/themis/internal/experiment"
	"github.com/tamen25/themis/internal/fixture"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/plan"
	"github.com/tamen25/themis/internal/result"
	"github.com/tamen25/themis/internal/safety"
)

const experimentalUsage = `Experimental owned local fixtures only:
  themis fixture start --directory <new-private-directory> --name demo [--mode healthy|buggy|noop-adapter|cleanup-denied] [--ttl 2m]
  themis fixture status|stop --directory <fixture-directory>
  themis experiment validate -f examples/owned-latency/experiment.yaml
  themis experiment plan -f <contract> --fixture <fixture-directory>
  themis experiment authorize -f <contract> --fixture <fixture-directory> --approve sha256:...
  themis experiment run -f <contract> --fixture <fixture-directory> --authorization <private-record> [--runs-dir .themis/experiments]
  themis experiment replay -f <events.jsonl>
  themis experiment status --run <run-directory> [--output text|json]
  themis experiment cancel --run <run-directory> [--output text|json]
  themis experiment cleanup --run <run-directory>
`

func experimental(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		return report(stderr, ExitInvalidConfig, errors.New(experimentalUsage))
	}
	if args[1] == "--help" || args[1] == "-h" {
		if _, err := io.WriteString(stdout, experimentalUsage); err != nil {
			return report(stderr, ExitInfrastructure, err)
		}
		return ExitOK
	}
	if args[0] == "fixture" {
		return fixtureCommand(ctx, args[1:], stdout, stderr)
	}
	command := args[1]
	flags := flag.NewFlagSet("experiment "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var file, fixtureDir, approval, authorization, runsDir, runDir string
	output := "json"
	if command == "status" {
		output = "text"
	}
	source := "local"
	switch command {
	case "validate", "plan", "authorize", "run", "replay":
		flags.StringVar(&file, "f", "", "contract or journal file")
	case "cleanup", "cancel", "status":
		flags.StringVar(&runDir, "run", "", "run directory")
	default:
		return report(stderr, ExitInvalidConfig, errors.New("unknown experiment command"))
	}
	if command == "run" || command == "replay" || command == "status" || command == "cancel" || command == "cleanup" {
		flags.StringVar(&output, "output", output, "text or json")
	}
	if command == "replay" {
		flags.StringVar(&source, "provenance", "local", "local or imported")
	}
	if command == "plan" || command == "authorize" || command == "run" {
		flags.StringVar(&fixtureDir, "fixture", "", "owned fixture directory")
	}
	if command == "authorize" {
		flags.StringVar(&approval, "approve", "", "fresh explicit approval of the resolved plan digest")
	}
	if command == "run" {
		flags.StringVar(&authorization, "authorization", "", "private authorization record")
		flags.StringVar(&runsDir, "runs-dir", "", "run directory root")
	}
	if err := flags.Parse(args[2:]); err != nil {
		return report(stderr, ExitInvalidConfig, err)
	}
	if flags.NArg() != 0 {
		return report(stderr, ExitInvalidConfig, errors.New("unexpected positional arguments"))
	}
	if output != "text" && output != "json" {
		return report(stderr, ExitInvalidConfig, errors.New("unsupported output format"))
	}
	if source != "local" && source != "imported" {
		return report(stderr, ExitInvalidConfig, errors.New("unsupported provenance source"))
	}
	if command == "cleanup" || command == "cancel" || command == "status" {
		if runDir == "" {
			return report(stderr, ExitInvalidConfig, errors.New("--run required"))
		}
		if command == "status" {
			r, err := experiment.Inspect(ctx, runDir)
			if err != nil {
				return report(stderr, ExitAdmission, err)
			}
			if err := renderStatus(stdout, r, output); err != nil {
				return report(stderr, ExitInfrastructure, err)
			}
			if r.ReconciliationNecessary {
				return 7
			}
			return ExitOK
		}
		var r experiment.CleanupResult
		var err error
		if command == "cancel" {
			r, err = experiment.Cancel(ctx, runDir)
		} else {
			r, err = experiment.ReconcileContext(ctx, runDir)
		}
		if err != nil {
			if r.RunID != "" {
				_ = renderCleanup(stdout, r, output)
			}
			return report(stderr, 7, err)
		}
		if err := renderCleanup(stdout, r, output); err != nil {
			return report(stderr, ExitInfrastructure, err)
		}
		if !r.Completed {
			return 7
		}
		return ExitOK
	}
	if file == "" {
		return report(stderr, ExitInvalidConfig, errors.New("-f required"))
	}
	if command == "replay" {
		if source == "imported" {
			f, err := os.Open(file)
			if err != nil {
				return report(stderr, ExitInfrastructure, err)
			}
			defer f.Close()
			r, err := experiment.ReplayImported(f)
			if err != nil {
				return report(stderr, ExitInfrastructure, err)
			}
			if output == "json" {
				if err := encode(stdout, r); err != nil {
					return report(stderr, ExitInfrastructure, err)
				}
			} else {
				if err := renderExperimentText(stdout, r.RecordedReport, r.Provenance); err != nil {
					return report(stderr, ExitInfrastructure, err)
				}
			}
			return experimentExit(r.RecordedReport)
		}
		r, err := experiment.ReplayFile(file)
		if err != nil {
			return report(stderr, ExitInfrastructure, err)
		}
		return renderExperimentOutput(stdout, stderr, r, output)
	}
	f, err := os.Open(file)
	if err != nil {
		return report(stderr, ExitInfrastructure, err)
	}
	c, parseErr := contract.ParseExperiment(f)
	closeErr := f.Close()
	if parseErr != nil {
		return report(stderr, ExitInvalidConfig, parseErr)
	}
	if closeErr != nil {
		return report(stderr, ExitInfrastructure, closeErr)
	}
	if command == "validate" {
		if err := encode(stdout, struct {
			Digest string `json:"contractDigest"`
		}{c.Digest()}); err != nil {
			return report(stderr, ExitInfrastructure, err)
		}
		return ExitOK
	}
	if fixtureDir == "" {
		return report(stderr, ExitInvalidConfig, errors.New("--fixture required"))
	}
	client, err := fixture.Open(fixtureDir)
	if err != nil {
		return report(stderr, ExitAdmission, err)
	}
	defer client.Close()
	id, err := client.Resolve(ctx)
	if err != nil {
		return report(stderr, ExitAdmission, err)
	}
	p, err := plan.CompileExperiment(c, id)
	if err != nil {
		return report(stderr, ExitInvalidConfig, err)
	}
	if command == "plan" {
		var value json.RawMessage = p.JSON()
		if err := encode(stdout, value); err != nil {
			return report(stderr, ExitInfrastructure, err)
		}
		return ExitOK
	}
	if command == "authorize" {
		a, err := client.Authorize(ctx, p, approval)
		if err != nil {
			return report(stderr, ExitAdmission, err)
		}
		path := filepath.Join(fixtureDir, "authorization-"+a.ID+".json")
		if err := localstate.WriteNew(path, a); err != nil {
			return report(stderr, ExitInfrastructure, err)
		}
		if err := encode(stdout, struct {
			Path    string    `json:"authorizationFile"`
			Digest  string    `json:"planDigest"`
			Expires time.Time `json:"expiresAt"`
		}{path, p.Digest(), a.ExpiresAt}); err != nil {
			return report(stderr, ExitInfrastructure, err)
		}
		return ExitOK
	}
	if authorization == "" {
		return report(stderr, ExitAdmission, errors.New("--authorization required; T0 approval cannot authorize faults"))
	}
	var a safety.Authorization
	if err := localstate.Read(authorization, &a); err != nil {
		return report(stderr, ExitAdmission, err)
	}
	r, dir, err := experiment.Execute(ctx, p, a, fixtureDir, runsDir)
	if err != nil {
		code := ExitInfrastructure
		if errors.Is(err, safety.ErrDenied) {
			code = ExitAdmission
		}
		if r.RunID != "" {
			_ = renderExperimentOutput(stdout, stderr, r, output)
			if r.Execution.Status == result.CleanupPending {
				code = 7
			}
		}
		return report(stderr, code, fmt.Errorf("%w (run directory: %s)", err, dir))
	}
	return renderExperimentOutput(stdout, stderr, r, output)
}

func fixtureCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("fixture", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dir := flags.String("directory", "", "private fixture directory")
	name := flags.String("name", "demo", "fixture name")
	mode := flags.String("mode", "healthy", "synthetic demo behavior")
	ttl := flags.Duration("ttl", 2*time.Minute, "independent fixture lifetime")
	if err := flags.Parse(args[1:]); err != nil {
		return report(stderr, ExitInvalidConfig, err)
	}
	if flags.NArg() != 0 || *dir == "" {
		return report(stderr, ExitInvalidConfig, errors.New("--directory required and no positional arguments allowed"))
	}
	if args[0] == "start" {
		exe, err := os.Executable()
		if err != nil {
			return report(stderr, ExitInfrastructure, err)
		}
		id, err := fixture.Start(ctx, exe, *dir, *name, *mode, *ttl)
		if err != nil {
			return report(stderr, ExitInfrastructure, err)
		}
		if err := encode(stdout, id); err != nil {
			return report(stderr, ExitInfrastructure, err)
		}
		return ExitOK
	}
	if args[0] != "status" && args[0] != "stop" {
		return report(stderr, ExitInvalidConfig, errors.New("unknown fixture command"))
	}
	c, err := fixture.Open(*dir)
	if err != nil {
		return report(stderr, ExitAdmission, err)
	}
	defer c.Close()
	if args[0] == "status" {
		s, err := c.Status(ctx)
		if err != nil {
			return report(stderr, ExitInfrastructure, err)
		}
		if err := encode(stdout, s); err != nil {
			return report(stderr, ExitInfrastructure, err)
		}
		return ExitOK
	}
	if err := c.Stop(ctx); err != nil {
		return report(stderr, 7, err)
	}
	deadline, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if c.ListenersClosed(deadline) {
			if err := encode(stdout, struct {
				Stopped bool `json:"stopped"`
			}{true}); err != nil {
				return report(stderr, ExitInfrastructure, err)
			}
			return ExitOK
		}
		select {
		case <-deadline.Done():
			return report(stderr, 7, errors.New("fixture listeners remain unresolved"))
		case <-ticker.C:
		}
	}
}

func encode(w io.Writer, value any) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(value)
}
func renderExperiment(stdout, stderr io.Writer, r experiment.Report) int {
	return renderExperimentOutput(stdout, stderr, r, "json")
}
func renderExperimentOutput(stdout, stderr io.Writer, r experiment.Report, output string) int {
	var err error
	if output == "text" {
		err = renderExperimentText(stdout, r, r.Provenance)
	} else {
		err = encode(stdout, r)
	}
	if err != nil {
		return report(stderr, ExitInfrastructure, err)
	}
	return experimentExit(r)
}
func experimentExit(r experiment.Report) int {
	if r.Execution.Status == result.CleanupPending {
		return 7
	}
	if r.Verdict == result.Fail {
		return ExitFail
	}
	if r.Execution.Status == result.Error {
		return ExitInfrastructure
	}
	if r.Verdict == result.Pass {
		return ExitOK
	}
	return ExitInconclusive
}
