package livewitness

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"time"

	"github.com/tamen25/themis/internal/kubeexperiment"
	obs "github.com/tamen25/themis/pkg/liveobservation"
)

func Run(ctx context.Context, args []string, output io.Writer) int {
	emit := func(v any) bool { return json.NewEncoder(output).Encode(v) == nil }
	fail := func(message string, code int) int {
		emit(struct {
			Version string `json:"version"`
			Error   string `json:"error"`
		}{obs.Version, message})
		return code
	}
	if len(args) == 0 {
		return fail("use keygen, register, observe or inspect", 2)
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var keyDir, witness, record, session, digest, runnerID, cleanupID, state, trust string
	maxApp := 150
	switch args[0] {
	case "keygen":
		flags.StringVar(&keyDir, "key-dir", "", "new protected dedicated key directory")
		flags.StringVar(&witness, "witness", "", "operator provisioned witness name")
	case "register":
		flags.StringVar(&keyDir, "key-dir", "", "dedicated protected witness key")
		flags.StringVar(&record, "record", "", "public unused approved coordination record")
		flags.StringVar(&session, "session", "", "new exclusive session directory")
		flags.StringVar(&digest, "approve-digest", "", "explicit exact execution plan digest")
		flags.StringVar(&runnerID, "runner-key-id", "", "SHA256 of public invocation key")
		flags.StringVar(&cleanupID, "cleanup-key-id", "", "SHA256 of public cleanup key")
		flags.IntVar(&maxApp, "max-application-ms", 150, "approved application latency ceiling")
	case "observe":
		flags.StringVar(&keyDir, "key-dir", "", "dedicated protected key")
		flags.StringVar(&session, "session", "", "registered session")
		flags.StringVar(&state, "state", "", "dedicated witness credentials and installer ownership")
	case "inspect":
		flags.StringVar(&session, "session", "", "existing session, never resumed")
		flags.StringVar(&trust, "witness-policy", "", "independent exact-scope witness trust")
	default:
		return fail("unsupported witness command", 2)
	}
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return fail("invalid witness arguments", 2)
	}
	switch args[0] {
	case "keygen":
		if keyDir == "" || witness == "" {
			return fail("key-dir and witness required", 2)
		}
		identity, e := Keygen(keyDir, witness)
		if e != nil {
			return fail("witness protected key provisioning failed", 3)
		}
		if !emit(identity) {
			return 3
		}
		return 0
	case "register":
		if keyDir == "" || session == "" || record == "" || digest == "" || runnerID == "" || cleanupID == "" {
			return fail("explicit public experiment, key identities, session and digest approval required", 2)
		}
		b, e := readPublic(record, 1<<20)
		if e != nil {
			return fail("public registration record unavailable", 3)
		}
		r, e := kubeexperiment.DecodeCoordinationRecord(b)
		if e != nil {
			return fail("invalid public experiment", 6)
		}
		reg, e := Register(r, keyDir, session, digest, runnerID, cleanupID, maxApp, time.Now())
		if e != nil {
			return fail("unused exact experiment or witness registration denied", 6)
		}
		if !emit(reg) {
			return 3
		}
		return 0
	case "observe":
		if keyDir == "" || state == "" || session == "" {
			return fail("key-dir, witness state and session required", 2)
		}
		f, e := Observe(ctx, state, session, keyDir)
		if e != nil {
			return fail("witness observation failed; signed prefix may remain incomplete", 3)
		}
		if !emit(f) {
			return 3
		}
		if !f.Complete {
			return 8
		}
		return 0
	case "inspect":
		if session == "" {
			return fail("session required", 2)
		}
		var policy *obs.Policy
		if trust != "" {
			b, e := readPublic(trust, 128<<10)
			if e != nil {
				return fail("external witness policy unavailable", 5)
			}
			p, e := obs.ReadPolicy(b)
			if e != nil {
				return fail("invalid external witness policy", 5)
			}
			policy = &p
		}
		f, e := Inspect(session, policy, time.Now())
		if e != nil {
			return fail("witness session unavailable", 3)
		}
		if !emit(f) {
			return 3
		}
		return 0
	}
	return 2
}
func readPublic(path string, limit int64) ([]byte, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, os.ErrInvalid
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit+1))
}
