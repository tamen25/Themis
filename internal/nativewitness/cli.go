package nativewitness

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"time"

	"github.com/tamen25/themis/pkg/evidence"
	obs "github.com/tamen25/themis/pkg/nativeobservation"
)

// ReadPublic opens only the caller's explicit path, never artifact-supplied paths.
func ReadPublic(path string, limit int64, out any) error {
	info, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return os.ErrInvalid
	}
	file, e := os.Open(path)
	if e != nil {
		return e
	}
	defer file.Close()
	b, e := io.ReadAll(io.LimitReader(file, limit+1))
	if e != nil {
		return e
	}
	if int64(len(b)) > limit {
		return os.ErrInvalid
	}
	return evidence.Decode(b, out)
}
func CLI(ctx context.Context, args []string, out io.Writer) int {
	emit := func(v any, code int) int {
		if json.NewEncoder(out).Encode(v) != nil {
			return 3
		}
		return code
	}
	deny := func() int {
		return emit(struct{ Version, Error string }{obs.Version, "native witness input denied or observation incomplete; inspect the retained signed prefix"}, 6)
	}
	if len(args) == 0 {
		return 2
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	keyDir := flags.String("key-dir", "", "dedicated protected witness key")
	witness := flags.String("witness", "", "explicit witness name")
	approval := flags.String("approval", "", "public signed approval reference")
	session := flags.String("session", "", "new/existing exclusive witness session")
	digest := flags.String("approve-digest", "", "exact approved native plan digest")
	state := flags.String("state", "", "dedicated read-only witness principal")
	trust := flags.String("witness-policy", "", "external exact-scope policy")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return 2
	}
	switch args[0] {
	case "keygen":
		if *keyDir == "" || *witness == "" {
			return 2
		}
		r, e := Keygen(*keyDir, *witness)
		if e != nil {
			return deny()
		}
		return emit(r, 0)
	case "register":
		if *keyDir == "" || *session == "" || *approval == "" || *digest == "" {
			return 2
		}
		var ref obs.ApprovalReference
		if ReadPublic(*approval, obs.MaxRecord, &ref) != nil {
			return deny()
		}
		r, e := Register(ref, *keyDir, *session, *digest, time.Now())
		if e != nil {
			return deny()
		}
		return emit(r, 0)
	case "observe":
		if *keyDir == "" || *state == "" || *session == "" {
			return 2
		}
		f, e := Observe(ctx, *state, *session, *keyDir)
		if e != nil {
			return deny()
		}
		code := 0
		if !f.Complete {
			code = 8
		}
		return emit(f, code)
	case "inspect":
		if *session == "" {
			return 2
		}
		var p *obs.Policy
		pub := evidence.Publisher{}
		if *trust != "" {
			var policy obs.Policy
			if ReadPublic(*trust, 128<<10, &policy) != nil || policy.Validate() != nil {
				return deny()
			}
			p = &policy
			if len(policy.Keys) == 1 {
				pub.Name = policy.Keys[0].Publisher
				pub.KeyID = policy.Keys[0].PublisherKeyID
			}
		}
		f, e := Inspect(*session, p, pub, time.Now())
		if e != nil {
			return deny()
		}
		return emit(f, 0)
	default:
		return 2
	}
}
