// Package nativeexecution binds the existing native runner to public live
// readiness. It never opens a witness or publisher private key.
package nativeexecution

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"

	adapter "github.com/tamen25/themis/internal/dependencyexperiment"
	wire "github.com/tamen25/themis/internal/dependencyhttp"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/nativewitness"
	"github.com/tamen25/themis/pkg/evidence"
	obs "github.com/tamen25/themis/pkg/nativeobservation"
)

func Approve(dir, keys, digest string, now time.Time) (obs.ApprovalReference, error) {
	var k adapter.Keys
	var p wire.Plan
	if localstate.Read(filepath.Join(keys, "keys.json"), &k) != nil || localstate.Read(filepath.Join(dir, "plan.json"), &p) != nil || k.Version != "themis.native-http-keys/v1alpha1" {
		return obs.ApprovalReference{}, wire.ErrDenied
	}
	if _, e := os.Lstat(filepath.Join(dir, "claim.json")); !errors.Is(e, os.ErrNotExist) {
		return obs.ApprovalReference{}, wire.ErrDenied
	}
	a, e := wire.Approve(p, digest, k.ApproverPrivate, now)
	if e != nil {
		return obs.ApprovalReference{}, e
	}
	ref, e := obs.PublicApproval(a.Grant, k.ApproverPrivate)
	if e != nil {
		return ref, e
	}
	// The existing approval issuer creates and privately delivers capabilities to
	// the runner. Neither witness nor publisher ever reads this operational file.
	if e = localstate.WriteNew(filepath.Join(dir, "authorization.json"), a); e != nil {
		return ref, e
	}
	return ref, localstate.WriteNew(filepath.Join(dir, "public-approval.json"), ref)
}
func Admit(dir, session, policyPath string, now time.Time) (obs.Admission, error) {
	var admission obs.Admission
	var ref obs.ApprovalReference
	var a wire.Authorization
	reg, e := nativewitness.ReadRegistration(session)
	if e != nil {
		return admission, e
	}
	begin, _ := obs.UTC(reg.NotBefore)
	end, _ := obs.UTC(reg.NotAfter)
	if now.Before(begin) || !now.Before(end) {
		return admission, wire.ErrDenied
	}
	if localstate.Read(filepath.Join(dir, "authorization.json"), &a) != nil || !a.Grant.Valid(now, true) || localstate.Read(filepath.Join(dir, "public-approval.json"), &ref) != nil || ref.Validate() != nil || !reflect.DeepEqual(ref, reg.Approval) || ref.ApprovalDigest != wire.Hash(a.Grant) {
		return admission, wire.ErrDenied
	}
	var policy obs.Policy
	if nativewitness.ReadPublic(policyPath, 128<<10, &policy) != nil || policy.Validate() != nil {
		return admission, wire.ErrDenied
	}
	trusted := false
	for _, k := range policy.Keys {
		if obs.Trusted(reg, &policy, evidence.Publisher{Name: k.Publisher, KeyID: k.PublisherKeyID}, now) {
			trusted = true
		}
	}
	if !trusted {
		return admission, wire.ErrDenied
	}
	path := filepath.Join(session, "observations.jsonl")
	if localstate.Check(path) != nil {
		return admission, wire.ErrDenied
	}
	file, e := os.Open(path)
	if e != nil {
		return admission, e
	}
	defer file.Close()
	raw, e := io.ReadAll(io.LimitReader(file, obs.MaxJournal+1))
	if e != nil {
		return admission, e
	}
	f, records := obs.Analyze(reg, raw, nil, evidence.Publisher{}, now)
	if f.SignatureChain != "VALID" || f.Baseline < 3 || f.Active != 0 || f.IdentityCorrelation != "MATCHED" {
		return admission, wire.ErrDenied
	}
	var ready obs.Record
	if localstate.Read(filepath.Join(session, "ready.json"), &ready) != nil || ready.Type != "READY" || !obs.VerifyRecord(ready, reg.PublicKey) {
		return admission, wire.ErrDenied
	}
	found := false
	for _, record := range records {
		if record.Hash == ready.Hash && reflect.DeepEqual(record, ready) {
			found = true
		}
		if record.Type == "END" || record.Type == "INTERRUPTED" {
			return admission, wire.ErrDenied
		}
	}
	if !found {
		return admission, wire.ErrDenied
	}
	admission = obs.NewAdmission(reg, ready)
	intent := obs.RunnerStatement{Version: obs.RunnerStatementVersion, Kind: "INTENT", Key: a.Grant.ApplyKey, PlanDigest: ref.PlanDigest, Invocation: ref.Invocation, ApprovalDigest: ref.ApprovalDigest, ReadyCommitment: admission.ApplyNonce, Execution: "INTENT", Candidate: "INCONCLUSIVE", Cleanup: "UNKNOWN"}
	intent = obs.SignRunner(intent, a.ApplyPrivate)
	if intent.Validate(ref) != nil {
		return admission, wire.ErrDenied
	}
	if e = localstate.WriteNew(filepath.Join(dir, "runner-intent.json"), intent); e != nil {
		return admission, e
	}
	admission = obs.BindIntent(admission, intent)
	return admission, localstate.WriteNew(filepath.Join(dir, "witness-admission.json"), admission)
}

func finalizeStatement(dir string, r adapter.Report) error {
	var a wire.Authorization
	var intent obs.RunnerStatement
	var ref obs.ApprovalReference
	if localstate.Read(filepath.Join(dir, "authorization.json"), &a) != nil || localstate.Read(filepath.Join(dir, "public-approval.json"), &ref) != nil || localstate.Read(filepath.Join(dir, "runner-intent.json"), &intent) != nil || intent.Validate(ref) != nil || wire.Public(a.ApplyPrivate) != intent.Key || wire.Hash(a.Grant) != ref.ApprovalDigest {
		return wire.ErrDenied
	}
	file, e := os.Open(filepath.Join(dir, "events.jsonl"))
	if e != nil {
		return e
	}
	defer file.Close()
	raw, e := io.ReadAll(io.LimitReader(file, obs.MaxJournal+1))
	if e != nil || len(raw) > obs.MaxJournal {
		return errors.New("native final journal bound")
	}
	statement := obs.RunnerStatement{Version: obs.RunnerStatementVersion, Kind: "FINAL", Key: intent.Key, PlanDigest: ref.PlanDigest, Invocation: ref.Invocation, ApprovalDigest: ref.ApprovalDigest, ReadyCommitment: intent.ReadyCommitment, IntentDigest: wire.Hash(intent), JournalDigest: evidence.Hash(raw), ReportDigest: evidence.Hash(wire.JSON(r)), Execution: r.Execution, Candidate: r.Verdict, Cleanup: r.Cleanup}
	statement = obs.SignRunner(statement, a.ApplyPrivate)
	if statement.Validate(ref) != nil {
		return wire.ErrDenied
	}
	return localstate.WriteNew(filepath.Join(dir, "runner-final.json"), statement)
}
func CLI(ctx context.Context, args []string, out io.Writer) int {
	if len(args) == 0 {
		return 2
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dir := flags.String("directory", "", "exact protected native run")
	keys := flags.String("keys", "", "approver key directory (approve-witnessed only)")
	digest := flags.String("approve-digest", "", "exact explicitly approved plan digest")
	state := flags.String("state", "", "existing runner principal")
	observations := flags.String("observations", "", "original separate unsigned observer")
	session := flags.String("witness-session", "", "live registered witness")
	policy := flags.String("witness-policy", "", "explicit external exact-scope witness trust")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return 2
	}
	emit := func(v any, code int) int {
		if json.NewEncoder(out).Encode(v) != nil {
			return 3
		}
		return code
	}
	denied := func() int {
		return emit(struct {
			Error string `json:"error"`
		}{"public native approval or live readiness denied"}, 5)
	}
	if *dir == "" {
		return 2
	}
	switch args[0] {
	case "approve-witnessed":
		if *keys == "" || *digest == "" {
			return 2
		}
		ref, e := Approve(*dir, *keys, *digest, time.Now())
		if e != nil {
			return denied()
		}
		return emit(ref, 0)
	case "run-witnessed":
		if *state == "" || *observations == "" || *session == "" || *policy == "" {
			return 2
		}
		admission, e := Admit(*dir, *session, *policy, time.Now())
		if e != nil {
			return denied()
		}
		r, e := adapter.RunWithReadiness(ctx, *state, *dir, *observations, admission.ApplyNonce)
		if e != nil {
			return emit(r, 6)
		}
		if e = finalizeStatement(*dir, r); e != nil {
			return emit(r, 3)
		}
		code := 0
		if r.Verdict == "FAIL" {
			code = 4
		} else if r.Verdict != "PASS" {
			code = 8
		}
		if r.Cleanup == "PENDING" {
			code = 7
		}
		if r.Execution == "CANCELLED" {
			code = 9
		}
		return emit(r, code)
	default:
		return 2
	}
}
