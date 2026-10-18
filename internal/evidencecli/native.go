package evidencecli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"time"

	adapter "github.com/tamen25/themis/internal/dependencyexperiment"
	wire "github.com/tamen25/themis/internal/dependencyhttp"
	"github.com/tamen25/themis/internal/evidencesource"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/pkg/evidence"
	obs "github.com/tamen25/themis/pkg/nativeobservation"
)

// Read only fixed PUBLIC files. Never open authorization.json, a kubeconfig,
// ownership inventory, witness private key or any actuator control capability.
func exportNative(dir, session, reconciliationPath string) (map[string][]byte, error) {
	files := map[string][]byte{}
	paths := map[string]string{
		filepath.Join(dir, "plan.json"):              "artifacts/native-plan.json",
		filepath.Join(dir, "public-approval.json"):   "artifacts/native-approval-reference.json",
		filepath.Join(dir, "witness-admission.json"): "artifacts/native-witness-admission.json",
		filepath.Join(session, "registration.json"):  "artifacts/native-witness-registration.json",
	}
	root, e := os.Lstat(dir)
	if e != nil || !root.IsDir() || root.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("native public export requires original real directory")
	}
	for path, name := range paths {
		b, e := stableNativeRead(path, obs.MaxRecord)
		if e != nil {
			return nil, e
		}
		var value any
		switch name {
		case "artifacts/native-plan.json":
			value = &wire.Plan{}
		case "artifacts/native-approval-reference.json":
			value = &obs.ApprovalReference{}
		case "artifacts/native-witness-admission.json":
			value = &obs.Admission{}
		case "artifacts/native-witness-registration.json":
			value = &obs.Registration{}
		}
		if localstate.Unmarshal(b, value) != nil {
			return nil, errors.New("invalid public native projection")
		}
		files[name] = wire.JSON(value)
	}
	journal, e := stableNativeRead(filepath.Join(dir, "events.jsonl"), obs.MaxJournal)
	if e != nil {
		return nil, e
	}
	files["artifacts/native-runner-journal.json"], e = obs.EncodeJournal(journal)
	if e != nil {
		return nil, e
	}
	journal, e = stableNativeRead(filepath.Join(session, "observations.jsonl"), obs.MaxJournal)
	if e != nil {
		return nil, e
	}
	files["artifacts/native-witness-journal.json"], e = obs.EncodeJournal(journal)
	if e != nil {
		return nil, e
	}
	result := evidencesource.NativeResult{Version: evidencesource.NativeResultVersion}
	reportPath := filepath.Join(dir, "report.json")
	if _, e := os.Lstat(reportPath); e == nil {
		b, e := stableNativeRead(reportPath, evidence.MaxFile)
		if e != nil {
			return nil, e
		}
		var r adapter.Report
		if localstate.Unmarshal(b, &r) != nil {
			return nil, errors.New("invalid native original report")
		}
		result.Report = &r
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	files["artifacts/native-result.json"] = wire.JSON(result)
	var intent obs.RunnerStatement
	intentBytes, e := stableNativeRead(filepath.Join(dir, "runner-intent.json"), obs.MaxRecord)
	if e != nil || localstate.Unmarshal(intentBytes, &intent) != nil {
		return nil, errors.New("original runner signed intent unavailable")
	}
	statements := evidencesource.NativeRunnerStatements{Version: obs.RunnerStatementVersion, Intent: intent}
	finalPath := filepath.Join(dir, "runner-final.json")
	if _, e := os.Lstat(finalPath); e == nil {
		raw, e := stableNativeRead(finalPath, obs.MaxRecord)
		if e != nil {
			return nil, e
		}
		var final obs.RunnerStatement
		if localstate.Unmarshal(raw, &final) != nil {
			return nil, errors.New("invalid original runner final assertion")
		}
		statements.Final = &final
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	files["artifacts/native-runner-statements.json"] = wire.JSON(statements)
	reconciliation := evidencesource.NativeReconciliation{Version: evidencesource.NativeReconciliationVersion, Receipts: []adapter.Receipt{}}
	if reconciliationPath != "" {
		b, e := stableNativeRead(reconciliationPath, obs.MaxRecord)
		if e != nil {
			return nil, e
		}
		var r adapter.Receipt
		if localstate.Unmarshal(b, &r) != nil {
			return nil, errors.New("invalid public reconciliation receipt")
		}
		reconciliation.Receipts = append(reconciliation.Receipts, r)
	}
	files["artifacts/native-reconciliation.json"] = wire.JSON(reconciliation)
	// Canonical public projection preserves all original report fields and raw
	// journal bytes. Ordinary private-file JSON formatting is not a signature.
	for name, b := range files {
		if e := evidence.CheckPublicArtifact(name, b); e != nil {
			return nil, e
		}
	}
	return files, nil
}
func stableNativeRead(path string, limit int64) ([]byte, error) {
	before, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	b, e := readFile(path, limit)
	if e != nil {
		return nil, e
	}
	after, e := os.Lstat(path)
	if e != nil || !os.SameFile(before, after) || before.ModTime() != after.ModTime() || before.Size() != after.Size() {
		return nil, errors.New("native public source changed during read")
	}
	again, e := readFile(path, limit)
	last, f := os.Lstat(path)
	if e != nil || f != nil || !bytes.Equal(b, again) || !os.SameFile(after, last) || after.ModTime() != last.ModTime() {
		return nil, errors.New("native public snapshot changed")
	}
	return b, nil
}
func nativeFinding(o evidence.Opened, path string, now time.Time) (obs.Finding, error) {
	var policy *obs.Policy
	if path != "" {
		b, e := readFile(path, 128<<10)
		if e != nil {
			return obs.NewFinding(), e
		}
		p, e := obs.ReadPolicy(b)
		if e != nil {
			return obs.NewFinding(), e
		}
		policy = &p
	}
	return evidencesource.CorroborateNative(o, policy, now), nil
}
func nativeExit(o evidence.Opened, f obs.Finding) int {
	if o.Result.PublisherTrust != "TRUSTED" {
		return 5
	}
	// An unknown mapping cannot evaluate a witness identity. Preserve the
	// unsupported format disposition instead of calling that identity untrusted.
	if o.Result.SourceChecks.Status == "UNSUPPORTED" || f.Status == "UNSUPPORTED_SOURCE" {
		return 7
	}
	if f.WitnessTrust != "TRUSTED" || f.Status == "WITNESS_IDENTITY_UNTRUSTED" {
		return 5
	}
	if f.Status == "WITNESS_SIGNATURE_INVALID" || f.Status == "OBSERVATIONS_CONTRADICTORY" {
		return 9
	}
	if o.Result.SourceChecks.Status == "FAILED" {
		return 6
	}
	if o.Result.SourceChecks.Status != "PASSED" || f.Status != "OBSERVATIONS_CORROBORATED" {
		return 8
	}
	return 0
}
