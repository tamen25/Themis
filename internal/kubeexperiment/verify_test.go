package kubeexperiment

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/result"
)

func copyEvents(events []Event) []Event {
	data, _ := json.Marshal(events)
	var copy []Event
	_ = json.Unmarshal(data, &copy)
	return copy
}

func rehashedJournal(t *testing.T, events []Event) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	previous := ""
	for i := range events {
		events[i].Sequence, events[i].Previous, events[i].Hash = i, previous, ""
		events[i].Hash = kubefault.Digest(events[i].Version, events[i])
		previous = events[i].Hash
		if err = json.NewEncoder(f).Encode(events[i]); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestOfflineVerificationRejectsRehashedForgeries(t *testing.T) {
	events, _ := measuredEvents(t, "healthy")
	for _, mutation := range []string{"clean", "unsigned timing rewrite", "forged application", "wrong invocation", "changed target", "duplicate observation", "phase transition", "unexpected status", "wrong run", "changed plan digest", "foreign control nonce"} {
		t.Run(mutation, func(t *testing.T) {
			copy := copyEvents(events)
			observation := 0
			for i, e := range copy {
				if e.Observation != nil {
					observation = i
					break
				}
			}
			switch mutation {
			case "unsigned timing rewrite":
				for i := range copy {
					if copy[i].Observation != nil {
						o := copy[i].Observation
						for j := range o.Probes {
							o.Probes[j].StartedNS = 0
							o.Probes[j].CompletedNS = 1
						}
						if o.Phase == "intervention" {
							o.Probes[1].CompletedNS = 200000001
						}
					}
				}
			case "forged application":
				copy[observation].Observation.Probes[2].Response.HTTPCode = 503
			case "wrong invocation":
				copy[0].Authorization.InvocationID = kubefault.RandomID()
			case "changed target":
				copy[0].Plan.Target.Fixture.InstanceID = kubefault.RandomID()
				copy[0].Authorization.PlanDigest = copy[0].Plan.Digest()
			case "duplicate observation":
				copy = append(copy[:observation+1], append([]Event{copy[observation]}, copy[observation+1:]...)...)
			case "phase transition":
				copy[1].Type = "RECOVERY"
			case "unexpected status":
				for _, event := range copy {
					if event.Status != nil {
						copy[1].Status = event.Status
						break
					}
				}
			case "wrong run":
				copy[0].Plan.RunUID = "99999999-9999-9999-9999-999999999999"
			case "changed plan digest":
				copy[0].Authorization.PlanDigest = "sha256:" + kubefault.RandomID()
			case "foreign control nonce":
				for i := range copy {
					if copy[i].Status != nil {
						copy[i].Status.Proof.Nonce = kubefault.RandomID()
						break
					}
				}
			}
			path := rehashedJournal(t, copy)
			verified, err := VerifyEvidence(path, events[0].Plan.Digest())
			if err != nil {
				if mutation == "clean" || mutation == "unsigned timing rewrite" {
					t.Fatal(err)
				}
				return
			}
			if verified.TrustedExecutionVerdict == result.Pass {
				t.Fatal("rehashed unsigned journal manufactured trusted PASS")
			}
			if mutation == "clean" || mutation == "unsigned timing rewrite" {
				if !verified.BindingsValid || verified.CandidateVerdict != result.Pass || verified.VerifiedDataSignatures != 27 {
					t.Fatal("valid measured candidate lost", verified.Problems, verified.CandidateVerdict)
				}
			} else if verified.BindingsValid {
				t.Fatal("forged binding accepted", mutation)
			}
		})
	}
}

func TestEmbeddedKeyIsNotIndependentExecutionTrust(t *testing.T) {
	events, _ := measuredEvents(t, "healthy")
	originalDigest := events[0].Plan.Digest()
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	events[0].Plan.Target.Fixture.EvidenceKey = hex.EncodeToString(public)
	id := events[0].Plan.Target.Fixture
	events[0].Authorization.PlanDigest = events[0].Plan.Digest()
	for i := range events {
		if o := events[i].Observation; o != nil {
			for j := range o.Probes {
				d := o.Probes[j].Response
				if d != nil {
					d.Identity = id
					d.Signature = ""
					d.Signature = kubefault.Sign("themis.kubernetes-data/v1alpha1", *d, key)
				}
			}
		}
		if s := events[i].Status; s != nil {
			proof := s.Proof
			s.Proof = nil
			reply := kubefault.Reply{Identity: id, Nonce: proof.Nonce, HTTPCode: 200, Status: *s}
			proof.Signature = kubefault.Sign("themis.kubernetes-reply/v1alpha1", reply, key)
			s.Proof = proof
		}
	}
	path := rehashedJournal(t, events)
	r, err := VerifyEvidence(path, "")
	if err != nil || !r.BindingsValid || r.CandidateVerdict != result.Pass || r.TrustedExecutionVerdict != result.Inconclusive {
		t.Fatal("embedded key substituted for execution attestation", err, r.Problems)
	}
	anchored, err := VerifyEvidence(path, originalDigest)
	if err != nil || anchored.BindingsValid || anchored.ExpectedDigestMatched == nil || *anchored.ExpectedDigestMatched {
		t.Fatal("retained external digest failed to reject key substitution", err)
	}
}

func TestVerificationDistinguishesIncompleteCoverageAndSignedFailure(t *testing.T) {
	for _, mode := range []string{"healthy", "buggy"} {
		events, _ := measuredEvents(t, mode)
		partial := []Event{}
		for _, e := range events {
			if e.Type == "FINAL" || e.Observation != nil && e.Observation.Phase == "intervention" && e.Observation.Index > 0 {
				continue
			}
			partial = append(partial, e)
		}
		r, err := VerifyEvidence(rehashedJournal(t, partial), "")
		if err != nil || !r.BindingsValid || r.JournalComplete || r.TrustedExecutionVerdict == result.Pass {
			t.Fatal("incomplete history was trusted", err, r.Problems)
		}
		if mode == "buggy" && (!r.CredibleSignedFailure || r.CandidateVerdict != result.Fail) {
			t.Fatal("missing observations hid a signed failure")
		}
	}
}

func TestJournalSizeLimitChecksActualFileSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate((16 << 20) + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err = ReadJournal(path); err == nil {
		t.Fatal("oversized journal accepted")
	}
}

func TestLifecycleSignedFailureSurvivesOtherInvalidEvidence(t *testing.T) {
	events, _ := measuredEvents(t, "buggy")
	for i := range events {
		events[i].Version = LifecycleJournalVersion
		if events[i].Observation != nil && events[i].Observation.Phase == "intervention" && events[i].Observation.Index == 2 {
			events[i].Observation.Probes[1].Response.Signature = "bad"
		}
	}
	r, err := VerifyEvidence(rehashedJournal(t, events), "")
	if err != nil || r.BindingsValid || !r.CredibleSignedFailure || r.CandidateVerdict != result.Fail || r.TrustedExecutionVerdict != result.Inconclusive {
		t.Fatal("other invalid evidence erased a credible signed violation", err, r.Problems)
	}
}
