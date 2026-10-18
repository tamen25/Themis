// Package livewitness implements only the owned synthetic HTTP observer.
package livewitness

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/tamen25/themis/internal/kubeexperiment"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/pkg/evidence"
	obs "github.com/tamen25/themis/pkg/liveobservation"
)

type Key struct {
	Version    string `json:"version"`
	Witness    string `json:"witness"`
	PrivateKey []byte `json:"privateKey"`
}

type PublicIdentity struct {
	Version   string `json:"version"`
	Witness   string `json:"witness"`
	KeyID     string `json:"keyId"`
	PublicKey []byte `json:"publicKey"`
	Algorithm string `json:"algorithm"`
}

func Keygen(dir, witness string) (PublicIdentity, error) {
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return PublicIdentity{}, e
	}
	identity := PublicIdentity{Version: "themis.live-observation-key-identity/v1alpha1", Witness: witness, KeyID: evidence.Fingerprint(pub), PublicKey: pub, Algorithm: evidence.Algorithm}
	if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`).MatchString(witness) {
		return identity, errors.New("invalid witness identity")
	}
	path, e := localstate.CreateDirectory(dir)
	if e != nil {
		return identity, e
	}
	e = localstate.WriteNew(filepath.Join(path, "witness-key.json"), Key{"themis.live-observation-key/v1alpha1", witness, key})
	return identity, e
}
func readKey(dir string) (Key, error) {
	var k Key
	e := localstate.Read(filepath.Join(dir, "witness-key.json"), &k)
	if e != nil || k.Version != "themis.live-observation-key/v1alpha1" || len(k.PrivateKey) != 64 || !bytes.Equal(k.PrivateKey, ed25519.NewKeyFromSeed(k.PrivateKey[:32])) {
		return Key{}, errors.New("protected witness key unavailable or invalid")
	}
	return k, nil
}

// Register receives only a public coordination record and public key hashes.
// It cannot approve, claim, execute, cancel or clean up a fault.
func Register(record kubeexperiment.CoordinationRecord, keyDir, sessionDir, digest, runnerKeyID, cleanupKeyID string, maxAppMillis int, now time.Time) (obs.Registration, error) {
	var r obs.Registration
	p := record.Proposal
	if p.Validate() != nil || p.PlanDigest != digest || record.ProposalDigest != p.Digest() || record.ExecutionState != "APPROVED" || record.LiveResult != nil || record.Approval == nil || record.InvocationID == "" || record.Approval.Version != kubeexperiment.CoordinationApprovalVersion || record.Approval.ProposalDigest != p.Digest() || record.Approval.ApproverKey != p.ApproverKey || record.Approval.InvocationID != record.InvocationID || record.Approval.PlanDigest != digest || now.Before(record.Approval.IssuedAt) || !now.Before(record.Approval.ApplyBefore) {
		return r, errors.New("explicit digest-approved unused public experiment required")
	}
	k, e := readKey(keyDir)
	if e != nil {
		return r, e
	}
	pub := ed25519.PrivateKey(k.PrivateKey).Public().(ed25519.PublicKey)
	fixture, _ := hex.DecodeString(p.Plan.Target.Fixture.EvidenceKey)
	approver, _ := hex.DecodeString(p.ApproverKey)
	keys := []string{evidence.Hash(fixture), evidence.Hash(approver), runnerKeyID, cleanupKeyID}
	sort.Strings(keys)
	r = obs.Registration{Version: obs.RegistrationVersion, Witness: k.Witness, KeyID: evidence.Fingerprint(pub), PublicKey: pub, Algorithm: evidence.Algorithm, Session: localstate.RandomID(), Plan: p.Plan, InvocationID: record.InvocationID, ProposalDigest: p.Digest(), NotBefore: now.UTC().Format(time.RFC3339Nano), NotAfter: now.Add(20 * time.Second).UTC().Format(time.RFC3339Nano), MaxSamples: obs.MaxSamples, IntervalMillis: 100, MaxApplicationMillis: maxAppMillis, Provenance: "LIVE_OBSERVER_REGISTRATION", AuthorityKeyIDs: keys}
	r = obs.SignRegistration(r, k.PrivateKey)
	if e = r.Validate(); e != nil {
		return r, e
	}
	path, e := localstate.CreateDirectory(sessionDir)
	if e != nil {
		return r, e
	}
	e = localstate.WriteNew(filepath.Join(path, "registration.json"), r)
	return r, e
}
