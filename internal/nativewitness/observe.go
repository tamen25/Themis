// Package nativewitness collects its own native HTTP measurements. It never
// opens a grant, runner inventory, approver key or cleanup capability.
package nativewitness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	adapter "github.com/tamen25/themis/internal/dependencyexperiment"
	wire "github.com/tamen25/themis/internal/dependencyhttp"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/pkg/evidence"
	obs "github.com/tamen25/themis/pkg/nativeobservation"
)

type keyRecord struct {
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

func Keygen(dir, name string) (PublicIdentity, error) {
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return PublicIdentity{}, e
	}
	identity := PublicIdentity{obs.Version, name, evidence.Fingerprint(pub), pub, evidence.Algorithm}
	// The registration validates the public name; restrict it before filesystem use.
	if len(name) == 0 || len(name) > 64 {
		return identity, wire.ErrDenied
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return identity, wire.ErrDenied
		}
	}
	path, e := localstate.CreateDirectory(dir)
	if e != nil {
		return identity, e
	}
	return identity, localstate.WriteNew(filepath.Join(path, "native-witness-key.json"), keyRecord{obs.Version, name, key})
}
func readKey(dir string) (keyRecord, error) {
	var k keyRecord
	e := localstate.Read(filepath.Join(dir, "native-witness-key.json"), &k)
	if e != nil || k.Version != obs.Version || len(k.PrivateKey) != 64 || !bytes.Equal(k.PrivateKey, ed25519.NewKeyFromSeed(k.PrivateKey[:32])) {
		return k, wire.ErrDenied
	}
	return k, nil
}
func Register(ref obs.ApprovalReference, keyDir, session, digest string, now time.Time) (obs.Registration, error) {
	var r obs.Registration
	if ref.Validate() != nil || ref.PlanDigest != digest || now.Before(ref.Issued) || !now.Before(ref.ApplyBefore) {
		return r, wire.ErrDenied
	}
	k, e := readKey(keyDir)
	if e != nil {
		return r, e
	}
	key := ed25519.PrivateKey(k.PrivateKey)
	pub := key.Public().(ed25519.PublicKey)
	r = obs.Registration{Version: obs.RegistrationVersion, Witness: k.Witness, KeyID: evidence.Fingerprint(pub), PublicKey: pub, Algorithm: evidence.Algorithm, Session: wire.ID(), Process: wire.ID(), Approval: ref, NotBefore: now.UTC().Format(time.RFC3339Nano), NotAfter: now.Add(20 * time.Second).UTC().Format(time.RFC3339Nano), MaxSamples: obs.MaxSamples, IntervalMS: int(obs.Interval / time.Millisecond), DurationMS: int(obs.Duration / time.Millisecond), Routes: obs.Routes(), Provenance: "LIVE_NATIVE_OBSERVER_REGISTRATION"}
	r = obs.SignRegistration(r, key)
	if e = r.Validate(); e != nil {
		return r, e
	}
	path, e := localstate.CreateDirectory(session)
	if e != nil {
		return r, e
	}
	return r, localstate.WriteNew(filepath.Join(path, "registration.json"), r)
}
func ReadRegistration(session string) (obs.Registration, error) {
	var r obs.Registration
	e := localstate.Read(filepath.Join(session, "registration.json"), &r)
	if e == nil {
		e = r.Validate()
	}
	return r, e
}

type journalFile interface {
	io.Writer
	Sync() error
	Close() error
}
type journal struct {
	file     journalFile
	reg      obs.Registration
	key      ed25519.PrivateKey
	epoch    time.Time
	records  []obs.Record
	raw      []byte
	poisoned bool
}

func (j *journal) append(kind, identity string, start int64, probes []obs.Probe) (obs.Record, error) {
	var r obs.Record
	if j.poisoned || len(j.records) >= obs.MaxRecords {
		return r, errors.New("native witness journal poisoned or full")
	}
	if start < 0 {
		start = int64(time.Since(j.epoch))
	}
	if probes == nil {
		probes = []obs.Probe{}
	}
	r = obs.Record{Version: obs.Version, Domain: obs.Domain, RegistrationDigest: obs.RegistrationDigest(j.reg), Session: j.reg.Session, Process: j.reg.Process, PID: os.Getpid(), KeyID: j.reg.KeyID, PlanDigest: j.reg.Approval.PlanDigest, Invocation: j.reg.Approval.Invocation, TargetDigest: wire.Hash(j.reg.Approval.Plan.Binding.Target), Sequence: len(j.records), Type: kind, UTC: time.Now().UTC().Format(time.RFC3339Nano), StartedNS: start, CompletedNS: int64(time.Since(j.epoch)), Identity: identity, Probes: probes}
	if len(j.records) > 0 {
		r.Previous = j.records[len(j.records)-1].Hash
	}
	r = obs.Seal(r, j.key)
	raw := append(wire.JSON(r), '\n')
	if len(raw) > obs.MaxRecord || len(j.raw)+len(raw) > obs.MaxJournal {
		return r, errors.New("native witness journal byte bound")
	}
	n, e := j.file.Write(raw)
	if e == nil && n != len(raw) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = j.file.Sync()
	}
	if e != nil {
		j.poisoned = true
		return r, e
	}
	j.raw = append(j.raw, raw...)
	j.records = append(j.records, r)
	return r, nil
}
func Observe(ctx context.Context, state, session, keyDir string) (obs.Finding, error) {
	f := obs.NewFinding()
	reg, e := ReadRegistration(session)
	if e != nil {
		return f, e
	}
	k, e := readKey(keyDir)
	if e != nil || k.Witness != reg.Witness || !bytes.Equal(ed25519.PrivateKey(k.PrivateKey).Public().(ed25519.PublicKey), reg.PublicKey) {
		return f, wire.ErrDenied
	}
	now := time.Now()
	begin, _ := obs.UTC(reg.NotBefore)
	end, _ := obs.UTC(reg.NotAfter)
	if now.Before(begin) || !now.Before(end.Add(-obs.Duration-time.Second)) {
		return f, errors.New("native witness registration start window closed")
	}
	// Track consumed session identities under the signing key, so copying a
	// registration to a new output directory cannot restart the same session.
	if e = claimSession(ctx, keyDir, reg.Session); e != nil {
		return f, e
	}
	if e = localstate.WriteNew(filepath.Join(session, "observe-claim.json"), struct {
		Session string `json:"session"`
	}{reg.Session}); e != nil {
		return f, errors.New("native witness sessions never resume")
	}
	file, e := localstate.OpenNew(filepath.Join(session, "observations.jsonl"))
	if e != nil {
		return f, e
	}
	defer file.Close()
	j := &journal{file: file, reg: reg, key: k.PrivateKey, epoch: time.Now()}
	ctx, cancel := context.WithDeadline(ctx, j.epoch.Add(obs.Duration))
	defer cancel()
	if _, e = j.append("START", "CONFIRMED", -1, nil); e != nil {
		return f, e
	}
	c, e := adapter.Open(ctx, state, "witness")
	if e != nil {
		_, writeErr := j.append("INTERRUPTED", "UNKNOWN", -1, nil)
		return f, errors.Join(e, writeErr)
	}
	if e = c.Check(ctx, reg.Approval.Plan.Binding.Target); e != nil {
		_, writeErr := j.append("INTERRUPTED", "UNKNOWN", -1, nil)
		return f, errors.Join(e, writeErr)
	}
	var connections [3]*adapter.Connection
	for i, role := range []string{"dependency", "proxy", "application"} {
		connections[i], e = c.Data(role)
		if e != nil {
			return f, e
		}
		defer connections[i].Close()
	}
	ready := false
	identity := "CONFIRMED"
	for count := 0; time.Since(j.epoch) < obs.Duration && count < obs.MaxSamples; count++ {
		if ctx.Err() != nil {
			break
		}
		if count%4 == 0 {
			checkCtx, stop := context.WithTimeout(ctx, time.Second)
			e = c.Check(checkCtx, reg.Approval.Plan.Binding.Target)
			stop()
			identity = "CONFIRMED"
			if e != nil {
				identity = "UNKNOWN"
			}
		}
		// Admit a group only while its full bounded request budget fits. Never
		// manufacture missing observations by starting at our own closing deadline.
		if time.Until(j.epoch.Add(obs.Duration)) < time.Duration(wire.RequestMS)*time.Millisecond {
			break
		}
		start := int64(time.Since(j.epoch))
		probes := make([]obs.Probe, 4)
		var tasks sync.WaitGroup
		for i, kind := range []string{"direct", "proxy", "application", "state"} {
			tasks.Go(func() {
				index := i
				if index == 3 {
					index = 1
				}
				conn := connections[index]
				nonce := wire.ID()
				route := "/value"
				expected := "value"
				if kind == "state" {
					route = "/state"
					expected = "state"
				}
				p := obs.Probe{Kind: kind, Nonce: nonce, StartedNS: int64(time.Since(j.epoch)), Outcome: "REQUEST_FAILED"}
				if kind == "state" {
					receipt, err := wire.FetchAuthority(ctx, conn.Client, conn.Base+"/receipt/"+reg.Approval.Invocation+"?nonce="+nonce)
					p.CompletedNS = int64(time.Since(j.epoch))
					if err == nil {
						p.Authority = &receipt
						p.HTTPCode = receipt.Code
						p.Outcome = "MEASURED"
						if !receipt.Verified(reg.Approval.Plan.Binding.Target.Proxy.Process, nonce, reg.Approval.Invocation) {
							p.Outcome = "IDENTITY_MISMATCH"
						}
					}
					probes[i] = p
					return
				}
				reply, err := wire.Fetch(ctx, conn.Client, conn.Base+route+"?nonce="+nonce)
				p.CompletedNS = int64(time.Since(j.epoch))
				if err == nil {
					p.Response = &reply
					p.HTTPCode = reply.Code
					p.Outcome = "MEASURED"
					target := reg.Approval.Plan.Binding.Target
					identity := []wire.Process{target.Dependency.Process, target.Proxy.Process, target.Application.Process, target.Proxy.Process}[i]
					if !reply.Verified(identity, nonce, expected) {
						p.Outcome = "IDENTITY_MISMATCH"
					}
				}
				probes[i] = p
			})
		}
		tasks.Wait()
		if _, e = j.append("SAMPLE", identity, start, probes); e != nil {
			return f, e
		}
		f, _ = obs.Analyze(reg, j.raw, nil, evidence.Publisher{}, time.Now())
		if !ready && f.Active > 0 {
			_, e = j.append("INTERRUPTED", identity, -1, nil)
			return f, e
		}
		if !ready && f.Baseline >= 3 && identity == "CONFIRMED" {
			r, err := j.append("READY", identity, -1, nil)
			if err != nil {
				return f, err
			}
			if e = localstate.WriteNew(filepath.Join(session, "ready.json"), r); e != nil {
				return f, e
			}
			ready = true
		}
		wait := time.Until(j.epoch.Add(time.Duration(start) + obs.Interval))
		if wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
			}
		}
	}
	kind := "END"
	if errors.Is(ctx.Err(), context.Canceled) {
		kind = "INTERRUPTED"
	}
	if _, e = j.append(kind, identity, -1, nil); e != nil {
		return f, e
	}
	f, _ = obs.Analyze(reg, j.raw, nil, evidence.Publisher{}, time.Now())
	return f, nil
}

func claimSession(ctx context.Context, keyDir, session string) error {
	lock, e := localstate.OpenLock(filepath.Join(keyDir, "session-claims.lock"), true)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = lock.Acquire(ctx); e != nil {
		return e
	}
	entries, e := os.ReadDir(keyDir)
	if e != nil {
		return e
	}
	count := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "used-session-") {
			count++
		}
	}
	if count >= 64 {
		return errors.New("native witness key session budget exhausted; rotate key")
	}
	return localstate.WriteNew(filepath.Join(keyDir, "used-session-"+session+".json"), struct {
		Session string `json:"session"`
	}{session})
}
func Inspect(session string, policy *obs.Policy, publisher evidence.Publisher, now time.Time) (obs.Finding, error) {
	reg, e := ReadRegistration(session)
	if e != nil {
		return obs.NewFinding(), e
	}
	path := filepath.Join(session, "observations.jsonl")
	if localstate.Check(path) != nil {
		return obs.NewFinding(), wire.ErrDenied
	}
	file, e := os.Open(path)
	if e != nil {
		return obs.NewFinding(), e
	}
	defer file.Close()
	raw, e := io.ReadAll(io.LimitReader(file, obs.MaxJournal+1))
	if e != nil {
		return obs.NewFinding(), e
	}
	f, _ := obs.Analyze(reg, raw, policy, publisher, now)
	return f, nil
}
