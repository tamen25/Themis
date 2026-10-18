package dependencyhttp

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tamen25/themis/internal/localstate"
)

// Config is supplied only by the owned installer, never by an experiment request.
type Config struct {
	ClusterUID   string `json:"clusterUID"`
	NamespaceUID string `json:"namespaceUID"`
	Namespace    string `json:"namespace"`
	InstallerKey string `json:"installerKey"`
	ApproverKey  string `json:"approverKey"`
	Actor        string `json:"actor"`
	ActorUID     string `json:"actorUID"`
	ProxyIP      string `json:"proxyIP"`
}
type epoch struct {
	grant    Grant
	state    State
	deadline time.Time
	stopped  chan struct{}
}
type Server struct {
	Identity         Process
	key              string
	config           Config
	boot             time.Time
	client           *http.Client
	slots            chan struct{}
	control          sync.Mutex // disk operations never hold the data-path mutex
	mu               sync.Mutex
	binding          *Binding
	epochs           map[string]*epoch
	active           *epoch
	journal          *os.File
	journalBytes     int
	journalDigest    [32]byte
	peerClient       *http.Client // controlled HTTP peer transport in tests; never exposed by config
	poisoned         bool
	unconfirmedUntil time.Time
}

func HTTPClient() *http.Client {
	t := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 300 * time.Millisecond}).DialContext, DisableKeepAlives: true, DisableCompression: true, MaxConnsPerHost: 16, MaxResponseHeaderBytes: 8192}
	return &http.Client{Transport: t, Timeout: RequestMS * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func NewServer(c Config, role, podUID, stateDir string) (*Server, error) {
	if !uuid.MatchString(c.ClusterUID) || !uuid.MatchString(c.NamespaceUID) || !uuid.MatchString(podUID) || !namespace.MatchString(c.Namespace) || !hexID.MatchString(c.InstallerKey) || !hexID.MatchString(c.ApproverKey) || c.InstallerKey == c.ApproverKey || c.Actor != "system:serviceaccount:"+c.Namespace+":native-runner" || !uuid.MatchString(c.ActorUID) || (role != "application" && role != "proxy" && role != "dependency") {
		return nil, ErrDenied
	}
	pub, key, e := NewKey()
	if e != nil {
		return nil, e
	}
	s := &Server{Identity: Process{Version, role, c.ClusterUID, c.NamespaceUID, podUID, ID(), pub}, key: key, config: c, boot: time.Now(), client: HTTPClient(), slots: make(chan struct{}, 16), epochs: map[string]*epoch{}}
	if !PrivateIP(c.ProxyIP) {
		return nil, ErrDenied
	}
	s.client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		allowed := role == "application" && address == net.JoinHostPort(c.ProxyIP, "8080")
		s.mu.Lock()
		binding := s.binding
		s.mu.Unlock()
		if role == "proxy" && binding != nil {
			allowed = address == net.JoinHostPort(binding.Target.DependencyIP, "8080")
		}
		if !allowed {
			return nil, errors.New("fixed dependency egress only")
		}
		return (&net.Dialer{Timeout: 300 * time.Millisecond}).DialContext(ctx, network, address)
	}
	if role == "proxy" {
		entries, e := os.ReadDir(stateDir)
		if e != nil || len(entries) >= 16 {
			return nil, errors.New("bounded proxy state unavailable")
		}
		dir, e := localstate.CreateDirectory(filepath.Join(stateDir, s.Identity.Boot))
		if e != nil {
			return nil, e
		}
		s.journal, e = localstate.OpenNew(filepath.Join(dir, "control.jsonl"))
		if e != nil {
			return nil, e
		}
		if e = s.persist(struct {
			Version  string
			Identity Process
		}{Version, s.Identity}); e != nil {
			s.Close()
			return nil, e
		}
	}
	return s, nil
}
func (s *Server) Close() {
	if s.journal != nil {
		_ = s.journal.Close()
	}
	s.client.CloseIdleConnections()
}

// persist is called only under the control gate (or during construction).
// A failed/torn append permanently denies further mutations in this process.
func (s *Server) persist(v any) error {
	if s.poisoned || s.journal == nil {
		return errors.New("control journal unavailable")
	}
	if localstate.Check(s.journal.Name()) != nil {
		s.poisoned = true
		return errors.New("control journal identity")
	}
	input, e := os.Open(s.journal.Name())
	if e != nil {
		s.poisoned = true
		return e
	}
	prior, e := io.ReadAll(io.LimitReader(input, (512<<10)+1))
	_ = input.Close()
	if e != nil || len(prior) != s.journalBytes || (s.journalBytes > 0 && sha256.Sum256(prior) != s.journalDigest) {
		s.poisoned = true
		return errors.New("control journal corrupt or torn")
	}
	b := append(JSON(v), '\n')
	if len(b) > 32<<10 || s.journalBytes+len(b) > 512<<10 {
		s.poisoned = true
		return errors.New("control journal bound")
	}
	n, e := s.journal.Write(b)
	if e == nil && n != len(b) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = s.journal.Sync()
	}
	if e != nil {
		s.poisoned = true
		return e
	}
	s.journalBytes += len(b)
	s.journalDigest = sha256.Sum256(append(prior, b...))
	return nil
}
func (s *Server) sign(r Reply) Reply {
	r.Version = Version
	r.Identity = s.Identity
	r.Signature = ""
	r.Signature = Sign(Version, r, s.key)
	return r
}
func (s *Server) clearLocked(e *epoch, reason string) {
	if e.state.Active {
		e.state.Active = false
		e.state.Reason = reason
		close(e.stopped)
	}
	if s.active == e {
		s.active = nil
	}
}
func (s *Server) activeLocked() *epoch {
	if s.active != nil && !time.Now().Before(s.active.deadline) {
		s.clearLocked(s.active, "expired")
	}
	return s.active
}
func (s *Server) snapshot(inv string) State {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeLocked()
	if e := s.epochs[inv]; e != nil {
		return e.state
	}
	return State{Invocation: inv, Reason: "not-applied"}
}
func (s *Server) checkPeers(ctx context.Context, t Target) bool {
	client := HTTPClient()
	defer client.CloseIdleConnections()
	client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != net.JoinHostPort(t.ApplicationIP, "8080") && address != net.JoinHostPort(t.DependencyIP, "8080") {
			return nil, ErrDenied
		}
		return (&net.Dialer{Timeout: 300 * time.Millisecond}).DialContext(ctx, network, address)
	}
	if s.peerClient != nil {
		client = s.peerClient
	}
	for _, peer := range []struct {
		ip       string
		identity Process
	}{{t.ApplicationIP, t.Application.Process}, {t.DependencyIP, t.Dependency.Process}} {
		nonce := ID()
		r, e := Fetch(ctx, client, "http://"+net.JoinHostPort(peer.ip, "8080")+"/identity?nonce="+nonce)
		if e != nil || !r.Verified(peer.identity, nonce, "identity") || r.Code != 200 {
			return false
		}
	}
	return true
}
func (s *Server) bind(ctx context.Context, b Binding) error {
	if time.Since(s.boot) > 60*time.Second || !b.Valid() || b.InstallerKey != s.config.InstallerKey || b.ApproverKey != s.config.ApproverKey || b.Actor != s.config.Actor || b.ActorUID != s.config.ActorUID || b.Target.Namespace != s.config.Namespace || b.Target.Proxy.Process != s.Identity {
		return ErrDenied
	}
	s.control.Lock()
	defer s.control.Unlock()
	s.mu.Lock()
	bound := s.binding != nil
	s.mu.Unlock()
	if bound {
		return ErrDenied
	}
	if !s.checkPeers(ctx, b.Target) {
		return ErrDenied
	}
	if e := s.persist(struct {
		Kind    string
		Binding Binding
	}{"BIND", b}); e != nil {
		return e
	}
	s.mu.Lock()
	s.binding = &b
	s.mu.Unlock()
	return nil
}
func (s *Server) mutate(ctx context.Context, c Command) (State, error) {
	now := time.Now()
	key := c.Grant.CleanupKey
	if c.Action == "apply" {
		key = c.Grant.ApplyKey
	}
	sig := c.Signature
	c.Signature = ""
	if c.Version != CommandVersion || (c.Action != "apply" && c.Action != "remove" && c.Action != "status") || !hexID.MatchString(c.Nonce) || now.Sub(c.At) > 2*time.Second || c.At.After(now.Add(time.Second)) || !c.Grant.Valid(now, c.Action == "apply") || !Verify(CommandVersion, c, sig, key) {
		return State{}, ErrDenied
	}
	s.control.Lock()
	defer s.control.Unlock()
	s.mu.Lock()
	b := s.binding
	s.mu.Unlock()
	if b == nil || Hash(*b) != Hash(c.Grant.Plan.Binding) || b.Target.Proxy.Process != s.Identity {
		return State{}, ErrDenied
	}
	inv := c.Grant.Invocation
	s.mu.Lock()
	s.activeLocked()
	old := s.epochs[inv]
	if old != nil && Hash(old.grant) != Hash(c.Grant) {
		s.mu.Unlock()
		return State{}, ErrDenied
	}
	if (c.Action == "status" || c.Action == "remove") && now.Before(s.unconfirmedUntil) {
		s.mu.Unlock()
		return State{}, errors.New("confirmation deliberately withheld")
	}
	if c.Action == "status" {
		v := State{Invocation: inv, Reason: "not-applied"}
		if old != nil {
			v = old.state
		}
		s.mu.Unlock()
		return v, nil
	}
	if c.Action == "remove" && old != nil && old.state.Fenced {
		v := old.state
		s.mu.Unlock()
		return v, nil
	}
	if c.Action == "apply" && old != nil {
		v := old.state
		s.mu.Unlock()
		if v.Fenced && !v.Applied {
			return v, ErrDenied
		}
		return v, nil
	} // retained once-only receipt; never extend
	if (old == nil && len(s.epochs) >= 64) || s.poisoned || (c.Action == "apply" && (s.active != nil || s.journalBytes+2*(32<<10) > 512<<10)) {
		s.mu.Unlock()
		return State{}, ErrDenied
	}
	s.mu.Unlock()
	if c.Action == "apply" && !s.checkPeers(ctx, b.Target) {
		return State{}, ErrDenied
	}
	// Durable one-use intent precedes changing the response path. A failed append
	// consumes safety, not permission; restart uses a different key/boot and no binding.
	if e := s.persist(struct {
		Kind  string
		Grant Grant
	}{c.Action + "-INTENT", c.Grant}); e != nil {
		return State{}, e
	}
	now = time.Now()
	if ctx.Err() != nil || !c.Grant.Valid(now, c.Action == "apply") {
		return State{}, ErrDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeLocked()
	e := old
	if e == nil {
		e = &epoch{grant: c.Grant, state: State{Invocation: inv, Reason: "not-applied"}, stopped: make(chan struct{})}
		s.epochs[inv] = e
	}
	if c.Action == "remove" {
		e.state.Fenced = true
		s.clearLocked(e, "removed")
		if !e.state.Applied {
			e.state.Reason = "fenced-before-apply"
		}
		return e.state, nil
	}
	if e.state.Fenced {
		return e.state, ErrDenied
	}
	d := time.Duration(c.Grant.Plan.LifetimeMS) * time.Millisecond
	// Convert the remaining wall-clock admission budget once into a local monotonic
	// cap. Wall-clock changes after admission cannot renew this deadline.
	if remaining := c.Grant.ApplyBefore.Sub(now); remaining < d {
		d = remaining
	}
	if d <= 0 {
		return State{}, ErrDenied
	}
	e.deadline = now.Add(d)
	e.state = State{Invocation: inv, Applied: true, ApplyCount: 1, Active: true, StartedNS: now.Sub(s.boot).Nanoseconds(), DeadlineNS: e.deadline.Sub(s.boot).Nanoseconds(), Reason: "active"}
	s.active = e
	if c.Grant.Plan.Scenario == "cleanup-unconfirmed" {
		s.unconfirmedUntil = e.deadline.Add(2 * time.Second)
	}
	time.AfterFunc(d, func() { s.mu.Lock(); defer s.mu.Unlock(); s.clearLocked(e, "expired") })
	return e.state, nil
}
func (s *Server) value(ctx context.Context, nonce string) Reply {
	r := Reply{Nonce: nonce, Kind: "value", Code: 200, Value: "synthetic-dependency-v1"}
	if s.Identity.Role == "dependency" {
		return s.sign(r)
	}
	if s.Identity.Role == "application" {
		upstream := "http://" + net.JoinHostPort(s.config.ProxyIP, "8080") + "/value?nonce=" + nonce
		p, e := Fetch(ctx, s.client, upstream)
		if e != nil || !p.Identity.Valid("proxy") || p.Identity.ClusterUID != s.Identity.ClusterUID || p.Identity.NamespaceUID != s.Identity.NamespaceUID || !p.Verified(p.Identity, nonce, "value") {
			r.Code = 504
			r.Value = "dependency-unavailable"
		} else {
			r.Proxy = &p
			r.Code = p.Code
			r.Value = p.Value
		}
		return s.sign(r)
	}
	s.mu.Lock()
	b := s.binding
	s.mu.Unlock()
	if b == nil {
		r.Code = 503
		r.Value = "proxy-not-bound"
		return s.sign(r)
	}
	d, e := Fetch(ctx, s.client, "http://"+net.JoinHostPort(b.Target.DependencyIP, "8080")+"/value?nonce="+nonce)
	if e != nil || !d.Verified(b.Target.Dependency.Process, nonce, "value") || d.Code != 200 {
		r.Code = 502
		r.Value = "dependency-unavailable"
		return s.sign(r)
	}
	r.Dependency = &d
	s.mu.Lock()
	active := s.activeLocked()
	var wait time.Duration
	var stopped <-chan struct{}
	if active != nil {
		r.State = active.state
		r.PlanDigest = active.grant.Digest
		stopped = active.stopped
		if active.grant.Plan.Scenario != "no-effect" {
			wait = time.Duration(active.grant.Plan.DelayMS) * time.Millisecond
			if remaining := time.Until(active.deadline); wait > remaining {
				wait = remaining
			}
		}
	}
	s.mu.Unlock()
	if wait > 0 {
		start := time.Now()
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			r.Code = 504
			r.Value = "request-deadline"
		case <-stopped:
		case <-timer.C:
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		r.HoldNS = time.Since(start).Nanoseconds()
	}
	// Every request checks the monotonic cap; expiry/remove also interrupt in-flight
	// waits. An unavailable proxy is not a recovered dependency path.
	return s.sign(r)
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		http.Error(w, "capacity", 429)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), RequestMS*time.Millisecond)
	defer cancel()
	if r.URL.RawPath != "" || r.URL.Fragment != "" || len(r.URL.RawQuery) > 200 || r.ContentLength > MaxBody {
		http.Error(w, "request denied", 400)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/health" {
		w.WriteHeader(200)
		return
	}
	nonce := r.URL.Query().Get("nonce")
	if !hexID.MatchString(nonce) || r.URL.RawQuery != "nonce="+nonce {
		http.Error(w, "nonce required", 400)
		return
	}
	reply := Reply{Nonce: nonce, Kind: "identity", Code: 200}
	switch {
	case r.Method == "GET" && r.URL.Path == "/identity":
	case r.Method == "GET" && r.URL.Path == "/value":
		reply = s.value(ctx, nonce)
	case r.Method == "GET" && r.URL.Path == "/state" && s.Identity.Role == "proxy":
		reply.Kind = "state"
		s.mu.Lock()
		e := s.activeLocked()
		if time.Now().Before(s.unconfirmedUntil) {
			reply.Code = 503
		} else if e != nil {
			reply.State = e.state
		}
		s.mu.Unlock()
		// Public observation is read-only and has no mutation nonce registry.
	case r.Method == "POST" && s.Identity.Role == "proxy" && (r.URL.Path == "/bind" || r.URL.Path == "/control"):
		body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 32<<10))
		if e != nil {
			http.Error(w, "bounded control body", 400)
			return
		}
		if r.URL.Path == "/bind" {
			var b Binding
			e = Decode(body, &b)
			if e == nil {
				e = s.bind(ctx, b)
			}
			reply.Kind = "bind"
		} else {
			var c Command
			e = Decode(body, &c)
			reply.Kind = "control"
			if e == nil && c.Nonce != nonce {
				e = ErrDenied
			}
			if e == nil {
				reply.State, e = s.mutate(ctx, c)
			}
			reply.Action = c.Action
			reply.PlanDigest = c.Grant.Digest
		}
		if e != nil {
			reply.Code = 403
			reply.Value = "denied-or-uncertain"
		}
	default:
		http.Error(w, "fixed routes only", 404)
		return
	}
	reply = s.sign(reply)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(reply.Code)
	_, _ = w.Write(JSON(reply))
}
func Fetch(ctx context.Context, c *http.Client, endpoint string) (Reply, error) {
	var r Reply
	req, e := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if e != nil {
		return r, e
	}
	resp, e := c.Do(req)
	if e != nil {
		return r, e
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if e != nil || len(b) > MaxBody {
		return r, errors.New("bounded response exceeded")
	}
	if e = Decode(b, &r); e != nil {
		return r, e
	}
	if r.Code != resp.StatusCode {
		return r, fmt.Errorf("response status mismatch")
	}
	return r, nil
}
