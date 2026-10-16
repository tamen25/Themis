package kubefault

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

type Config struct {
	ClusterUID   string `json:"clusterUID"`
	NamespaceUID string `json:"namespaceUID"`
	ApproverKey  string `json:"approverKey"`
	Operator     Actor  `json:"operator"`
}

type invocation struct {
	grant    Grant
	status   Status
	deadline time.Time // retains monotonic time; no client can renew it
	removed  chan struct{}
	fenced   bool
}

type Server struct {
	config       Config
	Identity     Identity
	key          ed25519.PrivateKey
	mu           sync.Mutex
	invocations  map[string]*invocation
	active       *invocation
	nonces       map[string]bool
	statusNonces map[string]bool
	slots        chan struct{}
	upstream     string
	client       *http.Client
}

func NewServer(config Config, podName, podUID string) (*Server, error) {
	if !uuid.MatchString(config.ClusterUID) || !uuid.MatchString(config.NamespaceUID) || !uuid.MatchString(podUID) || !validName(podName) || !validPublic(config.ApproverKey) || config.Operator.Name != OperatorName || !uuid.MatchString(config.Operator.UID) {
		return nil, ErrDenied
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	s := &Server{config: config, key: key, invocations: map[string]*invocation{}, nonces: map[string]bool{}, statusNonces: map[string]bool{}, slots: make(chan struct{}, 16)}
	s.Identity = Identity{Version: Version, ClusterUID: config.ClusterUID, NamespaceUID: config.NamespaceUID, PodName: podName, PodUID: podUID, InstanceID: RandomID(), ProxyID: RandomID(), EvidenceKey: hex.EncodeToString(public)}
	t := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext, DisableKeepAlives: true, DisableCompression: true, MaxConnsPerHost: 16, MaxResponseHeaderBytes: 8192}
	s.client = &http.Client{Transport: t, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return s, nil
}

func (s *Server) clearLocked(g *invocation, reason string) {
	if g.status.Active {
		g.status.Active = false
		g.status.Reason = reason
		close(g.removed)
	}
	if s.active == g {
		s.active = nil
	}
}

func (s *Server) currentLocked() *invocation {
	if s.active != nil && !time.Now().Before(s.active.deadline) {
		s.clearLocked(s.active, "expired")
	}
	return s.active
}

// No filesystem/network call runs while mu is held. The independent timer and
// request-path deadline check remain effective when a runner or journal stalls.
func (s *Server) control(c Command) (Status, string) {
	now := time.Now()
	if c.Action != "apply" && c.Action != "remove" && c.Action != "status" {
		return Status{}, "UnsupportedAction"
	}
	if !VerifyGrant(c.Grant, s.config.ApproverKey, s.Identity, s.config.Operator, now, c.Action == "apply") || !hexID.MatchString(c.Nonce) || c.At.After(now.Add(time.Second)) || now.Sub(c.At) > 5*time.Second {
		return Status{}, "AuthorizationDenied"
	}
	sig := c.Signature
	c.Signature = ""
	key := c.Grant.CleanupKey
	if c.Action == "apply" {
		key = c.Grant.InvocationKey
	}
	if !Verify("themis.kubernetes-command/v1alpha1", c, sig, key) {
		return Status{}, "CommandProofDenied"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentLocked()
	// Read polling must not consume the mutation budget needed for cleanup.
	// Both registries retain nonces without eviction; cross-action reuse is
	// rejected, including when an authenticated caller changes and re-signs it.
	registry := s.nonces
	if c.Action == "status" {
		registry = s.statusNonces
	}
	if len(registry) >= 4096 || s.nonces[c.Nonce] || s.statusNonces[c.Nonce] {
		return Status{}, "CommandReplayDenied"
	}
	registry[c.Nonce] = true
	g := s.invocations[c.Grant.InvocationID]
	if g != nil && Digest(GrantVersion, g.grant) != Digest(GrantVersion, c.Grant) {
		return Status{}, "InvocationMismatch"
	}
	if g == nil {
		if len(s.invocations) >= 256 {
			return Status{}, "FixtureCapacityReached"
		}
		g = &invocation{grant: c.Grant, status: Status{InvocationID: c.Grant.InvocationID, Reason: "not-applied"}}
		if c.Action != "status" {
			s.invocations[c.Grant.InvocationID] = g
		}
	}
	switch c.Action {
	case "apply":
		if g.status.Applied {
			return g.status, ""
		} // retained receipt; never renew/reapply
		if g.fenced {
			return g.status, "InvocationFenced"
		}
		if s.active != nil {
			return g.status, "FixtureBusy"
		}
		deadline := now.Add(time.Duration(c.Grant.Plan.Fault.DurationMS) * time.Millisecond)
		if c.Grant.ApplyBefore.Before(deadline) {
			deadline = now.Add(time.Until(c.Grant.ApplyBefore))
		}
		g.deadline, g.removed = deadline, make(chan struct{})
		g.status.Applied, g.status.Active, g.status.ApplyCount = true, true, 1
		g.status.AppliedAt, g.status.ExpiresAt, g.status.Reason = now.UTC(), deadline.UTC(), "active"
		s.active = g
		time.AfterFunc(time.Until(deadline), func() { s.mu.Lock(); defer s.mu.Unlock(); s.clearLocked(g, "expired") })
	case "remove":
		// An explicit synthetic negative mode. Expiry is never disabled by it.
		if g.status.Active && g.grant.Plan.Scenario == "cleanup-denied" {
			return g.status, "SyntheticCleanupDenied"
		}
		g.fenced = true
		s.clearLocked(g, "removed")
	}
	return g.status, ""
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		http.Error(w, "capacity", http.StatusTooManyRequests)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet && r.URL.Path == "/health" {
		w.WriteHeader(200)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/identity" {
		nonce := r.URL.Query().Get("nonce")
		if !hexID.MatchString(nonce) {
			w.WriteHeader(400)
			return
		}
		reply := Reply{Identity: s.Identity, Nonce: nonce, HTTPCode: 200}
		reply.Signature = Sign("themis.kubernetes-reply/v1alpha1", reply, s.key)
		_ = json.NewEncoder(w).Encode(reply)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/control" && r.URL.RawQuery == "" {
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
		var command Command
		if err != nil || Decode(data, &command) != nil {
			w.WriteHeader(400)
			return
		}
		status, code := s.control(command)
		httpCode := 200
		if code != "" {
			httpCode = 403
		}
		reply := Reply{Identity: s.Identity, Nonce: command.Nonce, HTTPCode: httpCode, Status: status, Error: code}
		reply.Signature = Sign("themis.kubernetes-reply/v1alpha1", reply, s.key)
		w.WriteHeader(httpCode)
		_ = json.NewEncoder(w).Encode(reply)
		return
	}
	if r.Method != http.MethodGet || r.URL.RawQuery != "" {
		w.WriteHeader(404)
		return
	}
	kind := ""
	switch r.URL.Path {
	case "/direct":
		kind = "direct"
	case "/proxy":
		kind = "proxy"
	case "/application":
		kind = "application"
	default:
		w.WriteHeader(404)
		return
	}
	id := r.Header.Get("X-Themis-Request-ID")
	if !hexID.MatchString(id) {
		w.WriteHeader(400)
		return
	}
	s.data(w, r, id, kind)
}

func (s *Server) data(w http.ResponseWriter, r *http.Request, id, kind string) {
	code, degraded, invocationID := 200, false, ""
	var heldDelay int64
	s.mu.Lock()
	g := s.currentLocked()
	var delay time.Duration
	var removed <-chan struct{}
	scenario := ""
	if g != nil {
		invocationID, scenario = g.grant.InvocationID, g.grant.Plan.Scenario
		if scenario != "noop" {
			delay = time.Duration(g.grant.Plan.Fault.DelayMS) * time.Millisecond
			removed = g.removed
		}
	}
	s.mu.Unlock()
	if kind == "direct" {
		invocationID = ""
	}
	if kind == "proxy" {
		if !s.call(r.Context(), "direct", id) {
			code = 502
		}
		if delay > 0 {
			heldStart := time.Now()
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-r.Context().Done():
				return
			case <-removed:
			case <-timer.C:
			}
			heldDelay = int64(time.Since(heldStart))
		}
	}
	if kind == "application" {
		ctx, cancel := context.WithTimeout(r.Context(), 75*time.Millisecond)
		ok := s.call(ctx, "proxy", id)
		cancel()
		if !ok {
			degraded = true
			if scenario == "buggy" {
				code = 503
			}
		}
	}
	body := Data{Identity: s.Identity, RequestID: id, Kind: kind, InvocationID: invocationID, HTTPCode: code, Degraded: degraded, ProxyDelayNS: heldDelay}
	body.Signature = Sign("themis.kubernetes-data/v1alpha1", body, s.key)
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func (s *Server) call(ctx context.Context, kind, id string) bool {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, s.upstream+"/"+kind, nil)
	if err != nil {
		return false
	}
	r.Header.Set("X-Themis-Request-ID", id)
	response, err := s.client.Do(r)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	var body Data
	return err == nil && len(data) <= 16384 && Decode(data, &body) == nil && response.StatusCode == 200 && VerifyData(body, s.Identity, id, kind, response.StatusCode)
}

// Serve owns its listener and fixed upstream. There is no configurable external
// destination. Process death leaves no persistent fault or networking mutation.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	port := listener.Addr().(*net.TCPAddr).Port
	s.upstream = "http://127.0.0.1:" + jsonNumber(port)
	listener = &limitedListener{Listener: listener, slots: make(chan struct{}, 32)}
	server := &http.Server{Handler: s, ReadHeaderTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 8192}
	defer s.client.CloseIdleConnections()
	go func() { <-ctx.Done(); _ = server.Close() }()
	err := server.Serve(listener)
	s.mu.Lock()
	if s.active != nil {
		s.clearLocked(s.active, "fixture-stopped")
	}
	s.mu.Unlock()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

type limitedListener struct {
	net.Listener
	slots chan struct{}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	l.slots <- struct{}{}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitedConnection{Conn: c, slots: l.slots}, nil
}

type limitedConnection struct {
	net.Conn
	slots chan struct{}
	once  sync.Once
}

func (c *limitedConnection) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { <-c.slots })
	return err
}

func jsonNumber(n int) string { b, _ := json.Marshal(n); return string(b) }
