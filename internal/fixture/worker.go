package fixture

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tamen25/themis/internal/contract"
	"github.com/tamen25/themis/internal/localpolicy"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/plan"
	"github.com/tamen25/themis/internal/safety"
)

type grant struct {
	authorization safety.Authorization
	plan          plan.ExperimentPlan
	deadline      time.Time // retains the monotonic clock
	leaseDeadline time.Time
	handle        FaultHandle
	receipt       Receipt
	quiesced      bool
	interrupted   bool
}

type activeFault struct {
	handle   FaultHandle
	deadline time.Time
	latency  time.Duration
	removed  chan struct{}
	timer    *time.Timer
}

// authority is the fixture's Safety Controller and single concrete fault adapter.
// No filesystem or network operation runs while mu is held. Expiry therefore
// does not depend on journal storage, a parent process, or a client connection.
type authority struct {
	mu         sync.Mutex
	config     WorkerConfig
	identity   plan.FixtureIdentity
	grants     map[string]*grant
	active     *activeFault
	claimed    string
	applyCount int
	events     []Lifecycle
	cancel     context.CancelFunc
	http       *http.Client
	requests   chan struct{}
	nonces     map[string]bool
}

// Worker runs in a separate, disposable process. Its only upstream is a service
// listener that it allocated itself; it cannot be configured to forward elsewhere.
func Worker(ctx context.Context, input io.Reader) error {
	data, err := io.ReadAll(io.LimitReader(input, 1<<20+1))
	if err != nil {
		return err
	}
	var cfg WorkerConfig
	if err := localstate.Unmarshal(data, &cfg); err != nil {
		return err
	}
	actor, err := localstate.CurrentActor()
	if err != nil {
		return err
	}
	if actor != cfg.Owner || !fixtureName.MatchString(cfg.Name) || cfg.Lifetime < 15*time.Second || cfg.Lifetime > localpolicy.FixtureTTL {
		return errors.New("invalid fixture owner or lifetime")
	}
	switch cfg.Mode {
	case "healthy", "buggy", "noop-adapter", "cleanup-denied":
	default:
		return errors.New("unsupported fixture mode")
	}
	var credentials Credentials
	if err := localstate.Read(filepath.Join(cfg.Directory, "credentials.json"), &credentials); err != nil {
		return err
	}
	if credentials != cfg.Credentials || !plan.ValidInstanceID(credentials.ControlToken) || !plan.ValidInstanceID(credentials.DataToken) || credentials.ControlToken == credentials.DataToken {
		return errors.New("invalid fixture credentials")
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Lifetime)
	defer cancel()
	listeners := make([]net.Listener, 0, 3)
	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}()
	for range 3 {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return err
		}
		listeners = append(listeners, &boundedListener{Listener: l, slots: make(chan struct{}, 32)})
	}
	id := plan.FixtureIdentity{Name: cfg.Name, InstanceID: localstate.RandomID(), ServiceID: localstate.RandomID(), ProxyID: localstate.RandomID(), OwnerUID: actor.UID, Host: actor.Host, PID: os.Getpid(), ServiceURL: "http://" + listeners[0].Addr().String(), ProxyURL: "http://" + listeners[1].Addr().String(), ControlURL: "http://" + listeners[2].Addr().String(), AdapterVersion: localpolicy.AdapterVersion, ExpiresAt: time.Now().Add(cfg.Lifetime).UTC()}
	id.EvidenceKey = hex.EncodeToString(evidencePrivateKey(cfg.Credentials.ControlToken)[32:])
	h, transport := NewHTTPClient()
	defer transport.CloseIdleConnections()
	a := &authority{config: cfg, identity: id, grants: make(map[string]*grant), cancel: cancel, http: h, requests: make(chan struct{}, 16), nonces: make(map[string]bool)}
	servers := []*http.Server{}
	failures := make(chan error, 3)
	for i, handler := range []http.Handler{http.HandlerFunc(a.service), http.HandlerFunc(a.proxy), http.HandlerFunc(a.control)} {
		server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 8192, BaseContext: func(net.Listener) context.Context { return ctx }}
		servers = append(servers, server)
		go func(l net.Listener) { failures <- server.Serve(l) }(listeners[i])
	}
	defer func() {
		a.mu.Lock()
		a.clearFault("worker-stopped")
		a.mu.Unlock()
		for _, s := range servers {
			_ = s.Close()
		}
	}()
	if err := localstate.WriteNew(filepath.Join(cfg.Directory, "identity.json"), id); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-failures:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// Close releases a connection's capacity exactly once, including server errors.
type boundedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *boundedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }

type boundedListener struct {
	net.Listener
	slots chan struct{}
}

func (l *boundedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &boundedConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			_ = c.Close()
		}
	}
}

func authorized(r *http.Request, token string) bool {
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) == 1
}
func writeJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}
func deny(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, struct {
		Error string `json:"error"`
	}{"denied"})
}

func (a *authority) control(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/inspect" && len(r.URL.Query()) == 1 && plan.ValidInstanceID(r.URL.Query().Get("nonce")) {
		data, _ := json.Marshal(a.snapshot())
		reply := controlResponse{Status: 200, Nonce: r.URL.Query().Get("nonce"), Body: data}
		reply.MAC = mac(a.config.Credentials.ControlToken, reply)
		writeJSON(w, 200, reply)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/identity" && len(r.URL.Query()) == 1 && plan.ValidInstanceID(r.URL.Query().Get("nonce")) {
		proof := IdentityProof{Version: Version, Identity: a.identity, Nonce: r.URL.Query().Get("nonce")}
		proof.MAC = mac(a.config.Credentials.ControlToken, proof)
		writeJSON(w, 200, proof)
		return
	}
	if r.Method != http.MethodPost || r.URL.RawQuery != "" {
		deny(w)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 128<<10))
	if err != nil {
		deny(w)
		return
	}
	nonce := r.Header.Get("X-Themis-Nonce")
	if !plan.ValidInstanceID(nonce) || !validMAC(a.config.Credentials.ControlToken, requestProof(a.identity.InstanceID, r.URL.Path, nonce, data), r.Header.Get("X-Themis-Signature")) {
		deny(w)
		return
	}
	a.mu.Lock()
	replayed := a.nonces[nonce] || len(a.nonces) >= 4096
	if !replayed {
		a.nonces[nonce] = true
	}
	a.mu.Unlock()
	if replayed {
		deny(w)
		return
	}
	respondCode := func(code int, value any) {
		data, _ := json.Marshal(value)
		reply := controlResponse{Status: code, Nonce: nonce, Body: data}
		reply.MAC = mac(a.config.Credentials.ControlToken, reply)
		writeJSON(w, code, reply)
	}
	respond := func(value any) { respondCode(200, value) }
	reject := func(code string) {
		respondCode(403, struct {
			Code string `json:"code"`
		}{code})
	}
	decode := func(out any) bool {
		if localstate.Unmarshal(data, out) != nil {
			deny(w)
			return false
		}
		return true
	}
	switch r.URL.Path {
	case "/authorize":
		var req AuthorizeRequest
		if !decode(&req) {
			return
		}
		authorization, err := a.authorize(req)
		if err != nil {
			reject("AUTHORIZATION_DENIED")
			return
		}
		respond(authorization)
	case "/claim":
		var req ClaimRequest
		if !decode(&req) {
			return
		}
		handle, err := a.claim(req)
		if err != nil {
			reject("CLAIM_DENIED")
			return
		}
		respond(handle)
	case "/apply":
		var req ApplyRequest
		if !decode(&req) {
			return
		}
		receipt, err := a.apply(req.Handle)
		if err != nil {
			reject("APPLY_DENIED")
			return
		}
		respond(receipt)
	case "/validate-claim":
		var req ApplyRequest
		if !decode(&req) {
			return
		}
		a.mu.Lock()
		err := a.validateClaim(req.Handle)
		a.mu.Unlock()
		if err != nil {
			reject("REVALIDATION_DENIED")
			return
		}
		respond(struct{}{})
	case "/quiesce":
		var req QuiesceRequest
		if !decode(&req) {
			return
		}
		if req.Reason != "runner" && req.Reason != "cancel" && req.Reason != "cleanup" {
			reject("INVALID_REASON")
			return
		}
		a.mu.Lock()
		g := a.grants[req.Handle.AuthorizationID]
		ok := g != nil && g.handle == req.Handle && a.claimed == req.Handle.RunID
		if ok {
			if !g.quiesced {
				g.quiesced = true
				a.event("quiesced", req.Handle.FaultID)
			}
			if req.Reason != "runner" && !g.interrupted {
				g.interrupted = true
				a.event("interrupted", req.Handle.FaultID)
			}
			if a.active != nil && a.active.handle == req.Handle {
				a.clearFault("quiesced")
			}
		}
		a.mu.Unlock()
		if !ok {
			reject("RESOURCE_MISMATCH")
			return
		}
		respond(struct{}{})
	case "/stop-run":
		var req ApplyRequest
		if !decode(&req) {
			return
		}
		a.mu.Lock()
		g := a.grants[req.Handle.AuthorizationID]
		ok := g != nil && g.handle == req.Handle && g.quiesced
		a.mu.Unlock()
		if !ok {
			reject("RESOURCE_MISMATCH")
			return
		}
		if a.config.Mode == "cleanup-denied" {
			reject("CLEANUP_DENIED")
			return
		}
		respond(struct{}{})
		time.AfterFunc(10*time.Millisecond, a.cancel)
	case "/remove":
		var req ApplyRequest
		if !decode(&req) {
			return
		}
		a.mu.Lock()
		g := a.grants[req.Handle.AuthorizationID]
		ok := g != nil && g.handle == req.Handle
		if ok && a.active != nil && a.active.handle == req.Handle {
			a.clearFault("removed")
		}
		a.mu.Unlock()
		if !ok {
			reject("RESOURCE_MISMATCH")
			return
		}
		respond(struct{}{})
	case "/status":
		var req struct{}
		if !decode(&req) {
			return
		}
		respond(a.snapshot())
	case "/stop":
		var req struct{}
		if !decode(&req) {
			return
		}
		if a.config.Mode == "cleanup-denied" {
			reject("CLEANUP_DENIED")
			return
		}
		a.mu.Lock()
		a.clearFault("stopped")
		a.mu.Unlock()
		respond(struct{}{})
		time.AfterFunc(10*time.Millisecond, a.cancel)
	default:
		deny(w)
	}
}

func (a *authority) authorize(req AuthorizeRequest) (safety.Authorization, error) {
	var envelope struct {
		Digest string                  `json:"planDigest"`
		Plan   plan.ExperimentDocument `json:"plan"`
	}
	if err := localstate.Unmarshal(req.Plan, &envelope); err != nil {
		return safety.Authorization{}, err
	}
	if envelope.Plan.Target != a.identity || req.Actor != a.config.Owner {
		return safety.Authorization{}, safety.ErrDenied
	}
	data, _ := json.Marshal(envelope.Plan.Contract)
	c, err := contract.ParseExperiment(bytes.NewReader(data))
	if err != nil {
		return safety.Authorization{}, err
	}
	p, err := plan.CompileExperiment(c, a.identity)
	if err != nil {
		return safety.Authorization{}, err
	}
	if envelope.Digest != p.Digest() || req.ApprovedDigest != p.Digest() {
		return safety.Authorization{}, safety.ErrDenied
	}
	// Recompilation rejects edited policy versions and unsigned envelope claims.
	var canonical bytes.Buffer
	if err := json.Compact(&canonical, req.Plan); err != nil {
		return safety.Authorization{}, err
	}
	if !bytes.Equal(canonical.Bytes(), p.JSON()) {
		return safety.Authorization{}, safety.ErrDenied
	}
	now := time.Now()
	if err := safety.Evaluate(p, a.config.Owner, now); err != nil {
		return safety.Authorization{}, err
	}
	auth := safety.Authorization{ID: localstate.RandomID(), PlanDigest: p.Digest(), Actor: a.config.Owner, FixtureID: a.identity.InstanceID, ServiceID: a.identity.ServiceID, ProxyID: a.identity.ProxyID, Action: "http.response-latency", AdapterVersion: localpolicy.AdapterVersion, IssuedAt: now.UTC(), ExpiresAt: now.Add(localpolicy.AuthorizationTTL).UTC()}
	auth.Seal = mac(a.config.Credentials.ControlToken, auth)
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.grants) >= 16 {
		return safety.Authorization{}, safety.ErrDenied
	}
	a.grants[auth.ID] = &grant{authorization: auth, plan: p, deadline: now.Add(localpolicy.AuthorizationTTL)}
	return auth, nil
}

func (a *authority) claim(req ClaimRequest) (FaultHandle, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.expire()
	g := a.grants[req.Authorization.ID]
	if g == nil || g.authorization != req.Authorization || !time.Now().Before(g.deadline) || !plan.ValidInstanceID(req.RunID) || a.claimed != "" {
		return FaultHandle{}, safety.ErrDenied
	}
	if err := safety.CheckAuthorization(req.Authorization, g.plan, a.config.Owner, time.Now()); err != nil {
		return FaultHandle{}, err
	}
	budget, _ := time.ParseDuration(g.plan.Snapshot().Contract.Spec.Execution.MaxDuration)
	g.leaseDeadline = time.Now().Add(budget)
	g.handle = FaultHandle{RunID: req.RunID, FaultID: localstate.RandomID(), AuthorizationID: req.Authorization.ID, FixtureID: a.identity.InstanceID, ProxyID: a.identity.ProxyID, AdapterVersion: localpolicy.AdapterVersion, ExpiresAt: g.leaseDeadline.UTC()}
	a.claimed = req.RunID
	a.event("claimed", g.handle.FaultID)
	return g.handle, nil
}

func (a *authority) apply(h FaultHandle) (Receipt, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.expire()
	g := a.grants[h.AuthorizationID]
	if g == nil || g.handle != h || a.claimed != h.RunID {
		return Receipt{}, safety.ErrDenied
	}
	// An acknowledged duplicate is inspect-only. It cannot restart an expired or
	// removed fault, extend its deadline, or invoke the adapter a second time.
	if !g.receipt.AppliedAt.IsZero() {
		r := g.receipt
		r.AlreadyApplied = true
		return r, nil
	}
	if g.quiesced {
		return Receipt{}, safety.ErrDenied
	}
	if !time.Now().Before(g.deadline) || !time.Now().Before(g.leaseDeadline) || !time.Now().Before(h.ExpiresAt) || a.active != nil {
		return Receipt{}, safety.ErrDenied
	}
	if err := safety.CheckAuthorization(g.authorization, g.plan, a.config.Owner, time.Now()); err != nil {
		return Receipt{}, err
	}
	s := g.plan.Snapshot().Contract.Spec
	latency, _ := time.ParseDuration(s.Fault.Latency)
	duration, _ := time.ParseDuration(s.Fault.Duration)
	now := time.Now()
	deadline := now.Add(duration)
	if g.leaseDeadline.Before(deadline) {
		deadline = g.leaseDeadline
	}
	f := &activeFault{handle: h, deadline: deadline, latency: latency, removed: make(chan struct{})}
	a.active = f
	a.applyCount++
	a.event("applied", h.FaultID)
	f.timer = time.AfterFunc(time.Until(deadline), func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.active == f {
			a.clearFault("expired")
		}
	})
	g.receipt = Receipt{Handle: h, AppliedAt: now.UTC(), FaultExpiresAt: deadline.UTC()}
	return g.receipt, nil
}

// Called under mu. Revalidation grants no new capability and has no fault effect.
func (a *authority) validateClaim(h FaultHandle) error {
	g := a.grants[h.AuthorizationID]
	if g == nil || g.handle != h || a.claimed != h.RunID || g.quiesced || !g.receipt.AppliedAt.IsZero() || !time.Now().Before(g.deadline) || !time.Now().Before(g.leaseDeadline) || !time.Now().Before(h.ExpiresAt) {
		return safety.ErrDenied
	}
	return safety.CheckAuthorization(g.authorization, g.plan, a.config.Owner, time.Now())
}

// Read-only inspection does not expire a fault, append lifecycle events, or
// consume control nonces. The independent timer still performs actual expiry.
func (a *authority) snapshot() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := Status{Identity: a.identity, ApplyCount: a.applyCount, Events: append([]Lifecycle{}, a.events...)}
	if a.active != nil && time.Now().Before(a.active.deadline) {
		h := a.active.handle
		s.ActiveFault = &h
	}
	for _, g := range a.grants {
		if g.handle.RunID != "" && g.handle.RunID == a.claimed {
			claim := &ClaimStatus{RunID: g.handle.RunID, Quiesced: g.quiesced, Interrupted: g.interrupted}
			if !g.receipt.AppliedAt.IsZero() {
				r := g.receipt
				claim.Receipt = &r
			}
			s.Claim = claim
			break
		}
	}
	return s
}

func (a *authority) event(kind, id string) {
	if len(a.events) == 256 {
		copy(a.events, a.events[1:])
		a.events = a.events[:255]
	}
	a.events = append(a.events, Lifecycle{kind, id, time.Now().UTC()})
}
func (a *authority) clearFault(reason string) {
	if a.active == nil {
		return
	}
	a.active.timer.Stop()
	close(a.active.removed)
	a.event(reason, a.active.handle.FaultID)
	a.active = nil
}
func (a *authority) expire() {
	if a.active != nil && !time.Now().Before(a.active.deadline) {
		a.clearFault("expired")
	}
}

func (a *authority) admitData(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet || r.URL.RawQuery != "" || !authorized(r, a.config.Credentials.DataToken) || !plan.ValidInstanceID(r.Header.Get("X-Themis-Request-ID")) {
		deny(w)
		return false
	}
	select {
	case a.requests <- struct{}{}:
		return true
	default:
		writeJSON(w, http.StatusServiceUnavailable, struct{}{})
		return false
	}
}

func (a *authority) service(w http.ResponseWriter, r *http.Request) {
	if !a.admitData(w, r) {
		return
	}
	defer func() { <-a.requests }()
	id := r.Header.Get("X-Themis-Request-ID")
	body := DataResponse{FixtureID: a.identity.InstanceID, ServiceID: a.identity.ServiceID, RequestID: id}
	switch r.URL.Path {
	case "/dependency":
		body.Kind = "dependency"
		a.writeData(w, 200, body)
	case "/work":
		body.Kind = "application"
		body.DependencyID = id
		budget := localpolicy.RequestLimit
		if a.config.Mode == "buggy" {
			budget = 50 * time.Millisecond
		}
		ctx, cancel := context.WithTimeout(r.Context(), budget)
		defer cancel()
		_, code, err := a.fetch(ctx, a.identity.ProxyURL+"/dependency", id, true)
		if err != nil || code != 200 {
			a.writeData(w, 503, body)
			return
		}
		a.writeData(w, 200, body)
	default:
		deny(w)
	}
}

func (a *authority) proxy(w http.ResponseWriter, r *http.Request) {
	if !a.admitData(w, r) {
		return
	}
	defer func() { <-a.requests }()
	if r.URL.Path != "/dependency" {
		deny(w)
		return
	}
	id := r.Header.Get("X-Themis-Request-ID")
	body, code, err := a.fetch(r.Context(), a.identity.ServiceURL+"/dependency", id, false)
	if err != nil {
		writeJSON(w, 502, struct{}{})
		return
	}
	a.mu.Lock()
	a.expire()
	f := a.active
	a.mu.Unlock()
	if f != nil && a.config.Mode != "noop-adapter" {
		delay := min(f.latency, time.Until(f.deadline))
		if delay > 0 {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-f.removed:
			case <-r.Context().Done():
				return
			}
		}
	}
	body.ProxyID = a.identity.ProxyID
	a.writeData(w, code, body)
}

func (a *authority) writeData(w http.ResponseWriter, code int, body DataResponse) {
	body.HTTPStatus = code
	writeJSON(w, code, signData(a.config.Credentials.ControlToken, body))
}

func (a *authority) fetch(ctx context.Context, endpoint, id string, proxy bool) (DataResponse, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return DataResponse{}, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+a.config.Credentials.DataToken)
	req.Header.Set("X-Themis-Request-ID", id)
	response, err := a.http.Do(req)
	if err != nil {
		return DataResponse{}, 0, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(data) > 4096 {
		return DataResponse{}, 0, errors.New("invalid upstream body")
	}
	var body DataResponse
	if err := localstate.Unmarshal(data, &body); err != nil {
		return body, 0, err
	}
	kind := "direct"
	if proxy {
		kind = "proxy"
	}
	if !VerifyData(body, a.identity, id, kind) || body.HTTPStatus != response.StatusCode {
		return body, 0, errors.New("upstream identity mismatch")
	}
	return body, response.StatusCode, nil
}
