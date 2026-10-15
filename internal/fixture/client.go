package fixture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/tamen25/themis/internal/localpolicy"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/plan"
	"github.com/tamen25/themis/internal/safety"
)

type Client struct {
	Identity    plan.FixtureIdentity
	directory   string
	credentials Credentials
	http        *http.Client
	transport   *http.Transport
}

func NewHTTPClient() (*http.Client, *http.Transport) {
	t := &http.Transport{DialContext: (&net.Dialer{Timeout: localpolicy.RequestLimit}).DialContext, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 8192, MaxConnsPerHost: 8}
	return &http.Client{Transport: t, Timeout: localpolicy.RequestLimit, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, t
}

func Open(directory string) (*Client, error) {
	if err := localstate.Check(directory); err != nil {
		return nil, err
	}
	var id plan.FixtureIdentity
	if err := localstate.Read(filepath.Join(directory, "identity.json"), &id); err != nil {
		return nil, err
	}
	if err := plan.ValidateFixture(id); err != nil {
		return nil, err
	}
	actor, err := localstate.CurrentActor()
	if err != nil {
		return nil, err
	}
	if id.OwnerUID != actor.UID || id.Host != actor.Host {
		return nil, fmt.Errorf("%w: fixture belongs to another OS user/host", safety.ErrDenied)
	}
	var credentials Credentials
	if err := localstate.Read(filepath.Join(directory, "credentials.json"), &credentials); err != nil {
		return nil, err
	}
	if !plan.ValidInstanceID(credentials.ControlToken) || !plan.ValidInstanceID(credentials.DataToken) || credentials.ControlToken == credentials.DataToken {
		return nil, errors.New("invalid scoped fixture credentials")
	}
	h, t := NewHTTPClient()
	return &Client{id, directory, credentials, h, t}, nil
}
func (c *Client) Close() { c.http.CloseIdleConnections(); c.transport.CloseIdleConnections() }

// OpenWithTransport permits controlled failures at the real HTTP boundary in
// integration tests. CLI execution always uses the bounded default transport.
func OpenWithTransport(directory string, transport http.RoundTripper) (*Client, error) {
	c, err := Open(directory)
	if err != nil {
		return nil, err
	}
	if transport == nil {
		c.Close()
		return nil, errors.New("HTTP transport required")
	}
	c.http.Transport = transport
	return c, nil
}

func (c *Client) Resolve(ctx context.Context) (plan.FixtureIdentity, error) {
	if err := plan.ValidateFixture(c.Identity); err != nil {
		return plan.FixtureIdentity{}, err
	}
	nonce := localstate.RandomID()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Identity.ControlURL+"/identity?nonce="+nonce, nil)
	if err != nil {
		return plan.FixtureIdentity{}, err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return plan.FixtureIdentity{}, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 32769))
	if err != nil {
		return plan.FixtureIdentity{}, err
	}
	if len(data) > 32768 || response.StatusCode != 200 {
		return plan.FixtureIdentity{}, errors.New("fixture identity handshake failed")
	}
	var proof IdentityProof
	if err := localstate.Unmarshal(data, &proof); err != nil {
		return plan.FixtureIdentity{}, err
	}
	signature := proof.MAC
	proof.MAC = ""
	if proof.Version != Version || proof.Nonce != nonce || proof.Identity != c.Identity || !validMAC(c.credentials.ControlToken, proof, signature) {
		return plan.FixtureIdentity{}, fmt.Errorf("%w: fixture instance proof mismatch", safety.ErrDenied)
	}
	return proof.Identity, nil
}

func (c *Client) call(ctx context.Context, path string, input, output any) error {
	if _, err := c.Resolve(ctx); err != nil {
		return err
	}
	return c.control(ctx, path, input, output)
}

type ControlError struct{ Code string }

func (e *ControlError) Error() string        { return "authenticated fixture denial: " + e.Code }
func (e *ControlError) Is(target error) bool { return target == safety.ErrDenied }

type notSent struct{ error }

// ApplicationNotAttempted is true only for a locally unsent request or an
// authenticated denial. Transport/acknowledgment failures remain ambiguous.
func ApplicationNotAttempted(err error) bool {
	var denied *ControlError
	var unsent *notSent
	return errors.As(err, &denied) || errors.As(err, &unsent)
}

func (c *Client) control(ctx context.Context, path string, input, output any) error {
	if err := ctx.Err(); err != nil {
		return &notSent{err}
	}
	if err := plan.ValidateFixture(c.Identity); err != nil {
		return &notSent{err}
	}
	data, err := json.Marshal(input)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Identity.ControlURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	nonce := localstate.RandomID()
	request.Header.Set("X-Themis-Nonce", nonce)
	request.Header.Set("X-Themis-Signature", mac(c.credentials.ControlToken, requestProof(c.Identity.InstanceID, path, nonce, data)))
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err = io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil {
		return err
	}
	if len(data) > 65536 {
		return errors.New("fixture response too large")
	}
	var reply controlResponse
	if err := localstate.Unmarshal(data, &reply); err != nil {
		return err
	}
	signature := reply.MAC
	reply.MAC = ""
	if reply.Nonce != nonce || reply.Status != response.StatusCode || !validMAC(c.credentials.ControlToken, reply, signature) {
		return fmt.Errorf("%w: invalid fixture control response proof", safety.ErrDenied)
	}
	if reply.Status != 200 {
		var failure struct {
			Code string `json:"code"`
		}
		if localstate.Unmarshal(reply.Body, &failure) != nil || failure.Code == "" {
			return errors.New("invalid authenticated denial")
		}
		return &ControlError{failure.Code}
	}
	if output == nil {
		return nil
	}
	return localstate.Unmarshal(reply.Body, output)
}
func (c *Client) Authorize(ctx context.Context, p plan.ExperimentPlan, approved string) (safety.Authorization, error) {
	actor, err := localstate.CurrentActor()
	if err != nil {
		return safety.Authorization{}, err
	}
	var a safety.Authorization
	err = c.call(ctx, "/authorize", AuthorizeRequest{p.JSON(), approved, actor}, &a)
	return a, err
}
func (c *Client) Claim(ctx context.Context, a safety.Authorization, runID string) (FaultHandle, error) {
	var h FaultHandle
	err := c.call(ctx, "/claim", ClaimRequest{a, runID}, &h)
	return h, err
}
func (c *Client) Apply(ctx context.Context, h FaultHandle) (Receipt, error) {
	var r Receipt
	err := c.call(ctx, "/apply", ApplyRequest{h}, &r)
	return r, err
}

func (c *Client) ValidateClaim(ctx context.Context, h FaultHandle) error {
	return c.call(ctx, "/validate-claim", ApplyRequest{h}, nil)
}

// ApplyPrepared is used immediately after a synced intent. Scope and HMACs are
// still verified, without another preflight operation between intent and Apply.
func (c *Client) ApplyPrepared(ctx context.Context, h FaultHandle) (Receipt, error) {
	var r Receipt
	err := c.control(ctx, "/apply", ApplyRequest{h}, &r)
	return r, err
}
func (c *Client) Quiesce(ctx context.Context, h FaultHandle, reason string) error {
	return c.call(ctx, "/quiesce", QuiesceRequest{h, reason}, nil)
}
func (c *Client) StopRun(ctx context.Context, h FaultHandle) error {
	return c.call(ctx, "/stop-run", ApplyRequest{h}, nil)
}
func (c *Client) Remove(ctx context.Context, h FaultHandle) error {
	return c.call(ctx, "/remove", ApplyRequest{h}, nil)
}
func (c *Client) Stop(ctx context.Context) error { return c.call(ctx, "/stop", struct{}{}, nil) }
func (c *Client) Status(ctx context.Context) (Status, error) {
	if _, err := c.Resolve(ctx); err != nil {
		return Status{}, err
	}
	nonce := localstate.RandomID()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Identity.ControlURL+"/inspect?nonce="+nonce, nil)
	if err != nil {
		return Status{}, err
	}
	response, err := c.http.Do(req)
	if err != nil {
		return Status{}, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(data) > 65536 {
		return Status{}, errors.New("invalid inspection response")
	}
	var reply controlResponse
	if err := localstate.Unmarshal(data, &reply); err != nil {
		return Status{}, err
	}
	signature := reply.MAC
	reply.MAC = ""
	if reply.Nonce != nonce || reply.Status != 200 || response.StatusCode != 200 || !validMAC(c.credentials.ControlToken, reply, signature) {
		return Status{}, errors.New("invalid inspection proof")
	}
	var s Status
	if err := localstate.Unmarshal(reply.Body, &s); err != nil {
		return s, err
	}
	if s.Identity != c.Identity {
		return Status{}, errors.New("inspection identity mismatch")
	}
	return s, nil
}

// DataRequest exposes only fixed synthetic paths; no arbitrary URL forwarding.
func (c *Client) DataRequest(ctx context.Context, kind, requestID string) (*http.Response, error) {
	if err := plan.ValidateFixture(c.Identity); err != nil {
		return nil, err
	}
	if !plan.ValidInstanceID(requestID) {
		return nil, errors.New("invalid synthetic request ID")
	}
	endpoint := c.Identity.ServiceURL
	switch kind {
	case "direct":
		endpoint += "/dependency"
	case "proxy":
		endpoint = c.Identity.ProxyURL + "/dependency"
	case "application":
		endpoint += "/work"
	default:
		return nil, errors.New("unsupported synthetic request kind")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.credentials.DataToken)
	req.Header.Set("X-Themis-Request-ID", requestID)
	return c.http.Do(req)
}

func (c *Client) ListenersClosed(ctx context.Context) bool {
	for _, probe := range c.InspectListeners(ctx) {
		if probe.Outcome != "connection-refused" {
			return false
		}
	}
	return true
}

type ListenerState struct {
	Endpoint string `json:"endpoint"`
	Outcome  string `json:"outcome"`
}

func (c *Client) InspectListeners(ctx context.Context) []ListenerState {
	probes, _ := InspectIdentityListeners(ctx, c.Identity)
	return probes
}

func InspectIdentityListeners(ctx context.Context, id plan.FixtureIdentity) ([]ListenerState, error) {
	if err := plan.ValidateFixture(id); err != nil {
		return nil, err
	}
	var probes []ListenerState
	for _, endpoint := range []string{id.ServiceURL, id.ProxyURL, id.ControlURL} {
		address := endpoint[len("http://"):]
		dialer := net.Dialer{Timeout: 100 * time.Millisecond}
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			conn.Close()
			probes = append(probes, ListenerState{endpoint, "listening"})
			continue
		}
		outcome := "unknown"
		if ctx.Err() == nil && connectionRefused(err) {
			outcome = "connection-refused"
		}
		probes = append(probes, ListenerState{endpoint, outcome})
	}
	return probes, nil
}
