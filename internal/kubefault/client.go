package kubefault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	base string
	http *http.Client
}

func NewClient(base string) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return nil, ErrDenied
	}
	t := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 8192, MaxConnsPerHost: 8}
	return &Client{base, &http.Client{Transport: t, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) Close() { c.http.CloseIdleConnections() }

func (c *Client) request(ctx context.Context, method, path string, input any, requestID string) ([]byte, int, error) {
	var body io.Reader
	if input != nil {
		b, err := json.Marshal(input)
		if err != nil {
			return nil, 0, err
		}
		body = bytes.NewReader(b)
	}
	r, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, 0, err
	}
	if requestID != "" {
		r.Header.Set("X-Themis-Request-ID", requestID)
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(r)
	if err != nil {
		return nil, 0, errors.New("fixture request failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(data) > 65536 {
		return nil, 0, errors.New("fixture response invalid or oversized")
	}
	return data, response.StatusCode, nil
}

func (c *Client) Resolve(ctx context.Context, expected *Identity) (Identity, error) {
	nonce := RandomID()
	data, code, err := c.request(ctx, http.MethodGet, "/identity?nonce="+nonce, nil, "")
	if err != nil {
		return Identity{}, err
	}
	var reply Reply
	if Decode(data, &reply) != nil {
		return Identity{}, ErrDenied
	}
	sig := reply.Signature
	reply.Signature = ""
	if code != 200 || reply.HTTPCode != code || reply.Nonce != nonce || reply.Identity.Version != Version || !Verify("themis.kubernetes-reply/v1alpha1", reply, sig, reply.Identity.EvidenceKey) || (expected != nil && *expected != reply.Identity) {
		return Identity{}, ErrDenied
	}
	return reply.Identity, nil
}

type Denial struct{ Code string }

func (d *Denial) Error() string     { return "authenticated fixture denial: " + d.Code }
func (d *Denial) Is(err error) bool { return err == ErrDenied }

func (c *Client) Control(ctx context.Context, a Authorization, action string) (Status, error) {
	command, err := NewCommand(a, action)
	if err != nil {
		return Status{}, err
	}
	data, code, err := c.request(ctx, http.MethodPost, "/control", command, "")
	if err != nil {
		return Status{}, err
	} // application may have occurred: never retry as new Apply
	var reply Reply
	if Decode(data, &reply) != nil {
		return Status{}, ErrDenied
	}
	sig := reply.Signature
	reply.Signature = ""
	if reply.Nonce != command.Nonce || reply.Identity != a.Grant.Plan.Target.Fixture || reply.HTTPCode != code || !Verify("themis.kubernetes-reply/v1alpha1", reply, sig, reply.Identity.EvidenceKey) {
		return Status{}, ErrDenied
	}
	if code != 200 {
		return reply.Status, &Denial{reply.Error}
	}
	if reply.Status.InvocationID != a.Grant.InvocationID {
		return Status{}, ErrDenied
	}
	reply.Status.Proof = &ControlProof{Nonce: reply.Nonce, HTTPCode: reply.HTTPCode, Error: reply.Error, Signature: sig}
	return reply.Status, nil
}

func (c *Client) Data(ctx context.Context, kind, id string) (Data, int, error) {
	if kind != "direct" && kind != "proxy" && kind != "application" {
		return Data{}, 0, ErrDenied
	}
	data, code, err := c.request(ctx, http.MethodGet, "/"+kind, nil, id)
	if err != nil {
		return Data{}, 0, err
	}
	var response Data
	if Decode(data, &response) != nil {
		return Data{}, 0, ErrDenied
	}
	return response, code, nil
}
