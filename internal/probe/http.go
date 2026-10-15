// Package probe collects bounded HTTP observations without interpreting assertions.
package probe

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/tamen25/themis/internal/localpolicy"
)

// Observation contains status and timing only. Response headers and bodies are
// never retained. Offsets use the runner's monotonic clock, in nanoseconds.
type Observation struct {
	Index       int    `json:"index"`
	Phase       string `json:"phase"`
	StartedNS   int64  `json:"startedNS"`
	CompletedNS int64  `json:"completedNS"`
	StatusCode  int    `json:"statusCode"`
	Outcome     string `json:"outcome"`
}

// Client has a private transport: environment proxies, redirects, cookies,
// compression and connection reuse cannot expand the declared request scope.
type Client struct {
	client    *http.Client
	transport *http.Transport
}

func NewClient() *Client {
	t := &http.Transport{
		DialContext:       (&net.Dialer{Timeout: localpolicy.RequestTimeout}).DialContext,
		DisableKeepAlives: true, DisableCompression: true,
		TLSHandshakeTimeout: localpolicy.RequestTimeout, ResponseHeaderTimeout: localpolicy.RequestTimeout,
		MaxResponseHeaderBytes: localpolicy.MaxResponseHeaderBytes,
	}
	return &Client{transport: t, client: &http.Client{
		Transport: t, Timeout: localpolicy.RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (c *Client) Close() { c.transport.CloseIdleConnections() }

// Collect requires a URL from a validated, admitted local contract.
func (c *Client) Collect(ctx context.Context, url string, start time.Time) Observation {
	o := Observation{StartedNS: time.Since(start).Nanoseconds()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		o.Outcome = "invalid-request"
	} else {
		response, err := c.client.Do(req)
		switch {
		case err == nil:
			o.Outcome, o.StatusCode = "http", response.StatusCode
			response.Body.Close() // Status-only checks do not read unbounded bodies.
		case ctx.Err() != nil:
			o.Outcome = "cancelled"
		case errors.Is(err, context.DeadlineExceeded):
			o.Outcome = "timeout"
		default:
			o.Outcome = "transport-error"
		}
	}
	o.CompletedNS = time.Since(start).Nanoseconds()
	return o
}
