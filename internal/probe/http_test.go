package probe_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/probe"
)

func TestHTTPObservationScope(t *testing.T) {
	var escaped atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { escaped.Add(1) }))
	defer other.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.Header.Get("Accept-Encoding") != "" || r.Header.Get("Cookie") != "" {
			t.Error("unexpected method, compression or cookies")
		}
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer server.Close()
	t.Setenv("HTTP_PROXY", other.URL)
	t.Setenv("HTTPS_PROXY", other.URL)
	client := probe.NewClient()
	defer client.Close()
	o := client.Collect(context.Background(), server.URL, time.Now())
	if o.Outcome != "http" || o.StatusCode != 302 || escaped.Load() != 0 || o.CompletedNS < o.StartedNS {
		t.Fatalf("observation=%+v escaped=%d", o, escaped.Load())
	}
}

func TestHTTPDoesNotReadBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done() // Body never completes; collector must still return.
	}))
	defer server.Close()
	client := probe.NewClient()
	defer client.Close()
	o := client.Collect(context.Background(), server.URL, time.Now())
	if o.Outcome != "http" || o.StatusCode != 200 {
		t.Fatalf("%+v", o)
	}
}

func TestHTTPErrors(t *testing.T) {
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer tls.Close()
	largeHeaders := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("X-Large", strings.Repeat("x", 64<<10)) }))
	defer largeHeaders.Close()
	client := probe.NewClient()
	defer client.Close()
	for _, url := range []string{tls.URL, largeHeaders.URL} {
		o := client.Collect(context.Background(), url, time.Now())
		if o.Outcome != "transport-error" || o.StatusCode != 0 {
			t.Fatalf("%s: %+v", url, o)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if o := client.Collect(ctx, largeHeaders.URL, time.Now()); o.Outcome != "cancelled" {
		t.Fatalf("%+v", o)
	}
}

func TestHTTPTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	client := probe.NewClient()
	defer client.Close()
	o := client.Collect(context.Background(), server.URL, time.Now())
	if o.Outcome != "timeout" || o.StatusCode != 0 {
		t.Fatalf("%+v", o)
	}
}
