package dependencyhttp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFixedEgressRedirectAndResponseBounds(t *testing.T) {
	var hits atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(strings.Repeat("x", MaxBody+1)))
	}))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 302) }))
	defer redirect.Close()
	c := HTTPClient()
	defer c.CloseIdleConnections()
	if _, e := Fetch(context.Background(), c, redirect.URL); e == nil || hits.Load() != 0 {
		t.Fatal("HTTP redirect followed")
	}
	if _, e := Fetch(context.Background(), c, destination.URL); e == nil {
		t.Fatal("unbounded response accepted")
	}
	f := newFixture(t)
	s, e := NewServer(f.servers[0].config, "application", uid(99), t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	prior := hits.Load()
	if _, e = s.client.Get(destination.URL); e == nil || hits.Load() != prior {
		t.Fatal("application gained arbitrary egress")
	}
}
func TestLostApplyAndDelayedRemoveAcknowledgementsDoNotRenew(t *testing.T) {
	f := newFixture(t)
	a := f.authorize(t)
	processed := make(chan struct{}, 2)
	delayed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := httptest.NewRecorder()
		f.proxy.ServeHTTP(recorder, r)
		processed <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		} // controlled acknowledgement loss only
		for key, values := range recorder.Header() {
			w.Header()[key] = values
		}
		w.WriteHeader(recorder.Code)
		_, _ = io.Copy(w, recorder.Body)
	}))
	defer delayed.Close()
	c := HTTPClient()
	defer c.CloseIdleConnections()
	issue := func(action string) {
		t.Helper()
		cmd := NewCommand(action, a, time.Now())
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		req, e := http.NewRequestWithContext(ctx, "POST", delayed.URL+"/control?nonce="+cmd.Nonce, bytes.NewReader(JSON(cmd)))
		if e != nil {
			t.Fatal(e)
		}
		result := make(chan error, 1)
		go func() {
			response, err := c.Do(req)
			if response != nil {
				_ = response.Body.Close()
			}
			result <- err
		}()
		select {
		case <-processed:
		case <-time.After(2 * time.Second):
			t.Fatal("actual control did not complete before loss simulation")
		}
		cancel()
		if err := <-result; err == nil {
			t.Fatal("expected lost acknowledgement")
		}
	}
	issue("apply")
	first := f.proxy.snapshot(a.Grant.Invocation)
	if !first.Applied || !first.Active || first.ApplyCount != 1 {
		t.Fatal("Apply was not actually committed before acknowledgement loss")
	}
	duplicate, e := f.proxy.mutate(context.Background(), NewCommand("apply", a, time.Now()))
	if e != nil || duplicate.DeadlineNS != first.DeadlineNS || duplicate.ApplyCount != 1 {
		t.Fatal("ambiguous Apply was renewed")
	}
	issue("remove")
	removed := f.proxy.snapshot(a.Grant.Invocation)
	if removed.Active || !removed.Fenced || removed.ApplyCount != 1 {
		t.Fatal("delayed Remove acknowledgement left injection active")
	}
}
