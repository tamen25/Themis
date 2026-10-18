package dependencyhttp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type controlledJournal struct {
	controlJournal
	write func([]byte) (int, error)
	sync  func() error
}

func (j controlledJournal) Write(b []byte) (int, error) {
	if j.write != nil {
		return j.write(b)
	}
	return j.controlJournal.Write(b)
}
func (j controlledJournal) Sync() error {
	if j.sync != nil {
		return j.sync()
	}
	return j.controlJournal.Sync()
}

func TestProxyActualShortWriteAndSyncFailurePoisonAdmission(t *testing.T) {
	for _, mode := range []string{"partial-write", "actual-closed-handle-sync"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			a := f.authorize(t)
			original := f.proxy.journal
			j := controlledJournal{controlJournal: original}
			if mode == "partial-write" {
				j.write = func(b []byte) (int, error) { return original.Write(b[:len(b)/2]) }
			} else {
				j.write = func(b []byte) (int, error) {
					n, err := original.Write(b)
					if err == nil {
						err = original.Close()
					}
					return n, err
				}
			}
			f.proxy.journal = j
			if _, err := f.proxy.mutate(context.Background(), NewCommand("apply", a, time.Now())); err == nil || !f.proxy.poisoned {
				t.Fatal("actual file failure did not poison admission")
			}
			if f.proxy.snapshot(a.Grant.Invocation).Applied {
				t.Fatal("failed intent changed response path")
			}
			f.proxy.journal = original
			if _, err := f.proxy.mutate(context.Background(), NewCommand("apply", a, time.Now())); err == nil {
				t.Fatal("poisoned writer resumed after replacing the wrapper")
			}
		})
	}
}

func TestProxyDiskStallCannotHoldExpiryOrRecoveredTraffic(t *testing.T) {
	f := newFixture(t)
	a := f.authorize(t)
	first, err := f.proxy.mutate(context.Background(), NewCommand("apply", a, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	original := f.proxy.journal
	f.proxy.journal = controlledJournal{controlJournal: original, sync: func() error {
		close(entered)
		<-release
		return original.Sync()
	}}
	done := make(chan error, 1)
	go func() {
		_, err := f.proxy.mutate(context.Background(), NewCommand("remove", a, time.Now()))
		done <- err
	}()
	<-entered
	time.Sleep(time.Until(f.proxy.boot.Add(time.Duration(first.DeadlineNS))) + 20*time.Millisecond)
	state := f.proxy.snapshot(a.Grant.Invocation)
	if state.Active || state.DeadlineNS != first.DeadlineNS || state.Reason != "expired" {
		t.Fatal("blocked control Sync controlled expiry", state)
	}
	client := HTTPClient()
	defer client.CloseIdleConnections()
	nonce := ID()
	reply, err := Fetch(context.Background(), client, f.appURL+"/value?nonce="+nonce)
	if err != nil || reply.Code != 200 || reply.Proxy == nil || reply.Proxy.HoldNS != 0 || reply.Proxy.State.Active {
		t.Fatal("actual application did not recover independently of blocked control storage", err)
	}
	once.Do(func() { close(release) })
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentProxyApplyRemoveExpiryRetainsOneEpoch(t *testing.T) {
	f := newFixture(t)
	a := f.authorize(t)
	results := make(chan State, 32)
	failures := make(chan error, 32)
	var group sync.WaitGroup
	for range 32 {
		group.Go(func() {
			state, err := f.proxy.mutate(context.Background(), NewCommand("apply", a, time.Now()))
			results <- state
			failures <- err
		})
	}
	group.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	var deadline int64
	for state := range results {
		if deadline == 0 {
			deadline = state.DeadlineNS
		}
		if !state.Applied || state.ApplyCount != 1 || state.DeadlineNS != deadline {
			t.Fatal("concurrent Apply changed original epoch", state)
		}
	}
	raw, err := os.ReadFile(f.proxy.journal.Name())
	if err != nil || strings.Count(string(raw), "\"Kind\":\"apply-INTENT\"") != 1 {
		t.Fatal("concurrent Apply wrote more than one intent", err)
	}
	time.Sleep(time.Until(f.proxy.boot.Add(time.Duration(deadline))) - 10*time.Millisecond)
	group.Go(func() {
		if _, err := f.proxy.mutate(context.Background(), NewCommand("remove", a, time.Now())); err != nil {
			t.Error(err)
		}
	})
	group.Go(func() { _ = f.proxy.snapshot(a.Grant.Invocation) })
	group.Wait()
	later, err := f.proxy.mutate(context.Background(), NewCommand("apply", a, time.Now()))
	if err != nil || later.Active || !later.Fenced || later.ApplyCount != 1 || later.DeadlineNS != deadline {
		t.Fatal("Remove/expiry/duplicate raced into a second intervention", later, err)
	}
}

func TestProxyBoundedRegistryAndControlJournalExhaustion(t *testing.T) {
	t.Run("64-invocations", func(t *testing.T) {
		f := newFixture(t)
		var last Authorization
		for range 64 {
			last = f.authorize(t)
			state, err := f.proxy.mutate(context.Background(), NewCommand("remove", last, time.Now()))
			if err != nil || !state.Fenced || state.Applied {
				t.Fatal("bounded pre-Apply fencing failed", len(f.proxy.epochs), err)
			}
		}
		if len(f.proxy.epochs) != 64 {
			t.Fatal("registry cap was not exercised")
		}
		next := f.authorize(t)
		if _, err := f.proxy.mutate(context.Background(), NewCommand("apply", next, time.Now())); err == nil {
			t.Fatal("registry admitted invocation beyond cap")
		}
		if _, err := f.proxy.mutate(context.Background(), NewCommand("remove", last, time.Now())); err != nil {
			t.Fatal("existing idempotent fence lost at registry capacity", err)
		}
	})
	t.Run("actual-bounded-file", func(t *testing.T) {
		f := newFixture(t)
		// Controlled nonmutating records fill the real private file; this is a
		// bounded storage equivalent, not an attempt to fill a host filesystem.
		for i := 0; i < 40; i++ {
			if err := f.proxy.persist(struct{ ControlledCapacity string }{strings.Repeat("x", 16<<10)}); err != nil {
				break
			}
		}
		info, err := os.Stat(f.proxy.journal.Name())
		if err != nil || !f.proxy.poisoned || info.Size() > 512<<10 || info.Size() < 480<<10 {
			t.Fatal("actual control file cap not enforced", info, err)
		}
		a := f.authorize(t)
		if _, err := f.proxy.mutate(context.Background(), NewCommand("apply", a, time.Now())); err == nil {
			t.Fatal("full control journal authorized mutation")
		}
	})
}

type heldTransport struct {
	next    http.RoundTripper
	release <-chan struct{}
}

func (p heldTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	select {
	case <-p.release:
		return p.next.RoundTrip(r)
	case <-r.Context().Done():
		return nil, r.Context().Err()
	}
}

func TestProxyActualHTTPHandlerCapacityIsBounded(t *testing.T) {
	f := newFixture(t)
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	f.proxy.client.Transport = heldTransport{f.proxy.client.Transport, release}
	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			response, err := http.Get(f.proxyURL + "/value?nonce=" + ID())
			if err == nil {
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
			}
		})
	}
	for deadline := time.Now().Add(time.Second); len(f.proxy.slots) != 16; {
		if time.Now().After(deadline) {
			once.Do(func() { close(release) })
			group.Wait()
			t.Fatal("actual concurrent handlers never filled the fixed slots")
		}
		time.Sleep(time.Millisecond)
	}
	response, err := http.Get(f.proxyURL + "/value?nonce=" + ID())
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusTooManyRequests || len(f.proxy.slots) > 16 {
		t.Fatal("seventeenth actual request bypassed handler capacity")
	}
	once.Do(func() { close(release) })
	group.Wait()
}

func TestProxyReadOnlyHandleReportsActualWriteError(t *testing.T) {
	f := newFixture(t)
	file, err := os.Open(f.proxy.journal.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	original := f.proxy.journal
	f.proxy.journal = file
	err = f.proxy.persist(struct{ Controlled string }{"read-only-file"})
	if err == nil || errors.Is(err, io.ErrShortWrite) || !f.proxy.poisoned {
		t.Fatal("actual read-only file write error not retained", err)
	}
	f.proxy.journal = original
}
