package dependencyhttp

import (
	"context"
	"io"
	"net/http"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/localstate"
)

type closeActionBody struct {
	io.ReadCloser
	after func()
}

func (b closeActionBody) Close() error {
	err := b.ReadCloser.Close()
	b.after()
	return err
}

type peerCloseAction struct {
	next  http.RoundTripper
	after func()
}

func (p peerCloseAction) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := p.next.RoundTrip(r)
	if err == nil && r.URL.Host == "10.0.0.3:8080" {
		response.Body = closeActionBody{response.Body, p.after}
	}
	return response, err
}

func TestInterruptedDurableProxyIntentCannotBeAppliedAgain(t *testing.T) {
	f := newFixture(t)
	a := f.authorize(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The final actual signed peer response is decoded successfully, then its
	// body Close cancels admission. The real journal still writes and syncs the
	// intent before mutate observes cancellation at its next boundary.
	f.proxy.peerClient.Transport = peerCloseAction{f.proxy.peerClient.Transport, cancel}
	first, err := f.proxy.mutate(ctx, NewCommand("apply", a, time.Now()))
	if err == nil || ctx.Err() == nil || first.Applied {
		t.Fatal("controlled cancellation did not reach pre-mutation admission")
	}
	prior, err := os.ReadFile(f.proxy.journal.Name())
	if err != nil || len(prior) != f.proxy.journalBytes {
		t.Fatal("actual durable intent unavailable", err)
	}
	repeated, err := f.proxy.mutate(context.Background(), NewCommand("apply", a, time.Now()))
	if err == nil || repeated.Applied || f.proxy.snapshot(a.Grant.Invocation).Applied {
		t.Fatal("interrupted durable Apply intent was reused for a new intervention")
	}
	later, err := os.ReadFile(f.proxy.journal.Name())
	if err != nil || string(prior) != string(later) {
		t.Fatal("denied retry appended a second Apply intent", err)
	}
}

func TestProxyJournalRejectsIdenticalBytesAtReplacementFileIdentity(t *testing.T) {
	f := newFixture(t)
	path := f.proxy.journal.Name()
	prior, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(path, path+".detached"); err != nil {
		if runtime.GOOS == "windows" {
			// Actual NTFS sharing semantics deny replacement of this open handle.
			// Linux exercises the replacement itself; do not weaken the file mode.
			t.Log("OBSERVED WINDOWS: open journal replacement denied by file sharing; Linux tests exercise successful rename")
			return
		}
		t.Fatal("supported local filesystem must permit observed identity test", err)
	}
	replacement, err := localstate.OpenNew(path)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := replacement.Write(prior); err != nil || n != len(prior) {
		t.Fatal("replacement bytes", n, err)
	}
	if err = replacement.Sync(); err != nil {
		t.Fatal(err)
	}
	if err = replacement.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.proxy.persist(struct{ Kind string }{"REPLACEMENT_PROBE"}); err == nil || !f.proxy.poisoned {
		t.Fatal("identical bytes at a new file identity bypassed the control journal guard")
	}
	a := f.authorize(t)
	if _, err = f.proxy.mutate(context.Background(), NewCommand("apply", a, time.Now())); err == nil {
		t.Fatal("replaced journal authorized mutation")
	}
}
