package experiment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/fixture"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
)

type interceptStorage struct {
	diskStorage
	writeEvent  func(Event) error
	syncEvent   func(Event) error
	writeRecord func(string, any) error
	tearEvent   State
}

func (s interceptStorage) OpenJournal(path string) (journalFile, error) {
	f, err := s.diskStorage.OpenJournal(path)
	if err != nil {
		return nil, err
	}
	return &interceptJournal{journalFile: f, storage: s}, nil
}
func (s interceptStorage) WriteRecord(path string, value any) error {
	if s.writeRecord != nil {
		return s.writeRecord(path, value)
	}
	return localstate.WriteNew(path, value)
}

type interceptJournal struct {
	journalFile
	storage interceptStorage
	last    Event
}

func (j *interceptJournal) Write(data []byte) (int, error) {
	if err := json.Unmarshal(data, &j.last); err != nil {
		return 0, err
	}
	if j.storage.writeEvent != nil {
		if err := j.storage.writeEvent(j.last); err != nil {
			return 0, err
		}
	}
	if j.last.State == j.storage.tearEvent {
		n, err := j.journalFile.Write(data[:len(data)/2])
		if err == nil {
			err = j.journalFile.Sync()
		}
		if err != nil {
			return n, err
		}
		return n, io.ErrUnexpectedEOF
	}
	return j.journalFile.Write(data)
}
func (j *interceptJournal) Sync() error {
	if j.storage.syncEvent != nil {
		if err := j.storage.syncEvent(j.last); err != nil {
			return err
		}
	}
	return j.journalFile.Sync()
}

type interceptHTTP struct {
	base       http.RoundTripper
	directHost string
	delay      time.Duration
	dropAck    bool
	applies    atomic.Int32
	applied    func()
}

func (t *interceptHTTP) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == "/dependency" && r.URL.Host == t.directHost && t.delay > 0 {
		timer := time.NewTimer(t.delay)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			return nil, r.Context().Err()
		case <-timer.C:
		}
	}
	if r.URL.Path == "/apply" {
		t.applies.Add(1)
	}
	response, err := t.base.RoundTrip(r)
	if err == nil && r.URL.Path == "/apply" && t.dropAck {
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if t.applied != nil {
			t.applied()
		}
		return nil, errors.New("controlled lost application acknowledgment")
	}
	return response, err
}
func (t *interceptHTTP) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func journalEvents(t *testing.T, directory string) []Event {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(directory, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var events []Event
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var e Event
		if json.Unmarshal(line, &e) != nil {
			break
		}
		events = append(events, e)
	}
	return events
}
func hasState(events []Event, state State) bool {
	for _, e := range events {
		if e.State == state {
			return true
		}
	}
	return false
}

func TestBaselineAndRevalidationBeforeIntent(t *testing.T) {
	for _, test := range []string{"baseline rejected", "claim fenced", "target gone"} {
		t.Run(test, func(t *testing.T) {
			c, p, a, root := setup(t, "healthy")
			_, transport := fixture.NewHTTPClient()
			defer transport.CloseIdleConnections()
			httpBoundary := &interceptHTTP{base: transport}
			storage := interceptStorage{}
			if test == "baseline rejected" {
				endpoint, _ := url.Parse(c.Identity.ServiceURL)
				httpBoundary.directHost = endpoint.Host
				httpBoundary.delay = 70 * time.Millisecond
			}
			if test == "claim fenced" {
				storage.syncEvent = func(e Event) error {
					if e.State == Revalidating {
						var inventory Inventory
						if err := localstate.Read(filepath.Join(root, "runs", "run-"+e.RunID, "resources.json"), &inventory); err != nil {
							return err
						}
						return c.Quiesce(context.Background(), inventory.Manifest.Handle, "cleanup")
					}
					return nil
				}
			}
			if test == "target gone" {
				process, err := os.FindProcess(c.Identity.PID)
				if err != nil {
					t.Fatal(err)
				}
				defer process.Release()
				storage.syncEvent = func(e Event) error {
					if e.State == Revalidating {
						return process.Kill()
					}
					return nil
				}
			}
			r, dir, err := executeUsing(context.Background(), p, a, cDirectory(root), filepath.Join(root, "runs"), storage, func(directory string) (*fixture.Client, error) {
				return fixture.OpenWithTransport(directory, httpBoundary)
			})
			if err != nil {
				t.Fatal(err)
			}
			if r.FaultAttempted == nil || *r.FaultAttempted || r.Verdict == result.Pass || httpBoundary.applies.Load() != 0 || hasState(journalEvents(t, dir), Intent) {
				t.Fatalf("fault intent/application after rejected prerequisites: %+v", r)
			}
			if r.Execution.Error == nil || r.Failure == nil {
				t.Fatal("missing explicit rejection reason")
			}
		})
	}
}

func TestJournalFailureBeforeApply(t *testing.T) {
	_, p, a, root := setup(t, "healthy")
	_, transport := fixture.NewHTTPClient()
	defer transport.CloseIdleConnections()
	httpBoundary := &interceptHTTP{base: transport}
	storage := interceptStorage{writeEvent: func(e Event) error {
		if e.State == Intent {
			return errors.New("controlled intent writer failure")
		}
		return nil
	}}
	r, dir, err := executeUsing(context.Background(), p, a, cDirectory(root), filepath.Join(root, "runs"), storage, func(directory string) (*fixture.Client, error) {
		return fixture.OpenWithTransport(directory, httpBoundary)
	})
	if err == nil || r.FaultAttempted == nil || *r.FaultAttempted || httpBoundary.applies.Load() != 0 || r.Verdict == result.Pass {
		t.Fatalf("intent write failure did not prevent Apply: %+v %v", r, err)
	}
	status, statusErr := Inspect(context.Background(), dir)
	if statusErr != nil || !status.InventoryUsable || status.Application != NotAttempted || status.LastFailure == nil || status.LastFailure.Failure.Operation != OpIntent {
		t.Fatalf("failure status: %+v %v", status, statusErr)
	}
}

func TestTornIntentNeverApplies(t *testing.T) {
	_, p, a, root := setup(t, "healthy")
	r, dir, err := execute(context.Background(), p, a, cDirectory(root), filepath.Join(root, "runs"), interceptStorage{tearEvent: Intent})
	if err == nil || r.FaultAttempted == nil || *r.FaultAttempted || r.Verdict == result.Pass {
		t.Fatalf("torn intent did not prevent application: %+v %v", r, err)
	}
	if _, err := ReplayFile(filepath.Join(dir, "events.jsonl")); err == nil {
		t.Fatal("strict replay accepted a torn record")
	}
	s, err := Inspect(context.Background(), dir)
	if err != nil || s.Journal.Integrity != JournalTorn || s.Journal.LastState != Revalidating || !s.InventoryUsable || s.Application != NotAttempted {
		t.Fatalf("torn intent inspection: %+v %v", s, err)
	}
	clean, err := Reconcile(dir)
	if err != nil || !clean.Completed || clean.RecoveryVerified {
		t.Fatalf("torn journal reconciliation: %+v %v", clean, err)
	}
}

func TestAmbiguousApplicationAcknowledgment(t *testing.T) {
	c, p, a, root := setup(t, "healthy")
	_, transport := fixture.NewHTTPClient()
	defer transport.CloseIdleConnections()
	var realApplyCount int
	httpBoundary := &interceptHTTP{base: transport, dropAck: true, applied: func() {
		s, err := c.Status(context.Background())
		if err != nil {
			t.Error(err)
		}
		realApplyCount = s.ApplyCount
	}}
	r, dir, err := executeUsing(context.Background(), p, a, cDirectory(root), filepath.Join(root, "runs"), diskStorage{}, func(directory string) (*fixture.Client, error) {
		return fixture.OpenWithTransport(directory, httpBoundary)
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.FaultAttempted != nil || r.Verdict == result.Pass || realApplyCount != 1 || !hasState(journalEvents(t, dir), Intent) || hasState(journalEvents(t, dir), Applied) {
		t.Fatalf("lost real acknowledgment misclassified: %+v", r)
	}
	replayed, err := ReplayFile(filepath.Join(dir, "events.jsonl"))
	if err != nil || replayed.FaultAttempted != nil {
		t.Fatalf("ambiguity was lost in replay: %v", err)
	}
}

func TestStalledWriterCannotExtendFault(t *testing.T) {
	c, p, a, root := setup(t, "healthy")
	blocked := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	storage := interceptStorage{syncEvent: func(e Event) error {
		if e.State == Applied {
			close(blocked)
			<-release
			return errors.New("controlled stalled acknowledgment writer")
		}
		return nil
	}}
	type outcome struct {
		r   Report
		dir string
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		r, dir, err := execute(context.Background(), p, a, cDirectory(root), filepath.Join(root, "runs"), storage)
		done <- outcome{r, dir, err}
	}()
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("writer did not reach applied state")
	}
	state, err := c.Status(context.Background())
	if err != nil || state.ActiveFault == nil || state.Claim == nil || state.Claim.Receipt == nil {
		t.Fatalf("no active real fault: %v", err)
	}
	timer := time.NewTimer(time.Until(state.Claim.Receipt.FaultExpiresAt) + 200*time.Millisecond)
	defer timer.Stop()
	<-timer.C
	state, err = c.Status(context.Background())
	if err != nil || state.ActiveFault != nil || state.ApplyCount != 1 {
		t.Fatalf("stalled writer extended fault expiry: %+v %v", state, err)
	}
	select {
	case <-done:
		t.Fatal("test writer unexpectedly resumed")
	default:
	}
	unblock()
	select {
	case got := <-done:
		if got.err == nil || got.r.Verdict == result.Pass || got.r.FaultAttempted == nil || !*got.r.FaultAttempted || got.r.Failure == nil || got.r.Failure.Operation != OpAcknowledge {
			t.Fatalf("stalled writer diagnostic: %+v %v", got.r, got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runner did not reconcile after writer release")
	}
}

func TestCleanupReceiptPersistenceFailure(t *testing.T) {
	_, p, a, root := setup(t, "healthy")
	storage := interceptStorage{writeRecord: func(path string, value any) error {
		if strings.HasPrefix(filepath.Base(path), "cleanup-") {
			return errors.New("controlled cleanup receipt persistence failure")
		}
		return localstate.WriteNew(path, value)
	}}
	r, dir, err := execute(context.Background(), p, a, cDirectory(root), filepath.Join(root, "runs"), storage)
	if err == nil || r.Execution.Status != result.CleanupPending || r.Verdict == result.Pass || r.Failure == nil || r.Failure.Code != "CLEANUP_RECEIPT_WRITE_FAILED" {
		t.Fatalf("receipt failure hidden: %+v %v", r, err)
	}
	status, err := Inspect(context.Background(), dir)
	if err != nil || !residualsClosed(status.Live.Residuals) || !status.ReconciliationNecessary {
		t.Fatalf("receipt failure status: %+v %v", status, err)
	}
	for range 2 {
		receipt, err := Reconcile(dir)
		if err != nil || !receipt.Completed {
			t.Fatalf("temporary storage failure did not reconcile: %+v %v", receipt, err)
		}
	}
	status, err = Inspect(context.Background(), dir)
	if err != nil || status.ReconciliationNecessary || status.ExecutionDisposition != result.ExecutionStatus("FINALIZED_WITH_RECONCILED_CLEANUP") || status.History.OriginalExecution == nil || status.History.OriginalExecution.Status != result.CleanupPending {
		t.Fatalf("historical pending result was conflated with current cleanup: %+v %v", status, err)
	}
	failed, err := reconcile(context.Background(), dir, CleanupAction, storage.WriteRecord)
	if err == nil || !failed.Completed || failed.Disposition != Pending || failed.ReceiptPersisted == nil || *failed.ReceiptPersisted || failed.Failure == nil || failed.Failure.Operation != OpReceipt {
		t.Fatalf("external cleanup hid receipt failure: %+v %v", failed, err)
	}
	if retried, err := Reconcile(dir); err != nil || !retried.Completed {
		t.Fatalf("external cleanup did not recover: %+v %v", retried, err)
	}
}
