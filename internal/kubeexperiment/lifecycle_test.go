package kubeexperiment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tamen25/themis/internal/kubefault"
	"github.com/tamen25/themis/internal/localstate"
	"github.com/tamen25/themis/internal/result"
	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func executionFixture(t *testing.T) (*Cluster, kubefault.Plan, kubefault.Authorization) {
	t.Helper()
	c, p := clusterFixture(t)
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	c.Owner.ApproverKey = hex.EncodeToString(public)
	c.StateDirectory, _ = localstate.CreateDirectory(filepath.Join(t.TempDir(), "state"))
	s, err := kubefault.NewServer(kubefault.Config{ClusterUID: c.Owner.ClusterUID, NamespaceUID: c.Owner.NamespaceUID, ApproverKey: c.Owner.ApproverKey, Operator: c.Owner.Operator}, p.Target.Fixture.PodName, p.Target.Fixture.PodUID)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.Serve(ctx, listener) }()
	p.Target.Fixture = s.Identity
	c.forwardPod = func(context.Context, string) (*Session, error) {
		client, err := kubefault.NewClient("http://" + listener.Addr().String())
		return &Session{Client: client, stop: make(chan struct{})}, err
	}
	a, err := kubefault.Approve(p, p.Digest(), key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return c, p, a
}

type pausedWrite struct {
	journalFile
	match            string
	entered, release chan struct{}
	once             sync.Once
}

func (f *pausedWrite) Write(data []byte) (int, error) {
	if bytes.Contains(data, []byte(f.match)) {
		f.once.Do(func() { close(f.entered); <-f.release })
	}
	return f.journalFile.Write(data)
}

// Actual local HTTP and OS file locks with controlled API reads. The live Kind
// suite separately runs the real CLI from independent OS processes.
func TestCancellationAtEachDurableLifecycleBoundary(t *testing.T) {
	for _, phase := range []string{"BASELINE", "INTENT", "APPLIED", "REMOVED", "RECOVERY", "FINAL"} {
		t.Run(phase, func(t *testing.T) {
			c, p, a := executionFixture(t)
			root := filepath.Join(c.StateDirectory, "runs")
			dir := filepath.Join(root, "run-"+a.Grant.InvocationID)
			pause := &pausedWrite{match: `"type":"` + phase + `"`, entered: make(chan struct{}), release: make(chan struct{})}
			var release sync.Once
			defer release.Do(func() { close(pause.release) })
			type outcome struct {
				report Report
				err    error
			}
			done := make(chan outcome, 1)
			go func() {
				r, _, err := c.executeWithStorage(context.Background(), p, a, root, func(path string) (journalFile, error) {
					f, err := localstate.OpenNew(path)
					pause.journalFile = f
					return pause, err
				})
				done <- outcome{r, err}
			}()
			select {
			case <-pause.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("runner never reached", phase)
			}
			action := make(chan CleanupReceipt, 1)
			actionError := make(chan error, 1)
			go func() { r, err := c.Cancel(context.Background(), dir); action <- r; actionError <- err }()
			// Apply and FINAL own the same gate. At other boundaries cancellation
			// must acknowledge while the runner remains paused on an actual write.
			if phase == "INTENT" || phase == "APPLIED" || phase == "FINAL" {
				release.Do(func() { close(pause.release) })
			}
			var receipt CleanupReceipt
			select {
			case receipt = <-action:
			case <-time.After(8 * time.Second):
				t.Fatal("cancellation did not complete")
			}
			if err := <-actionError; err != nil || receipt.OperationalState != "CLEANUP_COMPLETE" {
				t.Fatal("cancellation cleanup failed", err, receipt.Failure)
			}
			release.Do(func() { close(pause.release) })
			var finished outcome
			select {
			case finished = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("runner did not finalize")
			}
			if finished.err != nil {
				t.Fatal(finished.err)
			}
			if phase == "FINAL" {
				if !receipt.Action.AlreadyFinalized || finished.report.Verdict != result.Pass {
					t.Fatal("late action rewrote historical PASS", finished.report.Unknowns)
				}
			} else if receipt.Action.AlreadyFinalized || finished.report.Verdict == result.Pass || !finished.report.CancellationAccepted || finished.report.Execution != result.Cancelled {
				t.Fatal("accepted cancellation did not prevent PASS", finished.report.Execution, finished.report.Unknowns)
			}
			before, _ := os.ReadFile(filepath.Join(dir, "events.jsonl"))
			again, err := c.Cancel(context.Background(), dir)
			after, _ := os.ReadFile(filepath.Join(dir, "events.jsonl"))
			if err != nil || again.OperationalState != "CLEANUP_COMPLETE" || !bytes.Equal(before, after) {
				t.Fatal("duplicate cancellation changed history or cleanup", err)
			}
			s, err := c.Connect(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			status, err := s.Client.Control(context.Background(), a, "apply")
			if err == nil && (status.Active || status.ApplyCount > 1) {
				t.Fatal("canceled invocation applied or renewed")
			}
			if phase == "BASELINE" && !errors.Is(err, kubefault.ErrDenied) {
				t.Fatal("pre-Apply fence missing", err)
			}
		})
	}
}

func recordedInventory(t *testing.T, c *Cluster, p kubefault.Plan, a kubefault.Authorization) string {
	t.Helper()
	dir, err := localstate.CreateDirectory(filepath.Join(c.StateDirectory, "run-"+a.Grant.InvocationID))
	if err != nil {
		t.Fatal(err)
	}
	if err = writePrivate(filepath.Join(dir, "inventory.json"), inventory{Version: InventoryVersion, Plan: p, Authorization: a, StateDirectory: c.StateDirectory}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestReceiptPublicationFailureIsOperationallyPending(t *testing.T) {
	c, p, a := executionFixture(t)
	dir := recordedInventory(t, c, p, a)
	r, err := c.action(context.Background(), dir, "cancel", func(path string, value any) error {
		if strings.HasPrefix(filepath.Base(path), "cleanup-") {
			return io.ErrClosedPipe
		}
		return writePrivate(path, value)
	})
	if !errors.Is(err, ErrReceiptPublication) || r.CurrentState != "INACTIVE" || r.OperationalState != "CLEANUP_PENDING" || r.ReceiptPersisted == nil || *r.ReceiptPersisted {
		t.Fatal("receipt loss silently succeeded", err)
	}
	if _, err = c.Cancel(context.Background(), dir); err != nil {
		t.Fatal("idempotent retry did not publish", err)
	}
}

func TestMissingCorruptAndMisboundInventoryNeverControlsTarget(t *testing.T) {
	for _, kind := range []string{"missing", "corrupt", "plan mismatch", "authorization mismatch", "copied directory"} {
		t.Run(kind, func(t *testing.T) {
			c, p, a := executionFixture(t)
			dir := recordedInventory(t, c, p, a)
			path := filepath.Join(dir, "inventory.json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "missing":
				err = os.Remove(path)
			case "corrupt":
				err = os.WriteFile(path, []byte("{"), 0600)
			case "copied directory":
				other, e := localstate.CreateDirectory(filepath.Join(c.StateDirectory, "copied"))
				if e != nil {
					t.Fatal(e)
				}
				err = writePrivate(filepath.Join(other, "inventory.json"), json.RawMessage(data))
				dir = other
			default:
				var inv inventory
				_ = json.Unmarshal(data, &inv)
				if kind == "plan mismatch" {
					inv.Plan.Scenario = "buggy"
				} else {
					inv.Authorization.Grant.Signature = "00"
				}
				data, _ = json.Marshal(inv)
				err = os.WriteFile(path, data, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			forwarded := false
			original := c.forwardPod
			c.forwardPod = func(ctx context.Context, name string) (*Session, error) { forwarded = true; return original(ctx, name) }
			if _, err = c.Cancel(context.Background(), dir); err == nil || forwarded {
				t.Fatal("invalid inventory reached control")
			}
		})
	}
}

func TestStatusIsReadOnlyAndCorruptHistoryCannotGainTrust(t *testing.T) {
	c, p, a := executionFixture(t)
	dir := recordedInventory(t, c, p, a)
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte("corrupt\n"), 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadDir(dir)
	r, err := c.Inspect(context.Background(), dir)
	after, _ := os.ReadDir(dir)
	if err != nil || r.JournalValid || r.RecordedVerdict == result.Pass || r.Current.ResidualIntervention != "ABSENT" || len(before) != len(after) {
		t.Fatal("fresh state authenticated corrupt history or wrote local state", err)
	}
	receipt, err := c.Cancel(context.Background(), dir)
	if err != nil || receipt.OperationalState != "CLEANUP_COMPLETE" || !receipt.RecoveryVerified {
		t.Fatal("corrupt journal removed protected cleanup authority", err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if string(data) != "corrupt\n" {
		t.Fatal("corrupt history rewritten")
	}
}

func TestOriginalBootCleanupSurvivesWorkloadGenerationDrift(t *testing.T) {
	c, p, a := executionFixture(t)
	dir := recordedInventory(t, c, p, a)
	s, err := c.Connect(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.Client.Control(context.Background(), a, "apply"); err != nil {
		t.Fatal(err)
	}
	dep := &appsv1.Deployment{}
	if err = c.Reader.Get(context.Background(), client.ObjectKey{Namespace: p.Target.Namespace, Name: p.Target.DeploymentName}, dep); err != nil {
		t.Fatal(err)
	}
	dep.Generation++
	if err = c.Reader.Update(context.Background(), dep); err != nil {
		t.Fatal(err)
	}
	if err = c.Revalidate(context.Background(), p); err == nil {
		t.Fatal("drift did not forbid execution")
	}
	r, err := c.Cancel(context.Background(), dir)
	if err != nil || r.OperationalState != "CLEANUP_COMPLETE" || !r.RecoveryVerified {
		t.Fatal("safe original-boot cleanup depended on stale execution generation", err)
	}
}
