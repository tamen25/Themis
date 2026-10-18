package localstate

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestPrivatePublicationCrashChild(t *testing.T) {
	dir := os.Getenv("THEMIS_T44_PRIVATE_CRASH_DIR")
	if dir == "" {
		return
	}
	stage := os.Getenv("THEMIS_T44_PRIVATE_CRASH_STAGE")
	role := os.Getenv("THEMIS_T44_PRIVATE_CRASH_ROLE")
	err := writeNew(filepath.Join(dir, "record.json"), struct {
		Boundary string `json:"boundary"`
		Complete bool   `json:"complete"`
	}{role, true}, func(current string) error {
		if current == stage {
			if err := os.WriteFile(filepath.Join(dir, "ready"), []byte(current), 0600); err != nil {
				return err
			}
			<-time.After(time.Hour) // a live timer prevents runtime deadlock detection
		}
		return nil
	})
	t.Fatal("crash child unexpectedly returned", err)
}

func TestPrivateRecordPublicationActualProcessCrashCuts(t *testing.T) {
	// These are semantic representatives of the same actual protected publication
	// primitive, not claims that a whole Kubernetes workflow ran in this test.
	for _, role := range []string{"approval", "registration", "key-session-claim", "runner-intent", "apply-claim", "runner-final", "cleanup-receipt"} {
		for _, stage := range []string{"opened", "written", "synced", "linked", "directory-synced"} {
			t.Run(role+"/"+stage, func(t *testing.T) {
				dir, err := CreateDirectory(filepath.Join(t.TempDir(), "state"))
				if err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(os.Args[0], "-test.run=^TestPrivatePublicationCrashChild$")
				cmd.Env = append(os.Environ(), "THEMIS_T44_PRIVATE_CRASH_DIR="+dir, "THEMIS_T44_PRIVATE_CRASH_STAGE="+stage, "THEMIS_T44_PRIVATE_CRASH_ROLE="+role)
				var diagnostic bytes.Buffer
				cmd.Stdout, cmd.Stderr = &diagnostic, &diagnostic
				if err = cmd.Start(); err != nil {
					t.Fatal(err)
				}
				defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
				for deadline := time.Now().Add(10 * time.Second); ; {
					if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("actual publication checkpoint unavailable", diagnostic.String())
					}
					time.Sleep(5 * time.Millisecond)
				}
				if err = cmd.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				if err = cmd.Wait(); err == nil {
					t.Fatal("child was not interrupted")
				}
				raw, err := os.ReadFile(filepath.Join(dir, "record.json"))
				visible := stage == "linked" || stage == "directory-synced"
				if !visible {
					if !os.IsNotExist(err) {
						t.Fatal("pre-link crash exposed a final record", err)
					}
				} else {
					var record struct {
						Boundary string `json:"boundary"`
						Complete bool   `json:"complete"`
					}
					if err != nil || json.Unmarshal(raw, &record) != nil || record.Boundary != role || !record.Complete {
						t.Fatal("post-link crash exposed an incomplete final record", err)
					}
					if WriteNew(filepath.Join(dir, "record.json"), record) == nil {
						t.Fatal("crashed record was overwritten or implicitly resumed")
					}
				}
				t.Logf("ACTUAL LOCAL PROCESS DEATH role=%s cut=%s finalVisible=%t childExit=%d; file/directory sync is not a power-loss proof", role, stage, visible, cmd.ProcessState.ExitCode())
			})
		}
	}
}

func TestConcurrentPrivatePublishersExposeOneCompleteRecord(t *testing.T) {
	dir, err := CreateDirectory(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	type answer struct {
		id  int
		err error
	}
	done := make(chan answer, 16)
	for i := range 16 {
		go func() { done <- answer{i, WriteNew(filepath.Join(dir, "record.json"), struct{ ID int }{i})} }()
	}
	winner, successes := -1, 0
	for range 16 {
		r := <-done
		if r.err == nil {
			winner, successes = r.id, successes+1
		}
	}
	var record struct{ ID int }
	if Read(filepath.Join(dir, "record.json"), &record) != nil || successes != 1 || record.ID != winner {
		t.Fatal("concurrent private publication exposed partial or overwritten state")
	}
}
