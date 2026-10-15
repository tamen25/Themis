package localstate_test

import (
	"context"
	"github.com/tamen25/themis/internal/localstate"
	"path/filepath"
	"testing"
	"time"
)

func TestOSLockOwnershipAndDeadline(t *testing.T) {
	dir, err := localstate.CreateDirectory(filepath.Join(t.TempDir(), "private"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ownership.lock")
	first, err := localstate.OpenLock(path, true)
	if err != nil {
		t.Fatal(err)
	}
	second, err := localstate.OpenLock(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if acquired, err := first.Try(); err != nil || !acquired {
		t.Fatalf("first lock: %v", err)
	}
	if acquired, err := second.Try(); err != nil || acquired {
		t.Fatalf("lock did not exclude another handle: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := second.Acquire(ctx); err == nil {
		t.Fatal("lock wait ignored deadline")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if acquired, err := second.Try(); err != nil || !acquired {
		t.Fatalf("released ownership not available: %v", err)
	}
}
