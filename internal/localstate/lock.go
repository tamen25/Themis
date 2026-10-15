package localstate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Lock uses an OS-held file lock. Process death releases ownership; no PID or
// stale timestamp is interpreted as permission to take over a running process.
type Lock struct {
	file *os.File
	held bool
}

func OpenLock(path string, create bool) (*Lock, error) {
	if err := Check(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if create {
		f, err := OpenNew(path)
		if err == nil {
			_ = f.Close()
		} else if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	if err := Check(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return &Lock{file: f}, nil
}

func (l *Lock) Try() (bool, error) {
	if l.held {
		return true, nil
	}
	held, err := tryLock(l.file)
	l.held = held
	return held, err
}
func (l *Lock) Acquire(ctx context.Context) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		held, err := l.Try()
		if err != nil {
			return err
		}
		if held {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func (l *Lock) Close() error {
	if l.held {
		if err := unlock(l.file); err != nil {
			_ = l.file.Close()
			return err
		}
		l.held = false
	}
	return l.file.Close()
}
