//go:build !windows

package postgres

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func backupFileIdentity(f *os.File) (string, error) {
	s, e := f.Stat()
	if e != nil {
		return "", e
	}
	v, ok := s.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("stable backup file identity unsupported")
	}
	return fmt.Sprintf("unix:%d:%d", v.Dev, v.Ino), nil
}
