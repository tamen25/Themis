//go:build !windows && !linux && !darwin

package localstate

import (
	"errors"
	"os"
)

func protect(string, bool) error {
	return errors.New("experimental local authorization is unsupported on this OS")
}
func checkPrivate(string, os.FileInfo) error {
	return errors.New("experimental local authorization is unsupported on this OS")
}
func SyncDirectory(string) error { return errors.New("unsupported OS") }
