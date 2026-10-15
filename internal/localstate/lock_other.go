//go:build !windows && !linux && !darwin

package localstate

import (
	"errors"
	"os"
)

func tryLock(*os.File) (bool, error) { return false, errors.New("OS file locks unsupported") }
func unlock(*os.File) error          { return errors.New("OS file locks unsupported") }
