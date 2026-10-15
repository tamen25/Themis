//go:build !windows && !linux && !darwin

package fixture

import "os/exec"

func configureProcess(*exec.Cmd) {}
