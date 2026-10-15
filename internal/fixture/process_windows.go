package fixture

import (
	"os/exec"
	"syscall"
)

func configureProcess(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000 | syscall.CREATE_NEW_PROCESS_GROUP}
}
