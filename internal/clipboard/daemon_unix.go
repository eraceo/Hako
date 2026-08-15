//go:build !windows

package clipboard

import (
	"os/exec"
	"syscall"
)

func prepareDaemonCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
}

func killProcess(pid int) error {
	return syscall.Kill(pid, syscall.SIGTERM)
}
