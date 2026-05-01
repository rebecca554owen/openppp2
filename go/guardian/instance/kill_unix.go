//go:build !windows

package instance

import (
	"os/exec"
	"syscall"
)

func killProcessGroup(pid int, sig syscall.Signal) error {
	return syscall.Kill(-pid, sig)
}

func forceKillProcessGroup(pid int) error {
	return syscall.Kill(-pid, syscall.SIGKILL)
}

func signalFromName(name string) syscall.Signal {
	switch name {
	case "interrupt", "sigint":
		return syscall.SIGINT
	case "terminate", "sigterm":
		return syscall.SIGTERM
	case "kill", "sigkill":
		return syscall.SIGKILL
	default:
		return syscall.SIGINT
	}
}

func setProcAttr(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}
