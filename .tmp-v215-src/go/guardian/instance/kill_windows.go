//go:build windows

package instance

import (
	"os"
	"os/exec"
	"syscall"
)

func killProcessGroup(pid int, sig syscall.Signal) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}

func forceKillProcessGroup(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}

func signalFromName(name string) syscall.Signal {
	// Windows does not support POSIX signals; always return 0
	// so stopInstance falls through to force-kill.
	return 0
}

func setProcAttr(cmd *exec.Cmd) {
	// No-op on Windows: Setpgid / process groups are not used.
}
