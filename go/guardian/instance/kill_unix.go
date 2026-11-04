//go:build !windows

package instance

import (
	"os/exec"
	"syscall"
)

/* Verify process group ID before killing to avoid stale PID reuse.
   Uses getpgid(2) rather than /proc/<pid>/stat: /proc exists only on Linux,
   so on macOS/BSD the read always failed and this check returned false for
   every pid, making killProcessGroup return ESRCH without ever sending a
   signal.  The caller discards that error, so stopping an instance silently
   did nothing on those platforms.  getpgid(2) is available on every unix Go
   target and returns ESRCH for a pid that does not exist, which is exactly
   the stale-pid guard this function is after. */
func verifyPgid(pid int) bool {
	if pid <= 0 {
		return false
	}

	// Returns the process group id of pid, or ESRCH if pid does not exist.
	pgrp, err := syscall.Getpgid(pid)
	if err != nil {
		return false
	}

	// Verify the process is actually the process group leader (pid == pgrp)
	return pgrp == pid
}

func killProcessGroup(pid int, sig syscall.Signal) error {
	/* Verify pgid before sending signal to avoid killing reused PID */
	if !verifyPgid(pid) {
		return syscall.ESRCH // No such process or not a group leader
	}
	return syscall.Kill(-pid, sig)
}

func forceKillProcessGroup(pid int) error {
	/* Verify pgid before SIGKILL to avoid killing reused PID */
	if !verifyPgid(pid) {
		return syscall.ESRCH
	}
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
