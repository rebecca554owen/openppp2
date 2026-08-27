//go:build !windows

package instance

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

/* Verify process group ID before killing to avoid stale PID reuse */
func verifyPgid(pid int) bool {
	// Read /proc/<pid>/stat to get process group ID
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false // Process doesn't exist
	}

	// Parse stat format: pid (comm) state ppid pgrp ...
	// Find closing ')' of comm field, then split remaining fields
	var pgrp int
	closeIdx := -1
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == ')' {
			closeIdx = i
			break
		}
	}
	if closeIdx == -1 {
		return false
	}

	// Format after ')': " state ppid pgrp ..."
	_, err = fmt.Sscanf(string(data[closeIdx+1:]), " %*c %*d %d", &pgrp)
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
