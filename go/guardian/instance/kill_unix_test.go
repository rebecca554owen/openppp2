//go:build !windows

package instance

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"
)

/* startChild launches `sleep 60` with or without its own process group and
   returns the *exec.Cmd.  The caller owns cmd.Wait via cmd.Process.Wait. */
func startChild(t *testing.T, ownGroup bool) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "60")
	if ownGroup {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd
}

func alive(pid int) bool {
	// Signal 0 performs error checking only.
	return syscall.Kill(pid, 0) == nil
}

/* A process-group leader must be recognised as such on every unix target.
   The previous implementation read /proc/<pid>/stat, which does not exist on
   macOS or the BSDs, so this returned false for every pid there and
   killProcessGroup returned ESRCH without ever signalling the group. */
func TestVerifyPgidRecognisesGroupLeader(t *testing.T) {
	cmd := startChild(t, true)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if verifyPgid(cmd.Process.Pid) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	t.Fatalf("verifyPgid(%d) = false, want true for a process-group leader "+
		"(getpgid = %d, %v)", cmd.Process.Pid, pgid, err)
}

/* The stale-pid guard must survive the rewrite: a pid that does not exist
   must never be reported as a killable group leader. */
func TestVerifyPgidRejectsDeadPid(t *testing.T) {
	// Start and reap a child so its pid is known to be free-ish, then also
	// probe a pid far above the usual range which cannot be live.
	for _, pid := range []int{deadPid(t), 0, -1, 0x7ffffffe} {
		if verifyPgid(pid) {
			t.Errorf("verifyPgid(%d) = true, want false", pid)
		}
	}
}

func deadPid(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Wait()
	// Give the kernel a moment to reap it fully.
	time.Sleep(50 * time.Millisecond)
	if alive(pid) {
		t.Skipf("pid %d still alive after wait, cannot test stale-pid guard", pid)
	}
	return pid
}

/* A process that is NOT a group leader (it inherited ours) must be rejected,
   otherwise a recycled pid belonging to an unrelated child could be killed. */
func TestVerifyPgidRejectsNonLeader(t *testing.T) {
	cmd := startChild(t, false) // no Setpgid: inherits the test's group
	if pgid, err := syscall.Getpgid(cmd.Process.Pid); err != nil {
		t.Skipf("getpgid: %v", err)
	} else if pgid == cmd.Process.Pid {
		t.Skip("child unexpectedly became a group leader")
	}
	if verifyPgid(cmd.Process.Pid) {
		t.Errorf("verifyPgid(%d) = true, want false: pid is not the group leader", cmd.Process.Pid)
	}
}

/* Reap the child so its pid is released; a SIGKILLed-but-unreaped child stays
   a zombie, and kill(pid, 0) still succeeds against a zombie. */
func waitWithin(t *testing.T, cmd *exec.Cmd, d time.Duration) bool {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

/* End-to-end: stopInstance's signal path must actually terminate the group. */
func TestKillProcessGroupTerminatesGroup(t *testing.T) {
	cmd := startChild(t, true)
	pid := cmd.Process.Pid

	if err := killProcessGroup(pid, syscall.SIGKILL); err != nil {
		t.Fatalf("killProcessGroup: %v", err)
	}
	if !waitWithin(t, cmd, 3*time.Second) {
		t.Errorf("child %d was not reaped after killProcessGroup succeeded", pid)
	}
	if alive(pid) {
		t.Errorf("pid %d still alive after killProcessGroup succeeded", pid)
	}
}

func TestForceKillProcessGroupTerminatesGroup(t *testing.T) {
	cmd := startChild(t, true)
	pid := cmd.Process.Pid

	if err := forceKillProcessGroup(pid); err != nil {
		t.Fatalf("forceKillProcessGroup: %v", err)
	}
	if !waitWithin(t, cmd, 3*time.Second) {
		t.Errorf("child %d was not reaped after forceKillProcessGroup succeeded", pid)
	}
	if alive(pid) {
		t.Errorf("pid %d still alive after forceKillProcessGroup succeeded", pid)
	}
}

/* Documented regression witness: the old /proc-based read cannot work here.
   If /proc/<pid>/stat is readable on this platform the old code was not the
   problem; if it is not readable, that is exactly why the rewrite was needed. */
func TestProcStatUnavailableOnThisPlatform(t *testing.T) {
	cmd := startChild(t, true)
	path := "/proc/" + strconv.Itoa(cmd.Process.Pid) + "/stat"
	if _, err := os.ReadFile(path); err == nil {
		t.Logf("/proc is present on this platform; getpgid is still used for portability")
	} else {
		t.Logf("/proc/%d/stat unreadable (%v) — the /proc-based verifyPgid would "+
			"always have returned false here", cmd.Process.Pid, err)
	}
}
