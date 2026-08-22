package singbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The guard mechanism can only be tested with real processes, so the test
// binary re-executes itself in two helper roles:
//
//	test  --SIGKILL-->  parent (holds the guard pipe)  -->  shim  -->  child
//
// The claim under test is that killing the parent with SIGKILL — which runs no
// cleanup code at all — still takes the child down.
const roleEnv = "VPNCTL_TEST_ROLE"

func TestMain(m *testing.M) {
	switch os.Getenv(roleEnv) {
	case "parent":
		runParentRole()
	case "shim":
		if err := RunShim(os.Args[1:]); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	default:
		os.Exit(m.Run())
	}
}

// runParentRole stands in for the vpnctl daemon: it owns the write end of the
// guard pipe and does nothing else.
func runParentRole() {
	pidFile := os.Getenv("VPNCTL_TEST_PIDFILE")
	sleepFor := os.Getenv("VPNCTL_TEST_SLEEP")
	if sleepFor == "" {
		sleepFor = "300"
	}

	guardR, guardW, err := os.Pipe()
	if err != nil {
		os.Exit(1)
	}

	cmd := exec.Command(os.Args[0],
		"-guard-fd", "3",
		"-pidfile", pidFile,
		"-term-timeout", "1s",
		"--", "/bin/sleep", sleepFor)
	cmd.Env = append(os.Environ(), roleEnv+"=shim")
	cmd.ExtraFiles = []*os.File{guardR}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr

	if err := cmd.Start(); err != nil {
		os.Exit(1)
	}
	guardR.Close()

	// Held open on purpose: the kernel closes it when this process dies.
	// Parked in a package-level variable so the garbage collector cannot
	// reach it and run os.File's finaliser, which would close the fd early
	// and look exactly like the parent having died.
	heldGuard = guardW

	// Not select{}: with no other runnable goroutine the runtime reports a
	// deadlock and exits, which would itself close the pipe.
	time.Sleep(10 * time.Minute)
}

// heldGuard keeps the parent role's write end of the guard pipe alive.
var heldGuard *os.File

func alive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

func waitPidFile(t *testing.T, path string, timeout time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 1 {
				return pid
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("pidfile %s never appeared", path)
	return 0
}

func waitGone(t *testing.T, pid int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !alive(pid) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("pid %d still alive after %s", pid, timeout)
}

func startParent(t *testing.T) (*exec.Cmd, int) {
	t.Helper()
	pidFile := filepath.Join(t.TempDir(), "child.pid")

	parent := exec.Command(os.Args[0])
	parent.Env = append(os.Environ(), roleEnv+"=parent", "VPNCTL_TEST_PIDFILE="+pidFile)
	parent.Stdout, parent.Stderr = os.Stdout, os.Stderr
	if err := parent.Start(); err != nil {
		t.Fatalf("start parent: %v", err)
	}
	t.Cleanup(func() {
		_ = parent.Process.Kill()
		_, _ = parent.Process.Wait()
	})

	return parent, waitPidFile(t, pidFile, 5*time.Second)
}

// TestSIGKILLedSupervisorStillStopsSingBox is the load-bearing test for the
// whole fail-open design: if the supervisor can die without taking sing-box
// with it, the machine is left with routes pointing at a resolver and a proxy
// that are gone, and nothing on it can reach the network.
func TestSIGKILLedSupervisorStillStopsSingBox(t *testing.T) {
	parent, childPid := startParent(t)

	if !alive(childPid) {
		t.Fatalf("child %d not running before the kill", childPid)
	}

	if err := parent.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL parent: %v", err)
	}
	_, _ = parent.Process.Wait()

	waitGone(t, childPid, 10*time.Second)
}

// TestSIGTERMedSupervisorStopsSingBox covers the ordinary path, where the
// supervisor is asked to stop rather than killed outright.
func TestSIGTERMedSupervisorStopsSingBox(t *testing.T) {
	parent, childPid := startParent(t)

	if err := parent.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM parent: %v", err)
	}
	_, _ = parent.Process.Wait()

	waitGone(t, childPid, 10*time.Second)
}

// TestShimKillsChildThatIgnoresSIGTERM proves the escalation to SIGKILL, so a
// wedged sing-box cannot keep the TUN alive indefinitely.
func TestShimKillsChildThatIgnoresSIGTERM(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")

	guardR, guardW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	// A shell that traps SIGTERM and refuses to die from it.
	script := `trap '' TERM; while true; do sleep 0.2; done`
	shim := exec.Command(os.Args[0],
		"-guard-fd", "3", "-pidfile", pidFile, "-term-timeout", "700ms",
		"--", "/bin/sh", "-c", script)
	shim.Env = append(os.Environ(), roleEnv+"=shim")
	shim.ExtraFiles = []*os.File{guardR}
	shim.Stdout, shim.Stderr = os.Stdout, os.Stderr

	if err := shim.Start(); err != nil {
		t.Fatalf("start shim: %v", err)
	}
	guardR.Close()
	t.Cleanup(func() { _ = shim.Process.Kill() })

	childPid := waitPidFile(t, pidFile, 5*time.Second)

	guardW.Close() // simulate the supervisor going away
	waitGone(t, childPid, 10*time.Second)

	if _, err := shim.Process.Wait(); err != nil {
		t.Logf("shim exited: %v", err)
	}
}
