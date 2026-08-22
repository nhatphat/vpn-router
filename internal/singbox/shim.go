package singbox

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

// GuardFD is the descriptor the daemon passes the shim: the read end of a
// pipe the daemon holds the write end of.
const GuardFD = 3

// RunShim is the "vpnctl singbox-shim" subcommand. It is not meant to be run
// by hand.
//
// It exists to make one invariant true: sing-box must never outlive the
// supervisor. sing-box owns the TUN and the routes that send every
// application's traffic into it, while the supervisor owns the DNS resolver
// and the TCP racer that those routes depend on. A supervisor that dies while
// sing-box keeps running leaves the machine with routes pointing at a
// resolver and a proxy that no longer answer — every lookup and every
// connection fails, even though the interface still looks up.
//
// Signals cannot express that: the supervisor cannot send anything after being
// SIGKILLed. A pipe can. The shim blocks reading a descriptor whose only
// writer is the supervisor process, so the kernel reports EOF the moment that
// process ceases to exist, however it died. The shim then stops sing-box, the
// routes go with it, and the machine falls back to its own networking.
func RunShim(args []string) error {
	fs := flag.NewFlagSet("singbox-shim", flag.ExitOnError)
	guardFD := fs.Int("guard-fd", GuardFD, "descriptor whose EOF means the supervisor is gone")
	pidFile := fs.String("pidfile", "", "write the supervised process id here")
	termTimeout := fs.Duration("term-timeout", 5*time.Second, "how long to wait after SIGTERM before SIGKILL")
	if err := fs.Parse(args); err != nil {
		return err
	}

	argv := fs.Args()
	if len(argv) == 0 {
		return errors.New("singbox-shim: no command given")
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	// The daemon already replaced these with pipes it reads, so sing-box's
	// output reaches the log bus by inheritance.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = nil
	// Its own process group, so a stray signal to the group cannot reach
	// sing-box without going through the shim's shutdown path.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", argv[0], err)
	}

	if *pidFile != "" {
		_ = os.WriteFile(*pidFile, []byte(strconv.Itoa(cmd.Process.Pid)+"\n"), 0o644)
		defer os.Remove(*pidFile)
	}

	stop := make(chan string, 2)

	// The guard: EOF here means the supervisor process is gone.
	go func() {
		guard := os.NewFile(uintptr(*guardFD), "supervisor-guard")
		if guard == nil {
			stop <- "guard descriptor unavailable"
			return
		}
		defer guard.Close()

		buf := make([]byte, 64)
		for {
			_, err := guard.Read(buf)
			if err == nil {
				continue // the daemon may use the pipe to say something later
			}
			if errors.Is(err, io.EOF) {
				stop <- "supervisor exited (guard pipe closed)"
			} else {
				stop <- "guard pipe error: " + err.Error()
			}
			return
		}
	}()

	// An ordinary shutdown request, e.g. launchctl stopping the daemon tree.
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		s := <-sigCh
		stop <- "received " + s.String()
	}()

	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	select {
	case err := <-waitCh:
		return exitWith(cmd, err)

	case reason := <-stop:
		fmt.Fprintf(os.Stderr, "shim: stopping sing-box: %s\n", reason)
		_ = cmd.Process.Signal(syscall.SIGTERM)

		select {
		case err := <-waitCh:
			return exitWith(cmd, err)
		case <-time.After(*termTimeout):
			fmt.Fprintf(os.Stderr, "shim: sing-box did not exit in %s, sending SIGKILL\n", *termTimeout)
			_ = cmd.Process.Kill()
			<-waitCh
			return nil
		}
	}
}

// exitWith mirrors the supervised process's exit status, so the daemon can
// tell a crash from a clean stop.
func exitWith(cmd *exec.Cmd, waitErr error) error {
	if waitErr == nil {
		return nil
	}
	var ee *exec.ExitError
	if errors.As(waitErr, &ee) {
		code := ee.ExitCode()
		if code < 0 {
			return fmt.Errorf("sing-box killed by signal: %v", ee)
		}
		os.Exit(code)
	}
	return waitErr
}
