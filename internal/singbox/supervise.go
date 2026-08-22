package singbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"vpn-router/internal/config"
	"vpn-router/internal/logbus"
	"vpn-router/internal/status"
)

type BackoffSpec struct {
	Min time.Duration
	Max time.Duration
}

type BreakerSpec struct {
	Failures int
	Window   time.Duration
}

type Options struct {
	// VpnctlExe is this binary, re-executed as the shim.
	VpnctlExe string
	Binary    string
	Document  []byte

	ConfigPath   string
	ShimPidFile  string
	ChildPidFile string

	TUNInterface      string
	AllowUnsafeBinary bool

	Backoff BackoffSpec
	Breaker BreakerSpec

	Bus     *logbus.Bus
	OnPhase func(phase status.Phase, detail string)
}

// Runner keeps sing-box running, and stops trying when continuing to try
// would be worse than being stopped.
type Runner struct {
	o Options

	// document is replaced on reload and read on every start, so a restart
	// is what applies a new configuration. Writing it at start time rather
	// than immediately also means a rejected configuration never reaches
	// disk while sing-box is running on the old one.
	document atomic.Pointer[[]byte]

	mu       sync.Mutex
	phase    status.Phase
	detail   string
	restarts int
	failures []time.Time

	restartCh chan struct{}
	retryCh   chan struct{}

	// guard is the write end of the pipe the shim watches. Closing it is how
	// a stop is requested; it is also what the kernel closes for us if this
	// process dies without running any code.
	guard *os.File
}

func NewRunner(o Options) *Runner {
	if o.Backoff.Min <= 0 {
		o.Backoff.Min = time.Second
	}
	if o.Backoff.Max < o.Backoff.Min {
		o.Backoff.Max = o.Backoff.Min
	}
	r := &Runner{
		o:         o,
		phase:     status.PhaseStopped,
		restartCh: make(chan struct{}, 1),
		retryCh:   make(chan struct{}, 1),
	}
	r.SetDocument(o.Document)
	return r
}

// SetDocument replaces the configuration sing-box will be started with. It
// takes effect on the next start, which the caller triggers with Restart.
func (r *Runner) SetDocument(doc []byte) {
	cp := make([]byte, len(doc))
	copy(cp, doc)
	r.document.Store(&cp)
}

// Document returns the configuration currently staged for sing-box.
func (r *Runner) Document() []byte {
	p := r.document.Load()
	if p == nil {
		return nil
	}
	return *p
}

func (r *Runner) setPhase(p status.Phase, format string, args ...any) {
	detail := fmt.Sprintf(format, args...)

	r.mu.Lock()
	r.phase, r.detail = p, detail
	r.mu.Unlock()

	if r.o.OnPhase != nil {
		r.o.OnPhase(p, detail)
	}
	r.logf(logbus.LevelInfo, "sing-box %s: %s", p, detail)
}

func (r *Runner) Phase() (status.Phase, string, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.phase, r.detail, r.restarts
}

func (r *Runner) logf(lvl logbus.Level, format string, args ...any) {
	if r.o.Bus != nil {
		r.o.Bus.Publishf(logbus.SourceSupervisor, lvl, format, args...)
	}
}

// Restart asks for the current sing-box to be stopped and started again. It
// also clears a safe-mode hold, since an explicit request outranks the
// breaker's decision.
func (r *Runner) Restart() {
	select {
	case r.retryCh <- struct{}{}:
	default:
	}
	select {
	case r.restartCh <- struct{}{}:
	default:
	}
}

// Retry leaves safe mode without disturbing a healthy process.
func (r *Runner) Retry() {
	select {
	case r.retryCh <- struct{}{}:
	default:
	}
}

// Run supervises sing-box until ctx is cancelled.
func (r *Runner) Run(ctx context.Context) error {
	if err := r.preflight(); err != nil {
		r.logf(logbus.LevelWarn, "preflight: %v", err)
	}

	delay := r.o.Backoff.Min

	for {
		if err := ctx.Err(); err != nil {
			r.setPhase(status.PhaseStopped, "supervisor shutting down")
			return err
		}

		start := time.Now()
		exitErr := r.runOnce(ctx)
		ran := time.Since(start)

		if ctx.Err() != nil {
			r.setPhase(status.PhaseStopped, "supervisor shutting down")
			return ctx.Err()
		}

		// A process that stayed up long enough to be useful resets the
		// backoff, so an occasional crash after hours does not inherit the
		// penalty of a crash loop from last week.
		if ran > 2*r.o.Breaker.Window {
			r.failures = nil
			delay = r.o.Backoff.Min
		}

		r.mu.Lock()
		r.restarts++
		r.failures = append(r.failures, time.Now())
		r.trimFailuresLocked()
		tooMany := r.o.Breaker.Failures > 0 && len(r.failures) >= r.o.Breaker.Failures
		r.mu.Unlock()

		if exitErr != nil {
			r.logf(logbus.LevelError, "sing-box exited after %s: %v", ran.Round(time.Millisecond), exitErr)
		} else {
			r.logf(logbus.LevelWarn, "sing-box exited after %s", ran.Round(time.Millisecond))
		}

		if tooMany {
			// Deliberately stop trying. Flapping the default route every few
			// seconds is worse for the machine than having no split routing
			// at all, and a loop that never gives up hides the failure.
			r.setPhase(status.PhaseSafeMode,
				"%d failures within %s; left stopped so the machine keeps its own routing",
				len(r.failures), r.o.Breaker.Window)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-r.retryCh:
				r.mu.Lock()
				r.failures = nil
				r.mu.Unlock()
				delay = r.o.Backoff.Min
				r.logf(logbus.LevelInfo, "leaving safe mode on request")
				continue
			}
		}

		r.setPhase(status.PhaseBackoff, "retrying in %s", delay)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.restartCh:
		case <-time.After(delay):
		}

		delay *= 2
		if delay > r.o.Backoff.Max {
			delay = r.o.Backoff.Max
		}
	}
}

func (r *Runner) trimFailuresLocked() {
	if r.o.Breaker.Window <= 0 {
		return
	}
	cutoff := time.Now().Add(-r.o.Breaker.Window)
	kept := r.failures[:0]
	for _, t := range r.failures {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	r.failures = kept
}

// runOnce starts sing-box and returns when it exits, a restart is requested,
// or ctx is cancelled.
func (r *Runner) runOnce(ctx context.Context) error {
	if err := config.CheckExecutable(r.o.Binary, r.o.AllowUnsafeBinary); err != nil {
		r.setPhase(status.PhaseFailed, "%v", err)
		// Not retryable by waiting: report and let the breaker trip.
		return err
	}

	if err := r.writeDocument(); err != nil {
		r.setPhase(status.PhaseFailed, "%v", err)
		return err
	}

	guardR, guardW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create guard pipe: %w", err)
	}

	outR, outW, err := os.Pipe()
	if err != nil {
		guardR.Close()
		guardW.Close()
		return fmt.Errorf("create output pipe: %w", err)
	}

	args := []string{"singbox-shim"}
	if r.o.ChildPidFile != "" {
		args = append(args, "-pidfile", r.o.ChildPidFile)
	}
	args = append(args, "--", r.o.Binary, "run", "-c", r.o.ConfigPath)

	cmd := exec.Command(r.o.VpnctlExe, args...)
	cmd.Stdout = outW
	cmd.Stderr = outW
	cmd.ExtraFiles = []*os.File{guardR} // becomes GuardFD in the child

	r.setPhase(status.PhaseStarting, "launching %s", r.o.Binary)

	if err := cmd.Start(); err != nil {
		guardR.Close()
		guardW.Close()
		outR.Close()
		outW.Close()
		return fmt.Errorf("start shim: %w", err)
	}

	// The parent must not keep the read end: while it holds one, the shim
	// would never see EOF and would outlive us — the exact failure this
	// whole mechanism exists to prevent.
	guardR.Close()
	outW.Close()

	r.mu.Lock()
	r.guard = guardW
	r.mu.Unlock()

	if r.o.ShimPidFile != "" {
		_ = os.WriteFile(r.o.ShimPidFile, []byte(strconv.Itoa(cmd.Process.Pid)+"\n"), 0o644)
	}

	if r.o.Bus != nil {
		go r.o.Bus.Attach(logbus.SourceSingBox, outR, logbus.ClassifySingBox)
	} else {
		go func() { _, _ = os.Stdout.ReadFrom(outR) }()
	}

	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	go r.watchReadiness(ctx, waitCh)

	stop := func(reason string) {
		r.logf(logbus.LevelInfo, "stopping sing-box: %s", reason)
		r.mu.Lock()
		if r.guard != nil {
			r.guard.Close()
			r.guard = nil
		}
		r.mu.Unlock()
	}

	defer func() {
		stop("cleanup")
		outR.Close()
		if r.o.ShimPidFile != "" {
			os.Remove(r.o.ShimPidFile)
		}
	}()

	for {
		select {
		case err := <-waitCh:
			return err

		case <-ctx.Done():
			stop("supervisor shutting down")
			select {
			case <-waitCh:
			case <-time.After(10 * time.Second):
				r.logf(logbus.LevelWarn, "shim did not exit within 10s")
			}
			return ctx.Err()

		case <-r.restartCh:
			stop("restart requested")
			select {
			case <-waitCh:
			case <-time.After(10 * time.Second):
				r.logf(logbus.LevelWarn, "shim did not exit within 10s of a restart request")
			}
			return nil
		}
	}
}

// watchReadiness promotes the phase to running once the TUN interface exists,
// which is the observable proof that sing-box got far enough to matter. It is
// the interface, not the log line, because the interface is what the routes
// and every application depend on.
func (r *Runner) watchReadiness(ctx context.Context, done <-chan error) {
	deadline := time.After(15 * time.Second)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-deadline:
			r.setPhase(status.PhaseDegraded, "%s did not appear within 15s", r.o.TUNInterface)
			return
		case <-ticker.C:
			if _, err := net.InterfaceByName(r.o.TUNInterface); err == nil {
				r.setPhase(status.PhaseRunning, "%s up", r.o.TUNInterface)
				return
			}
		}
	}
}

func (r *Runner) writeDocument() error {
	if err := os.MkdirAll(filepath.Dir(r.o.ConfigPath), 0o755); err != nil {
		return err
	}
	// 0644 root-owned: the document is generated output, and letting an
	// unprivileged writer edit what root feeds sing-box would undo the point
	// of validating the config in the first place.
	return os.WriteFile(r.o.ConfigPath, r.Document(), 0o644)
}

// preflight cleans up anything a previous, abruptly-terminated supervisor left
// behind. A shim killed with SIGKILL cannot stop its child, so sing-box can
// survive as an orphan still holding the TUN.
func (r *Runner) preflight() error {
	var problems []string

	for _, pf := range []struct{ label, path string }{
		{"shim", r.o.ShimPidFile},
		{"sing-box", r.o.ChildPidFile},
	} {
		if pf.path == "" {
			continue
		}
		pid, ok := readPidFile(pf.path)
		if !ok {
			continue
		}
		if err := terminatePid(pid, 5*time.Second); err != nil {
			problems = append(problems, fmt.Sprintf("orphan %s pid %d: %v", pf.label, pid, err))
		} else {
			r.logf(logbus.LevelWarn, "preflight: terminated orphan %s pid %d from a previous run", pf.label, pid)
		}
		os.Remove(pf.path)
	}

	// Verified on this platform: a utun interface belongs to the file
	// descriptor that created it, so the kernel destroys it — and the routes
	// pointing at it — when that process dies. If it is still here, something
	// is still holding it.
	if r.o.TUNInterface != "" {
		if _, err := net.InterfaceByName(r.o.TUNInterface); err == nil {
			problems = append(problems, fmt.Sprintf(
				"%s still exists before start: another sing-box may be running", r.o.TUNInterface))
		}
	}

	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func readPidFile(path string) (int, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		return 0, false
	}
	return pid, true
}

// terminatePid stops a process politely, then forcibly. A missing process is
// success: the goal is that it is not running.
func terminatePid(pid int, grace time.Duration) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return nil // already gone
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return err
	}

	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return proc.Kill()
}
