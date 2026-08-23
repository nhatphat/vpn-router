// Package supervisor runs the whole stack and decides what to do when part of
// it stops working.
//
// The ordering constraint it exists to enforce is that sing-box must never
// outlive the resolver and the racer, because sing-box installs the routes
// that make every application depend on them. That is handled structurally:
// the resolver and the racer are goroutines in this process, and sing-box is a
// child guarded by a pipe this process holds (see internal/singbox). So the
// supervisor's own job is narrower — keep each part running, notice when the
// machine's networking is worse with the stack than without it, and in that
// case take the stack down rather than keep it up.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"vpn-router/container"
	"vpn-router/internal/config"
	"vpn-router/internal/dnsrouter"
	"vpn-router/internal/dockerctl"
	"vpn-router/internal/health"
	"vpn-router/internal/logbus"
	"vpn-router/internal/netmon"
	"vpn-router/internal/racer"
	"vpn-router/internal/resolver"
	"vpn-router/internal/singbox"
	"vpn-router/internal/status"
	"vpn-router/internal/vpnbox"
	"vpn-router/internal/vpndns"
)

type Options struct {
	Cfg           *config.Config
	Bus           *logbus.Bus
	VpnctlExe     string
	SingBoxDoc    []byte
	SingBoxBinary string
	Version       string
	StateDir      string
	// RouterProcess is the process name the generated sing-box document must
	// name in its loop-breaking route rule; see internal/singbox.
	RouterProcess string
	// ResolverDir is where scoped resolvers are written. Only tests set it;
	// everything else takes the one place macOS reads.
	ResolverDir string
}

type Supervisor struct {
	o Options
	// current holds the live configuration. It is swapped on reload rather
	// than mutated, so the goroutines reading it never see a half-applied
	// change; each picks the new values up when its component restarts.
	current atomic.Pointer[config.Config]

	holder *netmon.Holder
	sb     *singbox.Runner
	docker *dockerctl.Client
	prober *health.Prober

	mu          sync.Mutex
	comps       map[string]status.Component
	order       []string
	generation  uint64
	containerID string
	started     time.Time

	statusSubs   map[int]chan status.Snapshot
	nextStatusID int

	resolvers []status.Resolver

	restart map[string]chan struct{}
	pause   *pauseState

	// reloadResolvers tells the system resolver to re-read the directory.
	// A field so a test can write resolvers without signalling a real
	// mDNSResponder.
	reloadResolvers func() error
}

func New(o Options) (*Supervisor, error) {
	cfg := o.Cfg

	holder := &netmon.Holder{}
	if cfg.DNSRouter.BindInterface != "" {
		ip, err := netmon.InterfaceIPv4(cfg.DNSRouter.BindInterface)
		if err != nil {
			// Not fatal: the interface may come up later, and the stack is
			// more useful unbound than not running.
			o.Bus.Publishf(logbus.SourceSupervisor, logbus.LevelWarn,
				"bind interface %s has no address yet: %v", cfg.DNSRouter.BindInterface, err)
		} else {
			holder.Set(ip)
		}
	}

	docker, err := dockerctl.New(cfg.Docker.Host)
	if err != nil {
		return nil, err
	}

	if o.ResolverDir == "" {
		o.ResolverDir = resolver.Dir
	}

	s := &Supervisor{
		o:          o,
		holder:     holder,
		docker:     docker,
		comps:      make(map[string]status.Component),
		statusSubs: make(map[int]chan status.Snapshot),
		started:    time.Now(),
		pause:      newPauseState(),

		reloadResolvers: resolver.Reload,
		restart: map[string]chan struct{}{
			status.CompVPN:       make(chan struct{}, 1),
			status.CompDNSRouter: make(chan struct{}, 1),
			status.CompRacer:     make(chan struct{}, 1),
		},
	}

	s.current.Store(cfg)

	// A pause outlives the daemon on purpose: someone who turned the stack
	// off does not expect a reboot to turn it back on.
	if paused, err := readPaused(cfg.Supervisor.StateDir); err == nil && paused {
		s.pause.Set(true)
		o.Bus.Publishf(logbus.SourceSupervisor, logbus.LevelWarn,
			"starting paused; run \"vpnctl start\" to route traffic again")
	}

	for _, name := range []string{status.CompVPN, status.CompSingBox, status.CompDNSRouter, status.CompRacer} {
		s.order = append(s.order, name)
		s.comps[name] = status.Component{Name: name, Phase: status.PhaseStopped, Since: time.Now()}
	}

	s.sb = singbox.NewRunner(singbox.Options{
		VpnctlExe:         o.VpnctlExe,
		Binary:            o.SingBoxBinary,
		Document:          o.SingBoxDoc,
		ConfigPath:        cfg.Supervisor.StateDir + "/singbox.json",
		ShimPidFile:       cfg.Supervisor.StateDir + "/singbox-shim.pid",
		ChildPidFile:      cfg.Supervisor.StateDir + "/singbox.pid",
		TUNInterface:      cfg.SingBox.TUN.InterfaceName,
		AllowUnsafeBinary: cfg.SingBox.AllowUnsafeBinary,
		Backoff: singbox.BackoffSpec{
			Min: cfg.Supervisor.SingBoxBackoff.Min.D(),
			Max: cfg.Supervisor.SingBoxBackoff.Max.D(),
		},
		Breaker: singbox.BreakerSpec{
			Failures: cfg.Supervisor.SingBoxBreaker.Failures,
			Window:   cfg.Supervisor.SingBoxBreaker.Window.D(),
		},
		Bus: o.Bus,
		OnPhase: func(p status.Phase, detail string) {
			s.setComp(status.CompSingBox, p, detail, nil)
		},
		Gate: s.pause,
	})

	s.prober = &health.Prober{
		DirectTarget: "1.1.1.1:443",
		DNSAddr:      cfg.DNSRouter.Listen,
		RacerAddr:    cfg.Racer.Listen,
		ChainName:    "example.com",
		BindIP:       holder.IP,
		Timeout:      8 * time.Second,
	}

	return s, nil
}

// cfg returns the live configuration.
func (s *Supervisor) cfg() *config.Config { return s.current.Load() }

func (s *Supervisor) logf(lvl logbus.Level, format string, args ...any) {
	s.o.Bus.Publishf(logbus.SourceSupervisor, lvl, format, args...)
}

// Run starts everything and returns when ctx is cancelled.
func (s *Supervisor) Run(ctx context.Context) error {
	s.applyResolvers()

	g, ctx := errgroup.WithContext(ctx)

	dnsSource := &vpndns.Source{
		Docker:    s.docker,
		Container: s.currentContainerID,
		Logf:      s.o.Bus.Logf(logbus.SourceDNS, logbus.LevelInfo),
		Warnf:     s.o.Bus.Logf(logbus.SourceDNS, logbus.LevelWarn),
	}

	g.Go(func() error {
		return s.runService(ctx, status.CompDNSRouter, func(c context.Context) error {
			// Read the configuration at start time: a restart is what applies
			// a reloaded one.
			cfg := s.cfg()
			dnsSource.File = cfg.Docker.VPNDNSFile
			return dnsrouter.Start(c, dnsrouter.Config{
				Listen:          cfg.DNSRouter.Listen,
				PublicDNS:       cfg.DNSRouter.PublicDNS,
				SocksAddr:       cfg.Docker.Socks,
				RefreshInterval: cfg.DNSRouter.RefreshInterval.D(),
				QueryTimeout:    cfg.DNSRouter.QueryTimeout.D(),
				GraceWindow:     cfg.DNSRouter.GraceWindow.D(),
				BindIP:          s.holder.IP,
				Servers:         dnsSource.Servers,
				Logf:            s.o.Bus.Logf(logbus.SourceDNS, logbus.LevelInfo),
			})
		})
	})

	g.Go(func() error {
		return s.runService(ctx, status.CompRacer, func(c context.Context) error {
			cfg := s.cfg()
			return racer.Start(c, racer.Config{
				Listen:      cfg.Racer.Listen,
				SocksAddr:   cfg.Docker.Socks,
				DialTimeout: cfg.Racer.DialTimeout.D(),
				RelayBuffer: cfg.Racer.RelayBuffer.Bytes(),
				Generation:  s.currentGeneration,
				LearnedTTL:  cfg.Racer.LearnedTTL.D(),
				BindIP:      s.holder.IP,
				Logf:        s.o.Bus.Logf(logbus.SourceRacer, logbus.LevelInfo),
			})
		})
	})

	g.Go(func() error { return s.sb.Run(ctx) })
	g.Go(func() error { return s.watchDocker(ctx) })
	g.Go(func() error { return s.watchNetwork(ctx) })
	g.Go(func() error { return s.watchHealth(ctx) })

	return g.Wait()
}

// runService keeps one in-process listener alive. A port already in use is
// treated as fatal for the component rather than something to retry quickly:
// spinning on it produces noise and never succeeds, and the operator needs to
// see which process is holding the port.
func (s *Supervisor) runService(ctx context.Context, name string, fn func(context.Context) error) error {
	restart := s.restart[name]
	backoff := s.cfg().Supervisor.ContainerBackoff
	delay := backoff.Min.D()
	if delay <= 0 {
		delay = time.Second
	}

	for {
		if err := ctx.Err(); err != nil {
			s.setComp(name, status.PhaseStopped, "supervisor shutting down", nil)
			return err
		}

		if s.pause.Paused() {
			s.setComp(name, status.PhaseStopped, "paused", nil)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-s.pause.WhileRunning():
				delay = backoff.Min.D()
			}
			continue
		}

		err, restarted := s.runServiceOnce(ctx, name, restart, fn)
		if ctx.Err() != nil {
			s.setComp(name, status.PhaseStopped, "supervisor shutting down", nil)
			return ctx.Err()
		}
		if restarted {
			delay = backoff.Min.D()
			continue
		}

		if err != nil && strings.Contains(err.Error(), "address already in use") {
			s.setComp(name, status.PhaseFailed, "port already in use", err)
			s.logf(logbus.LevelError, "%s cannot start: %v", name, err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-restart:
				continue
			}
		}

		s.setComp(name, status.PhaseBackoff, fmt.Sprintf("restarting in %s", delay), err)
		s.logf(logbus.LevelWarn, "%s stopped (%v), restarting in %s", name, err, delay)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-restart:
		case <-time.After(delay):
		}

		delay *= 2
		if max := backoff.Max.D(); max > 0 && delay > max {
			delay = max
		}
	}
}

func (s *Supervisor) runServiceOnce(ctx context.Context, name string, restart <-chan struct{}, fn func(context.Context) error) (error, bool) {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- fn(runCtx) }()

	s.setComp(name, status.PhaseRunning, "listening", nil)

	select {
	case err := <-done:
		return err, false

	case <-restart:
		s.logf(logbus.LevelInfo, "restarting %s on request", name)
		cancel()
		<-done
		return nil, true

	case <-s.pause.WhilePaused():
		cancel()
		<-done
		return nil, false

	case <-ctx.Done():
		cancel()
		<-done
		return ctx.Err(), false
	}
}

// applyResolvers makes /etc/resolver match what the stack is currently doing.
//
// Running means the configured suffixes are written and point at the daemon's
// own DNS port. Paused means none of them are, because a scoped resolver
// naming a listener that is not running is a black hole: those names would
// stop resolving even on a network that answers them perfectly well. Stopping
// vpnctl has to leave the machine resolving names the way it did before vpnctl
// existed.
//
// One function for both states rather than a removal path bolted onto pause,
// so every caller — startup, reload, pause, resume — states the same rule and
// there is no ordering in which the directory disagrees with the switch.
//
// It runs from the daemon rather than from install so that "vpnctl reload"
// applies a changed list, and because the port it points at is the daemon's
// own. A failure here is reported and otherwise ignored: scoped resolvers are
// an additional guarantee, and losing them is not a reason to refuse to route
// anything.
func (s *Supervisor) applyResolvers() {
	cfg := s.cfg()

	var result resolver.Result

	if s.pause.Paused() {
		result = resolver.RemoveAll(s.o.ResolverDir, s.o.Bus.Logf(logbus.SourceDNS, logbus.LevelWarn))
	} else {
		host, portStr, err := net.SplitHostPort(cfg.DNSRouter.Listen)
		if err != nil {
			s.logf(logbus.LevelError, "resolver: cannot read dns_router.listen: %v", err)
			return
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			s.logf(logbus.LevelError, "resolver: bad port in dns_router.listen: %v", err)
			return
		}

		// Only the enabled ones are written; anything switched off has its
		// file removed by Apply, because a resolver file that exists is in
		// effect.
		result, err = resolver.Apply(s.o.ResolverDir, cfg.DNSRouter.ResolverDomains.Enabled(), host, port,
			s.o.Bus.Logf(logbus.SourceDNS, logbus.LevelWarn))
		if err != nil {
			s.logf(logbus.LevelError, "resolver: %v", err)
			return
		}
	}

	s.refreshResolverState()

	if !result.Changed() {
		return
	}

	s.logf(logbus.LevelInfo, "resolver: %s", result)
	if err := s.reloadResolvers(); err != nil {
		s.logf(logbus.LevelWarn, "resolver: %v (the files are in place; a reboot or a manual "+
			"\"sudo killall -HUP mDNSResponder\" will pick them up)", err)
	}
}

// stopContainerForPause takes the tunnel down with everything else. Leaving it
// up would keep a VPN connected and a port published for a stack that is
// meant to be off.
func (s *Supervisor) stopContainerForPause(ctx context.Context) {
	s.mu.Lock()
	id := s.containerID
	s.mu.Unlock()

	if id == "" {
		// A daemon that started paused never went looking for the container,
		// so it has no id to stop — and something else may well have started
		// one, which is exactly the case worth handling.
		ct, err := s.findExistingContainer(ctx)
		if err != nil {
			return
		}
		if ct.State != "running" {
			return
		}
		id = ct.ID
	}

	if err := s.docker.Stop(ctx, id, 15*time.Second); err != nil {
		if ctx.Err() == nil {
			s.logf(logbus.LevelWarn, "could not stop the VPN container: %v", err)
		}
		return
	}
	s.logf(logbus.LevelInfo, "VPN container stopped")
}

// SetPaused turns the whole stack off or on without stopping the daemon, so
// that a menu bar running as the user can do it without a password.
func (s *Supervisor) SetPaused(paused bool) error {
	if !s.pause.Set(paused) {
		return nil
	}

	if err := writePaused(s.cfg().Supervisor.StateDir, paused); err != nil {
		s.logf(logbus.LevelWarn, "could not record the paused state: %v", err)
	}

	// The directory follows the switch straight away. Components stop and
	// start concurrently with this, so for a few milliseconds either way the
	// two disagree — harmlessly in both orderings. Pausing, a query that
	// arrives after the files are gone but before the router stops simply
	// reaches the state pausing is asking for. Resuming, one that arrives
	// after the files are back but before the router binds fails, which is
	// the fail-closed half of the trade and the same window the daemon
	// already has at startup.
	s.applyResolvers()

	if paused {
		s.logf(logbus.LevelWarn, "paused: the machine is routing its own traffic")
	} else {
		s.logf(logbus.LevelInfo, "resumed")
	}

	s.broadcast()
	return nil
}

// Paused reports the current state.
func (s *Supervisor) Paused() bool { return s.pause.Paused() }

// refreshResolverState records what is configured against what is actually on
// disk, for the status snapshot.
func (s *Supervisor) refreshResolverState() {
	managed := map[string]bool{}
	for _, d := range resolver.Managed(s.o.ResolverDir) {
		managed[d] = true
	}

	var out []status.Resolver
	for _, entry := range s.cfg().DNSRouter.ResolverDomains {
		state := status.Resolver{Domain: entry.Domain, Enabled: entry.Enabled}

		if _, err := os.Stat(filepath.Join(s.o.ResolverDir, entry.Domain)); err == nil {
			if managed[entry.Domain] {
				state.Installed = true
			} else {
				state.Foreign = true
			}
		}
		out = append(out, state)
	}

	s.mu.Lock()
	s.resolvers = out
	s.mu.Unlock()

	s.broadcast()
}

// watchNetwork keeps the bind address current. sing-box tracks the default
// interface itself, so nothing here restarts it; what does need updating is
// the address the resolver and the racer bind their direct connections to,
// which is resolved once at startup and would otherwise go stale the first
// time the machine changes network.
func (s *Supervisor) watchNetwork(ctx context.Context) error {
	iface := s.cfg().DNSRouter.BindInterface

	onChange := func(old, cur net.IP) {
		s.bumpGeneration(fmt.Sprintf("%s address %s -> %s", iface, old, cur))
	}

	return netmon.Watch(ctx, iface, s.holder, onChange, s.o.Bus.Logf(logbus.SourceSupervisor, logbus.LevelInfo))
}

// watchHealth is the self-healing loop. It acts only on repeated evidence,
// because a single failed probe during startup or a momentary network blip is
// not a reason to tear anything down.
func (s *Supervisor) watchHealth(ctx context.Context) error {
	interval := s.cfg().Supervisor.HealthInterval.D()
	if interval <= 0 {
		interval = 10 * time.Second
	}

	// Give the stack a chance to come up before judging it.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(interval):
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	consecutiveBroken := 0

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		if s.pause.Paused() {
			continue
		}

		res := s.prober.Probe(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}

		switch res.Verdict {
		case health.VerdictHealthy:
			if consecutiveBroken > 0 {
				s.logf(logbus.LevelInfo, "connectivity recovered: %s", res)
			}
			consecutiveBroken = 0

		case health.VerdictOffline:
			// The machine has no network at all. Restarting our stack cannot
			// help and would only add churn while the user waits for Wi-Fi.
			consecutiveBroken = 0
			s.logf(logbus.LevelWarn, "machine appears offline: %s", res)

		case health.VerdictBindStale:
			s.logf(logbus.LevelWarn, "direct path failed but applications are fine (%s); re-reading %s",
				res, s.cfg().DNSRouter.BindInterface)
			s.refreshBindAddress()

		case health.VerdictStackBroken:
			consecutiveBroken++
			s.logf(logbus.LevelError,
				"applications cannot reach the network but the interface can (%s), strike %d; culprit looks like %s",
				res, consecutiveBroken, res.Culprit())

			switch {
			case consecutiveBroken == 2 && res.Culprit() == "resolver-or-racer":
				// Cheap and non-disruptive: these are loopback listeners, and
				// restarting them does not touch the machine's routing.
				s.logf(logbus.LevelWarn, "restarting the resolver and the racer")
				s.signalRestart(status.CompDNSRouter)
				s.signalRestart(status.CompRacer)

			case consecutiveBroken >= 3:
				// Restarting sing-box drops the TUN, which restores native
				// routing immediately; if it cannot come back cleanly its own
				// breaker will stop trying and leave the machine that way.
				s.logf(logbus.LevelError, "restarting sing-box to restore the machine's networking")
				s.sb.Restart()
				consecutiveBroken = 0
			}
		}
	}
}

func (s *Supervisor) refreshBindAddress() {
	iface := s.cfg().DNSRouter.BindInterface
	if iface == "" {
		return
	}
	ip, err := netmon.InterfaceIPv4(iface)
	if err != nil {
		s.logf(logbus.LevelWarn, "%s still has no IPv4 address: %v", iface, err)
		return
	}
	if old := s.holder.IP(); !old.Equal(ip) {
		s.holder.Set(ip)
		s.bumpGeneration("bind address changed to " + ip.String())
	}
}

// watchDocker tracks the VPN container. The container runtime here runs in the
// user's session, so before login it simply does not exist: that is reported
// as unavailable and retried, never treated as a failure of ours.
func (s *Supervisor) watchDocker(ctx context.Context) error {
	const retry = 5 * time.Second

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		if s.pause.Paused() {
			s.setComp(status.CompVPN, status.PhaseStopped, "paused", nil)
			s.stopContainerForPause(ctx)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-s.pause.WhileRunning():
			}
			continue
		}

		if err := s.docker.Ping(ctx); err != nil {
			s.setComp(status.CompVPN, status.PhaseUnavailable,
				"container runtime not reachable (it starts with your login session)", nil)
			if !s.sleepUnlessPauseChanges(ctx, retry) {
				return ctx.Err()
			}
			continue
		}

		id, err := s.ensureContainer(ctx)
		if err != nil {
			s.setComp(status.CompVPN, status.PhaseFailed, "container unavailable", err)
			if !s.sleepUnlessPauseChanges(ctx, retry) {
				return ctx.Err()
			}
			continue
		}

		s.mu.Lock()
		s.containerID = id
		s.mu.Unlock()

		s.refreshContainer(ctx)

		err = s.followContainer(ctx, id)
		if errors.Is(err, errSpecChanged) {
			// Straight back to ensureContainer, which will recreate it. No
			// pause: the user asked for this and is watching.
			continue
		}
		if err != nil && ctx.Err() == nil {
			s.logf(logbus.LevelWarn, "container watch ended: %v", err)
		}

		if !s.sleepUnlessPauseChanges(ctx, retry) {
			return ctx.Err()
		}
	}
}

// sleepUnlessPauseChanges waits, but wakes as soon as the stack is switched
// off or on, so a transition is acted on immediately instead of at the end of
// a retry interval.
func (s *Supervisor) sleepUnlessPauseChanges(ctx context.Context, d time.Duration) bool {
	var change <-chan struct{}
	if s.pause.Paused() {
		change = s.pause.WhileRunning()
	} else {
		change = s.pause.WhilePaused()
	}

	select {
	case <-ctx.Done():
		return false
	case <-change:
		return true
	case <-time.After(d):
		return true
	}
}

// errSpecChanged says the running container was built from settings that no
// longer apply, so it has to be recreated rather than restarted.
var errSpecChanged = errors.New("container specification changed")

// containerMatchesConfig compares the running container against the
// specification the current configuration produces.
//
// Restarting is not enough when they differ: a container carries its
// environment and its mounts from creation, so a changed VPN profile, port or
// TOTP secret would survive a restart untouched — and "restarting vpn" would
// report success while changing nothing.
func (s *Supervisor) containerMatchesConfig(ctx context.Context, id string) bool {
	tag, err := container.ImageTag()
	if err != nil {
		return true // cannot tell; do not churn the container over it
	}

	spec, err := vpnbox.Spec(s.cfg(), tag)
	if err != nil {
		return true
	}

	ins, err := s.docker.Inspect(ctx, id)
	if err != nil {
		return true
	}

	return ins.Config.Labels[vpnbox.LabelSpec] == spec.Labels[vpnbox.LabelSpec]
}

// currentGeneration is read by the racer, which must not reuse a path it
// worked out on a different network.
func (s *Supervisor) currentGeneration() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generation
}

// currentContainerID is read by the VPN-DNS source, which may run before the
// container has been located.
func (s *Supervisor) currentContainerID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.containerID
}

// ensureContainer brings the VPN container into existence and returns its id.
//
// Creating it here rather than at install time is what lets the daemon recover
// on its own: the container runtime only exists once someone has logged in, so
// at boot there is nothing to create yet, and the container may also have been
// removed by hand since. Building the image, by contrast, stays an install-time
// action — it needs the network and takes minutes, which is not something to
// start doing unannounced inside a boot sequence.
func (s *Supervisor) ensureContainer(ctx context.Context) (string, error) {
	box := vpnbox.Options{
		Docker: s.docker,
		Cfg:    s.cfg(),
		Logf:   s.o.Bus.Logf(logbus.SourceVPN, logbus.LevelInfo),
	}

	tag, err := container.ImageTag()
	if err != nil {
		return "", err
	}

	built, err := s.docker.ImageExists(ctx, tag)
	if err != nil {
		return "", err
	}
	if !built {
		// Fall back to whatever container is already there, so an
		// installation part-way through a migration still gets a working
		// status display and a working restart button.
		if ct, ferr := s.findExistingContainer(ctx); ferr == nil {
			s.logf(logbus.LevelWarn,
				"image %s is not built; managing the existing container %s instead. "+
					"Run \"sudo vpnctl install\" to build it.", tag, ct.Name())
			return ct.ID, nil
		}
		return "", fmt.Errorf("image %s is not built and no existing container was found; run \"sudo vpnctl install\"", tag)
	}

	return vpnbox.EnsureContainer(ctx, box, tag)
}

// findExistingContainer looks for a container from an earlier setup: one of
// ours, then one compose created, then one matching the configured name.
func (s *Supervisor) findExistingContainer(ctx context.Context) (*dockerctl.Container, error) {
	cfg := s.cfg()

	if list, err := s.docker.ListByLabel(ctx, vpnbox.LabelOwner+"=true"); err == nil && len(list) > 0 {
		return &list[0], nil
	}
	if ct, err := s.docker.FindByComposeProject(ctx, cfg.Docker.Project, "vpn"); err == nil {
		return ct, nil
	}
	return s.docker.FindByName(ctx, cfg.Docker.Container)
}

// followContainer streams events and the container's log output, and services
// restart requests, until something goes wrong or ctx ends.
func (s *Supervisor) followContainer(ctx context.Context, id string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go s.streamContainerLogs(ctx, id)

	events, errs, err := s.docker.Events(ctx, s.cfg().Docker.Project)
	if err != nil {
		return err
	}

	poll := time.NewTicker(15 * time.Second)
	defer poll.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case err := <-errs:
			return err

		case ev, ok := <-events:
			if !ok {
				return fmt.Errorf("event stream closed")
			}
			s.onContainerEvent(ctx, ev)

		case <-poll.C:
			s.refreshContainer(ctx)

		case <-s.pause.WhilePaused():
			// Stopped here rather than left to the outer loop, which waits
			// before looking again. Someone who just asked for their own
			// network back should not watch the tunnel stay up for another
			// five seconds.
			s.stopContainerForPause(ctx)
			return nil

		case <-s.restart[status.CompVPN]:
			if !s.containerMatchesConfig(ctx, id) {
				s.logf(logbus.LevelInfo, "the VPN container predates the current config; recreating it")
				s.setComp(status.CompVPN, status.PhaseStarting, "recreating", nil)
				return errSpecChanged
			}

			s.logf(logbus.LevelInfo, "restarting the VPN container on request")
			s.setComp(status.CompVPN, status.PhaseStarting, "restarting", nil)
			if err := s.docker.Restart(ctx, id, 15*time.Second); err != nil {
				s.setComp(status.CompVPN, status.PhaseFailed, "restart failed", err)
				s.logf(logbus.LevelError, "container restart failed: %v", err)
				continue
			}
			s.bumpGeneration("VPN container restarted")
			s.refreshContainer(ctx)
		}
	}
}

// onContainerEvent reacts to the container's lifecycle. A tunnel that has just
// come back means every previously-learned path and every cached answer was
// decided under different conditions, which is what the generation counter
// records.
func (s *Supervisor) onContainerEvent(ctx context.Context, ev dockerctl.Event) {
	switch ev.Action {
	case "start", "restart", "unpause":
		s.bumpGeneration("container " + ev.Action)
	case "die", "stop", "kill", "pause":
		s.logf(logbus.LevelWarn, "VPN container %s", ev.Action)
	}
	if strings.HasPrefix(ev.Action, "health_status") {
		s.logf(logbus.LevelInfo, "VPN container %s", ev.Action)
		if strings.Contains(ev.Action, "healthy") && !strings.Contains(ev.Action, "unhealthy") {
			s.bumpGeneration("container became healthy")
		}
	}
	s.refreshContainer(ctx)
}

func (s *Supervisor) refreshContainer(ctx context.Context) {
	s.mu.Lock()
	id := s.containerID
	s.mu.Unlock()
	if id == "" {
		return
	}

	ins, err := s.docker.Inspect(ctx, id)
	if err != nil {
		if ctx.Err() == nil {
			s.setComp(status.CompVPN, status.PhaseFailed, "inspect failed", err)
		}
		return
	}

	hs := ins.HealthStatus()
	switch {
	case !ins.State.Running:
		s.setComp(status.CompVPN, status.PhaseStopped,
			fmt.Sprintf("container %s (exit %d)", ins.State.Status, ins.State.ExitCode), nil)
	case hs == "healthy" || hs == "none":
		s.setComp(status.CompVPN, status.PhaseRunning, "tunnel up, SOCKS reachable", nil)
	case hs == "starting":
		s.setComp(status.CompVPN, status.PhaseStarting, "healthcheck starting", nil)
	default:
		// Public traffic is unaffected: the resolver falls back to public DNS
		// and the racer falls back to direct. Only VPN traffic is down, and
		// that is meant to fail closed.
		s.setComp(status.CompVPN, status.PhaseDegraded,
			"tunnel down; public traffic unaffected, VPN traffic fails closed", nil)
	}
}

func (s *Supervisor) streamContainerLogs(ctx context.Context, id string) {
	rc, err := s.docker.Logs(ctx, id, true, 50)
	if err != nil {
		if ctx.Err() == nil {
			s.logf(logbus.LevelWarn, "container logs unavailable: %v", err)
		}
		return
	}
	defer rc.Close()

	_ = dockerctl.DemuxLines(rc, func(_ dockerctl.StdStream, line string) {
		lvl, msg := logbus.ClassifyPlain(line)
		s.o.Bus.Publish(logbus.SourceVPN, lvl, msg)
	})
}

func (s *Supervisor) bumpGeneration(reason string) {
	s.mu.Lock()
	s.generation++
	gen := s.generation
	s.mu.Unlock()

	s.logf(logbus.LevelInfo, "network generation %d: %s", gen, reason)
	s.broadcast()
}

func (s *Supervisor) setComp(name string, phase status.Phase, detail string, err error) {
	s.mu.Lock()
	prev := s.comps[name]

	next := status.Component{
		Name:     name,
		Phase:    phase,
		Detail:   detail,
		Since:    prev.Since,
		Restarts: prev.Restarts,
		LastErr:  prev.LastErr,
	}
	if prev.Phase != phase {
		next.Since = time.Now()
	}
	if phase == status.PhaseRunning && prev.Phase == status.PhaseBackoff {
		next.Restarts = prev.Restarts + 1
	}
	if err != nil {
		next.LastErr = err.Error()
	}

	changed := prev != next
	s.comps[name] = next
	s.mu.Unlock()

	if changed {
		s.broadcast()
	}
}

func (s *Supervisor) signalRestart(name string) {
	ch, ok := s.restart[name]
	if !ok {
		return
	}
	select {
	case ch <- struct{}{}:
	default: // one pending request is enough
	}
}

// --- ipc.Backend ---

func (s *Supervisor) Snapshot() status.Snapshot {
	s.mu.Lock()
	comps := make([]status.Component, 0, len(s.order))
	for _, name := range s.order {
		comps = append(comps, s.comps[name])
	}
	resolvers := make([]status.Resolver, len(s.resolvers))
	copy(resolvers, s.resolvers)

	snap := status.Snapshot{
		Components: comps,
		Resolvers:  resolvers,
		Paused:     s.pause.Paused(),
		Generation: s.generation,
		Since:      s.started,
		Version:    s.o.Version,
	}
	s.mu.Unlock()

	if snap.Paused {
		snap.Overall, snap.Reason = status.AggregatePaused()
	} else {
		snap.Overall, snap.Reason = status.Aggregate(comps)
	}
	return snap
}

func (s *Supervisor) Restart(component string) error {
	switch component {
	case status.CompVPN, status.CompDNSRouter, status.CompRacer:
		s.signalRestart(component)
		return nil
	case status.CompSingBox:
		s.sb.Restart()
		return nil
	case "all":
		s.signalRestart(status.CompVPN)
		s.signalRestart(status.CompDNSRouter)
		s.signalRestart(status.CompRacer)
		s.sb.Restart()
		return nil
	default:
		return fmt.Errorf("unknown component %q (want vpn, singbox, dns-router, racer or all)", component)
	}
}

func (s *Supervisor) Retry() { s.sb.Retry() }

func (s *Supervisor) Logs(since uint64, source logbus.Source) []logbus.Entry {
	return s.o.Bus.Snapshot(since, source)
}

func (s *Supervisor) SubscribeLogs(buffer int) (<-chan logbus.Entry, func()) {
	return s.o.Bus.Subscribe(buffer)
}

func (s *Supervisor) SubscribeStatus(buffer int) (<-chan status.Snapshot, func()) {
	if buffer <= 0 {
		buffer = 16
	}
	ch := make(chan status.Snapshot, buffer)

	s.mu.Lock()
	id := s.nextStatusID
	s.nextStatusID++
	s.statusSubs[id] = ch
	s.mu.Unlock()

	return ch, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if c, ok := s.statusSubs[id]; ok {
			delete(s.statusSubs, id)
			close(c)
		}
	}
}

func (s *Supervisor) Version() string { return s.o.Version }

func (s *Supervisor) broadcast() {
	snap := s.Snapshot()

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ch := range s.statusSubs {
		select {
		case ch <- snap:
		default: // a slow client gets the next one
		}
	}
}
