package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"vpn-router/internal/config"
	"vpn-router/internal/installer"
	"vpn-router/internal/ipc"
	"vpn-router/internal/logbus"
	"vpn-router/internal/supervisor"
)

// --- daemon and its clients ---

var version = "dev"

func daemon(args []string) error {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yaml")
	socketPath := fs.String("socket", ipc.DefaultSocket, "control socket path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if os.Geteuid() != 0 {
		// sing-box cannot create a TUN or edit the routing table otherwise,
		// and the whole point of the daemon is to hold that privilege once so
		// nothing else has to ask for it again.
		return errors.New("the daemon must run as root: sing-box needs it to create the TUN " +
			"interface and edit the routing table.\n\nInstall it as a launchd daemon instead, " +
			"which asks for authorisation once:\n  sudo vpnctl install")
	}

	cfg, doc, err := generate(*configPath)
	if err != nil {
		return err
	}

	binary, err := resolveSingBox(cfg)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(cfg.Supervisor.StateDir, 0o755); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}

	bus := logbus.New(cfg.UI.LogBufferLines)
	bus.Publishf(logbus.SourceSupervisor, logbus.LevelInfo,
		"vpnctl %s starting: config=%s singbox=%s", version, cfg.Path, binary)
	warnAboutSharing(cfg, bus)

	// Mirror the bus to stderr, which launchd captures into the daemon's log
	// file. Without this a crash before the socket exists would be invisible.
	go mirrorToStderr(bus)

	exe, err := os.Executable()
	if err != nil {
		return err
	}

	sup, err := supervisor.New(supervisor.Options{
		Cfg:           cfg,
		Bus:           bus,
		VpnctlExe:     exe,
		SingBoxDoc:    doc,
		SingBoxBinary: binary,
		Version:       version,
		RouterProcess: routerProcessName(),
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	done := make(chan struct{})
	srv := &ipc.Server{
		Path:    *socketPath,
		PeerGID: controlSocketGID(cfg, bus),
		Backend: sup,
		Logf:    bus.Logf(logbus.SourceSupervisor, logbus.LevelWarn),
	}
	go func() {
		if err := srv.Serve(done); err != nil {
			bus.Publishf(logbus.SourceSupervisor, logbus.LevelError, "control socket: %v", err)
		}
	}()

	err = sup.Run(ctx)
	close(done)

	if errors.Is(err, context.Canceled) {
		bus.Publish(logbus.SourceSupervisor, logbus.LevelInfo, "vpnctl stopped")
		return nil
	}
	return err
}

// warnAboutSharing flags a shared-file path the container runtime probably
// cannot bind-mount.
//
// This failure is silent by construction: the container writes the file
// happily into its own virtual machine, the host never sees it, and the DNS
// router falls back to reading the file through the Engine API — so everything
// keeps working, a little slower, with nothing to indicate why. Saying so at
// startup is the only way it becomes visible.
func warnAboutSharing(cfg *config.Config, bus *logbus.Bus) {
	path := cfg.Docker.VPNDNSFile
	if path == "" || strings.HasPrefix(path, cfg.Dir) {
		return
	}
	if strings.HasPrefix(path, "/Users/") {
		return // outside the config directory, but still in the shared area
	}

	bus.Publishf(logbus.SourceSupervisor, logbus.LevelWarn,
		"docker.vpn_dns_file is %s, which a container runtime typically does not share with its "+
			"virtual machine; the container will write it somewhere the host cannot see. "+
			"Put it beside the config instead: vpn_dns_file: run/vpn-dns", path)
}

// controlSocketGID decides which group may talk to the daemon.
//
// The installation record is authoritative, because it names the user the
// daemon was installed for. Falling back to the config file's group covers a
// daemon started by hand, but that is the weaker signal: a config written by
// root carries root's group, and using it would lock the very user who owns
// the menu bar out of their own daemon.
func controlSocketGID(cfg *config.Config, bus *logbus.Bus) int {
	if rec, err := installer.LoadRecord(); err == nil && rec.GID > 0 {
		return rec.GID
	}

	gid := cfg.OwnerGID()
	if gid <= 0 {
		bus.Publishf(logbus.SourceSupervisor, logbus.LevelWarn,
			"cannot tell which group should reach the control socket; "+
				"run \"sudo vpnctl install\" so status and restart work without sudo")
		return -1
	}
	return gid
}

// mirrorToStderr forwards bus entries to stderr for launchd's log file.
func mirrorToStderr(bus *logbus.Bus) {
	ch, release := bus.Subscribe(512)
	defer release()
	for e := range ch {
		suffix := ""
		if e.Count > 1 {
			suffix = fmt.Sprintf(" (x%d)", e.Count)
		}
		fmt.Fprintf(os.Stderr, "%s %-10s %-5s %s%s\n",
			e.TS.Format("15:04:05"), e.Source, e.Level, e.Msg, suffix)
	}
}

// resolveSingBox picks the binary to run and refuses one that an unprivileged
// user could replace, since the daemon executes it as root.
func resolveSingBox(cfg *config.Config) (string, error) {
	candidates := []string{cfg.SingBox.Binary, installer.SingBoxPath}
	if found, err := exec.LookPath("sing-box"); err == nil {
		candidates = append(candidates, found)
	}

	var rejected []string
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, err := os.Stat(c); err != nil {
			continue
		}
		if err := config.CheckExecutable(c, cfg.SingBox.AllowUnsafeBinary); err != nil {
			rejected = append(rejected, err.Error())
			continue
		}
		return c, nil
	}

	msg := "no usable sing-box binary found"
	if len(rejected) > 0 {
		msg += ":\n  " + strings.Join(rejected, "\n  ")
	}
	return "", errors.New(msg + "\n\nRun \"sudo vpnctl install\" to fetch a managed copy into " + installer.SingBoxPath)
}
