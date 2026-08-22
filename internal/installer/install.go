package installer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"vpn-router/internal/config"
	"vpn-router/internal/dockerctl"
	"vpn-router/internal/ipc"
	"vpn-router/internal/resolver"
	"vpn-router/internal/vpnbox"
)

type Options struct {
	// ConfigPath overrides where the config lives; empty means the target
	// user's ~/.config/vpnctl/config.yaml.
	ConfigPath string
	// SingBoxFrom copies a local sing-box instead of downloading one.
	SingBoxFrom string
	// WithMenuBar also installs the per-user LaunchAgent. The menu bar has to
	// exist for that to be useful.
	WithMenuBar bool
	// KeepStopped installs the files without starting the daemon.
	KeepStopped bool

	Logf func(string, ...any)
}

func (o Options) logf(format string, args ...any) {
	if o.Logf != nil {
		o.Logf(format, args...)
	}
}

// Record is written to /usr/local/etc/vpnctl/install.json so later runs know
// who this installation belongs to without having to guess from the
// environment — which a launchd daemon does not have.
type Record struct {
	InstalledAt  time.Time `json:"installed_at"`
	User         string    `json:"user"`
	UID          int       `json:"uid"`
	GID          int       `json:"gid"`
	ConfigPath   string    `json:"config_path"`
	VpnctlPath   string    `json:"vpnctl_path"`
	SingBoxPath  string    `json:"singbox_path"`
	SingBoxSHA   string    `json:"singbox_sha256"`
	SingBoxVer   string    `json:"singbox_version"`
	DockerSocket string    `json:"docker_socket"`
}

func Install(o Options) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("install must run as root:\n  sudo vpnctl install")
	}
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("this installer targets macOS; the container half runs anywhere but the TUN and launchd parts do not")
	}

	target, err := ResolveTarget()
	if err != nil {
		return err
	}
	o.logf("installing for %s (uid %d)", target.User, target.UID)

	for _, d := range []struct {
		path     string
		uid, gid int
		mode     os.FileMode
	}{
		{LibexecDir, 0, 0, 0o755},
		{EtcDir, 0, 0, 0o755},
		{LogDir, 0, 0, 0o755},
		{StateDir, 0, 0, 0o755},
	} {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return fmt.Errorf("create %s: %w", d.path, err)
		}
		if err := os.Chown(d.path, d.uid, d.gid); err != nil {
			return fmt.Errorf("chown %s: %w", d.path, err)
		}
	}

	if err := copySelf(); err != nil {
		return err
	}
	o.logf("installed %s", BinaryPath)

	// An update stages the new binary here and then execs it; by now it has
	// copied itself to BinaryPath, so the staged copy is finished with.
	if staged := filepath.Join(LibexecDir, UpdateStagingName); staged != "" {
		if err := os.Remove(staged); err == nil {
			o.logf("cleaned up the staged update")
		}
	}

	if err := linkOnPath(); err != nil {
		// A missing symlink only costs convenience, so it must not abort an
		// otherwise good installation.
		o.logf("could not link %s: %v", SymlinkPath, err)
	} else {
		o.logf("linked %s -> %s", SymlinkPath, BinaryPath)
	}

	configPath, created, err := ensureConfig(o, target)
	if err != nil {
		return err
	}
	if created {
		o.logf("wrote a starting config at %s", configPath)
	} else {
		o.logf("keeping the existing config at %s", configPath)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("the config is not usable yet:\n%w", err)
	}

	version := cfg.SingBox.Version
	if version == "" {
		version = config.DefaultSingBoxVersion
	}
	sum, err := InstallSingBox(version, o.SingBoxFrom, cfg.SingBox.SHA256, o.logf)
	switch {
	case errors.Is(err, ErrAlreadyInstalled):
		// Nothing was written, so saying "installed" would be a small lie —
		// and a log that says things that are not quite true is one nobody
		// reads carefully.
	case err != nil:
		return err
	default:
		o.logf("installed %s", SingBoxPath)
	}

	if err := ensureRulesFile(cfg, target, o); err != nil {
		return err
	}

	if err := ensureSharedDir(cfg, target, o); err != nil {
		return err
	}

	socket := setUpContainer(cfg, o)

	record := Record{
		InstalledAt:  time.Now(),
		User:         target.User,
		UID:          target.UID,
		GID:          target.GID,
		ConfigPath:   configPath,
		VpnctlPath:   BinaryPath,
		SingBoxPath:  SingBoxPath,
		SingBoxSHA:   sum,
		SingBoxVer:   version,
		DockerSocket: socket,
	}
	if err := writeRecord(record); err != nil {
		return err
	}

	RemoveStaleDaemonJobs(o.logf)
	RemoveStaleAgentJobs(target, o.logf)

	if err := writeFileAs(DaemonPlist, daemonPlist(configPath), 0, 0, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", DaemonPlist, err)
	}
	o.logf("wrote %s", DaemonPlist)

	if o.WithMenuBar {
		if err := writeFileAs(target.AgentPlist(), agentPlist(), target.UID, target.GID, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", target.AgentPlist(), err)
		}
		o.logf("wrote %s", target.AgentPlist())
	}

	if o.KeepStopped {
		o.logf("not starting the daemon (--keep-stopped)")
		return nil
	}

	if err := bootstrapDaemon(); err != nil {
		return fmt.Errorf("load the daemon: %w", err)
	}

	// launchd returns as soon as it has accepted the job, before the daemon
	// has done anything. Waiting for it to answer means "install" reports a
	// daemon that actually came up, and that whatever runs next — doctor, or
	// a person looking at the menu bar — sees a settled system rather than a
	// half-started one.
	if err := waitForDaemon(15 * time.Second); err != nil {
		o.logf("daemon loaded, but it has not answered yet: %v", err)
		o.logf("  watch it with: vpnctl status -w    or    sudo tail -f %s/daemon.log", LogDir)
	} else {
		o.logf("daemon loaded and answering")
	}

	if o.WithMenuBar {
		if err := bootstrapAgent(target); err != nil {
			// Not fatal: there may be no GUI session right now, and the agent
			// will start at the next login regardless.
			o.logf("menu bar not started now (%v); it will start at next login", err)
		}
	}

	return nil
}

// waitForDaemon polls the control socket until the daemon answers.
func waitForDaemon(timeout time.Duration) error {
	client := &ipc.Client{Path: ipc.DefaultSocket, Timeout: 2 * time.Second}

	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if _, err := client.Do(ipc.Request{Op: ipc.OpStatus}); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(250 * time.Millisecond)
	}
	return lastErr
}

// copySelf places the running binary where launchd will run it from, so a
// later rebuild in a source tree cannot silently change what root executes.
func copySelf() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(self)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return err
	}

	if same, _ := filepath.EvalSymlinks(BinaryPath); same == resolved {
		return nil // already running from the installed location
	}

	tmp, err := os.CreateTemp(LibexecDir, "vpnctl-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chown(tmp.Name(), 0, 0); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return err
	}
	// Rename rather than write in place: the old binary may be executing.
	return os.Rename(tmp.Name(), BinaryPath)
}

// linkOnPath points /usr/local/bin/vpnctl at the installed binary, replacing
// only a symlink we recognise so a real file someone else put there is left
// alone.
func linkOnPath() error {
	if err := os.MkdirAll(filepath.Dir(SymlinkPath), 0o755); err != nil {
		return err
	}

	switch existing, err := os.Readlink(SymlinkPath); {
	case err == nil && existing == BinaryPath:
		return nil
	case err == nil:
		if rerr := os.Remove(SymlinkPath); rerr != nil {
			return rerr
		}
	default:
		if _, serr := os.Lstat(SymlinkPath); serr == nil {
			return fmt.Errorf("%s exists and is not a symlink we created", SymlinkPath)
		}
	}

	return os.Symlink(BinaryPath, SymlinkPath)
}

// ensureConfig creates a starting config if the user has none. A config that
// already exists is never rewritten: it is the user's file, and it may hold
// customisations the installer knows nothing about.
func ensureConfig(o Options, t *Target) (path string, created bool, err error) {
	path = o.ConfigPath
	if path == "" {
		path = t.DefaultConfigPath()
	}
	if abs, aerr := filepath.Abs(path); aerr == nil {
		path = abs
	}

	if _, serr := os.Stat(path); serr == nil {
		// Make sure it really belongs to the user we are installing for. A
		// config created by root has root's group, and the control socket is
		// group-readable by exactly that group — so a wrong group here is
		// what would stop the user's own menu bar from connecting.
		if err := os.Chown(path, t.UID, t.GID); err != nil {
			o.logf("could not set ownership of %s: %v", path, err)
		}
		return path, false, nil
	}

	body := config.ExampleYAML
	// A freshly written config can point at the shared bind mount, since the
	// installer is creating it in the same breath.
	body = strings.Replace(body,
		`  vpn_dns_file: ""`,
		`  vpn_dns_file: `+filepath.Join(StateDir, "run", "vpn-dns"), 1)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return path, false, err
	}
	if err := os.Chown(filepath.Dir(path), t.UID, t.GID); err != nil {
		return path, false, err
	}
	// 0600 and owned by the user: it sits beside their VPN profile and auth
	// file, and the daemon reads it as root either way.
	if err := writeFileAs(path, body, t.UID, t.GID, 0o600); err != nil {
		return path, false, err
	}
	return path, true, nil
}

// ensureRulesFile guarantees the force-VPN rule-set exists, because sing-box
// refuses to start without a file its configuration references. An empty
// rule-set is the honest default: it forces nothing, and the user fills it in.
func ensureRulesFile(cfg *config.Config, t *Target, o Options) error {
	path := cfg.SingBox.ForceVPNRules
	if path == "" {
		return nil
	}
	if _, err := os.Stat(path); err == nil {
		return nil
	}

	if err := writeFileAs(path, emptyRuleSet, t.UID, t.GID, 0o644); err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	o.logf("created an empty force-VPN rule-set at %s", path)
	return nil
}

// ensureSharedDir creates the directory the container and the host exchange
// the VPN-pushed DNS servers through. It has to exist before the container
// starts, or the mount point is created empty and owned by root.
func ensureSharedDir(cfg *config.Config, t *Target, o Options) error {
	dir := vpnbox.SharedDir(cfg)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := os.Chown(dir, t.UID, t.GID); err != nil {
		return fmt.Errorf("chown %s: %w", dir, err)
	}
	o.logf("shared directory %s", dir)
	return nil
}

// setUpContainer builds the image and creates the container. A missing
// container runtime is not an error: it lives in the user's login session here,
// so it is legitimately absent at install time and at boot, and the daemon
// creates the container later when it appears.
func setUpContainer(cfg *config.Config, o Options) string {
	c, err := dockerctl.New(cfg.Docker.Host)
	if err != nil {
		o.logf("docker: %v", err)
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	pingCtx, cancelPing := context.WithTimeout(ctx, 5*time.Second)
	defer cancelPing()

	if err := c.Ping(pingCtx); err != nil {
		o.logf("docker: not reachable at %s.\n"+
			"    The VPN container cannot run without it. Install one (OrbStack, Docker Desktop,\n"+
			"    or colima) and start it, then run \"sudo vpnctl install\" again.\n"+
			"    Public traffic works without it; only VPN traffic is affected.",
			dockerctl.DefaultSocket)
		return ""
	}
	o.logf("docker: reachable at %s", dockerctl.DefaultSocket)

	box := vpnbox.Options{Docker: c, Cfg: cfg, Logf: o.logf}

	if err := vpnbox.StopLegacyContainers(ctx, box); err != nil {
		o.logf("could not stand down the old compose container: %v", err)
	}

	tag, err := vpnbox.EnsureImage(ctx, box)
	if err != nil {
		o.logf("image build failed: %v", err)
		return dockerctl.DefaultSocket
	}

	if _, err := vpnbox.EnsureContainer(ctx, box, tag); err != nil {
		o.logf("container not created yet: %v", err)
		o.logf("  fix the above and run \"sudo vpnctl install\" again, or let the daemon retry")
	}

	return dockerctl.DefaultSocket
}

func writeRecord(r Record) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAs(InstallRecord, string(data)+"\n", 0, 0, 0o644)
}

// LoadRecord reads the installation record, if there is one.
func LoadRecord() (*Record, error) {
	data, err := os.ReadFile(InstallRecord)
	if err != nil {
		return nil, err
	}
	var r Record
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Uninstall removes what Install added. The user's config, their secrets and
// the container are left alone: they are not ours to delete.
func Uninstall(o Options) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("uninstall must run as root:\n  sudo vpnctl uninstall")
	}

	if err := bootoutDaemon(); err != nil {
		o.logf("unloading the daemon: %v", err)
	} else {
		o.logf("daemon unloaded")
	}

	if target, err := ResolveTarget(); err == nil {
		if err := bootoutAgent(target); err == nil {
			o.logf("menu bar unloaded")
		}
		if err := os.Remove(target.AgentPlist()); err == nil {
			o.logf("removed %s", target.AgentPlist())
		}
	}

	if link, err := os.Readlink(SymlinkPath); err == nil && link == BinaryPath {
		if err := os.Remove(SymlinkPath); err == nil {
			o.logf("removed %s", SymlinkPath)
		}
	}

	if target, err := ResolveTarget(); err == nil {
		RemoveStaleAgentJobs(target, o.logf)
	}
	RemoveStaleDaemonJobs(o.logf)

	for _, p := range []string{DaemonPlist, BinaryPath, SingBoxPath, InstallRecord} {
		if err := os.Remove(p); err == nil {
			o.logf("removed %s", p)
		}
	}

	// Removed rather than left: a scoped resolver pointing at a listener that
	// will never come back makes those names fail permanently, which is not
	// what someone uninstalling asked for.
	if res := resolver.RemoveAll(resolver.Dir, o.logf); res.Changed() {
		o.logf("removed scoped resolvers: %s", strings.Join(res.Removed, ", "))
		if err := resolver.Reload(); err != nil {
			o.logf("could not reload the system resolver: %v", err)
		}
	}

	o.logf("left in place: your config, your VPN profile and auth file, %s, and the container", StateDir)
	return nil
}
