// Package doctor checks an installation for the problems this setup is known
// to produce, and says how to fix each one.
//
// It exists because of a specific shortcoming: the installer refuses to
// overwrite a config file the user owns, which is right, but means it has no
// way to correct a value it wrote itself in an earlier version. It also exists
// because several failures here are silent by nature — a bind mount the
// container runtime does not share still "works" thanks to a fallback, and a
// path into a source checkout keeps working right up until the checkout moves.
// Neither shows up as an error anywhere.
//
// Nothing here changes anything. Every finding carries the command to run.
package doctor

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"vpn-router/container"
	"vpn-router/internal/config"
	"vpn-router/internal/dockerctl"
	"vpn-router/internal/installer"
	"vpn-router/internal/ipc"
	"vpn-router/internal/resolver"
	"vpn-router/internal/singbox"
	"vpn-router/internal/status"
	"vpn-router/internal/vpnbox"
)

type Level string

const (
	LevelOK   Level = "ok"
	LevelWarn Level = "warn"
	LevelFail Level = "fail"
)

type Check struct {
	Name   string
	Level  Level
	Detail string
	// Fix is what to do about it, phrased as something to run or edit.
	Fix string
}

type Report struct {
	Checks []Check
}

func (r *Report) add(name string, level Level, detail, fix string) {
	r.Checks = append(r.Checks, Check{Name: name, Level: level, Detail: detail, Fix: fix})
}

func (r *Report) ok(name, detail string)        { r.add(name, LevelOK, detail, "") }
func (r *Report) warn(name, detail, fix string) { r.add(name, LevelWarn, detail, fix) }
func (r *Report) fail(name, detail, fix string) { r.add(name, LevelFail, detail, fix) }

// Failed reports whether anything needs attention badly enough to exit
// non-zero.
func (r *Report) Failed() bool {
	for _, c := range r.Checks {
		if c.Level == LevelFail {
			return true
		}
	}
	return false
}

func (r *Report) Counts() (ok, warn, fail int) {
	for _, c := range r.Checks {
		switch c.Level {
		case LevelOK:
			ok++
		case LevelWarn:
			warn++
		case LevelFail:
			fail++
		}
	}
	return
}

type Options struct {
	ConfigPath string
	SocketPath string
}

// Run performs every check it can. A check that cannot run because an earlier
// one failed is reported as such rather than skipped silently.
func Run(o Options) *Report {
	r := &Report{}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	configPath := o.ConfigPath
	if configPath == "" {
		configPath = config.DefaultPath()
	}

	cfg := checkConfig(r, configPath)
	if cfg == nil {
		return r
	}

	checkReferencedFiles(r, cfg)
	checkIndependence(r, cfg)
	checkSharedDir(r, cfg)
	checkResolvers(r, cfg)
	checkChecksumPin(r, cfg)
	binary := checkSingBoxBinary(r, cfg)
	checkDocument(r, cfg, binary)
	checkDaemon(r, o.SocketPath)
	checkPorts(r, cfg, o.SocketPath)
	checkDocker(ctx, r, cfg)

	return r
}

func checkConfig(r *Report, path string) *config.Config {
	if _, err := os.Stat(path); err != nil {
		r.fail("config", fmt.Sprintf("no config at %s", path),
			"sudo vpnctl install")
		return nil
	}

	cfg, err := config.Load(path)
	if err != nil {
		r.fail("config", err.Error(), "fix the file, then: vpnctl reload")
		return nil
	}

	r.ok("config", path)

	// A key this version does not know is silently ignored by the YAML
	// decoder, so a typo reads as "use the default" and says nothing.
	if unknown, err := config.UnknownFields(path); err == nil && len(unknown) > 0 {
		r.warn("config keys", fmt.Sprintf("%d unrecognised: %s", len(unknown), strings.Join(unknown, "; ")),
			"remove them, or fix the spelling — they are being ignored")
	}

	return cfg
}

func checkReferencedFiles(r *Report, cfg *config.Config) {
	type ref struct {
		label, path string
		secret      bool
	}

	refs := []ref{
		{"vpn profile", cfg.VPN.Config, true},
		{"auth file", cfg.VPN.AuthFile, true},
		{"env file", cfg.VPN.EnvFile, true},
		{"force-vpn rules", cfg.SingBox.ForceVPNRules, false},
	}

	for _, f := range refs {
		if f.path == "" {
			continue
		}

		info, err := os.Stat(f.path)
		if err != nil {
			fix := fmt.Sprintf("put it at %s", f.path)
			if f.label == "force-vpn rules" {
				fix = "sudo vpnctl install  (writes an empty rule-set)"
			}
			r.fail(f.label, fmt.Sprintf("missing: %s", f.path), fix)
			continue
		}

		if f.secret && info.Mode().Perm()&0o077 != 0 {
			r.warn(f.label, fmt.Sprintf("%s is readable by others (mode %o)", f.path, info.Mode().Perm()),
				fmt.Sprintf("chmod 600 %s", f.path))
			continue
		}

		r.ok(f.label, f.path)
	}

	if cfg.VPN.EnvFile == "" {
		return
	}
	env, err := vpnbox.LoadEnvFile(cfg.VPN.EnvFile)
	if err != nil {
		r.fail("totp secret", err.Error(), fmt.Sprintf("fix %s", cfg.VPN.EnvFile))
		return
	}
	if env["TOTP_SECRET"] == "" {
		r.fail("totp secret", fmt.Sprintf("TOTP_SECRET is not set in %s", cfg.VPN.EnvFile),
			fmt.Sprintf("add TOTP_SECRET=... to %s, then: sudo vpnctl install", cfg.VPN.EnvFile))
		return
	}
	r.ok("totp secret", "set")
}

// checkIndependence looks for paths that reach outside the config directory.
// A running installation that reads its inputs from a source checkout keeps
// working until the checkout is moved or deleted, and then fails in a way that
// looks unrelated to the checkout.
func checkIndependence(r *Report, cfg *config.Config) {
	outside := map[string]string{}

	for label, path := range map[string]string{
		"vpn.config":              cfg.VPN.Config,
		"vpn.auth_file":           cfg.VPN.AuthFile,
		"vpn.env_file":            cfg.VPN.EnvFile,
		"singbox.force_vpn_rules": cfg.SingBox.ForceVPNRules,
		"docker.vpn_dns_file":     cfg.Docker.VPNDNSFile,
	} {
		if path == "" {
			continue
		}
		if !strings.HasPrefix(path, cfg.Dir+string(filepath.Separator)) {
			outside[label] = path
		}
	}

	if len(outside) == 0 {
		r.ok("independence", "every input is inside "+cfg.Dir)
		return
	}

	var lines []string
	for label, path := range outside {
		lines = append(lines, fmt.Sprintf("%s -> %s", label, path))
	}
	r.warn("independence",
		"these read from outside the config directory: "+strings.Join(lines, ", "),
		"sudo vpnctl migrate <that directory>  (copies them in and repoints the config)")
}

// checkSharedDir covers a failure that hides itself: a bind mount whose host
// path the container runtime does not share resolves inside the runtime's own
// virtual machine. The container writes the file, the host never sees it, and
// the DNS router quietly falls back to reading it through the Engine API.
func checkSharedDir(r *Report, cfg *config.Config) {
	path := cfg.Docker.VPNDNSFile
	if path == "" {
		r.warn("shared file", "not configured, so DNS servers are read through the Engine API on every refresh",
			"set docker.vpn_dns_file: run/vpn-dns, then: vpnctl reload")
		return
	}

	if !strings.HasPrefix(path, "/Users/") {
		r.fail("shared file", fmt.Sprintf("%s is outside /Users, which a container runtime typically does not share", path),
			"set docker.vpn_dns_file: run/vpn-dns, then: vpnctl reload")
		return
	}

	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); err != nil {
		r.warn("shared file", fmt.Sprintf("%s does not exist yet", dir), "sudo vpnctl install")
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		r.warn("shared file", fmt.Sprintf("%s has not appeared; the DNS router is falling back to the Engine API", path),
			"check that the VPN has connected at least once: vpnctl logs -source vpn")
		return
	}

	r.ok("shared file", fmt.Sprintf("%s (updated %s ago)", path, time.Since(info.ModTime()).Round(time.Second)))
}

// checkChecksumPin catches a configuration whose sing-box version nothing has
// pinned. It is a warning rather than a failure: HTTPS to the release host
// authenticates the download, so an unpinned install is not unverified, only
// unreproducible.
func checkChecksumPin(r *Report, cfg *config.Config) {
	version := cfg.SingBox.Version
	if version == "" {
		version = config.DefaultSingBoxVersion
	}
	key := config.PinKey(version, config.Platform())

	if _, ok := cfg.SingBox.SHA256.Lookup(version); ok {
		r.ok("checksum pin", key)
		return
	}

	r.warn("checksum pin", key+" is not pinned",
		"sudo vpnctl install  (prints the hash and the key to paste under singbox.sha256)")
}

// checkResolvers compares the configured suffixes against what is actually in
// /etc/resolver. Drift is possible in both directions: the daemon applies the
// list at startup and on reload, so a config edited since then has not taken
// effect, and a file written by hand for the same suffix is deliberately left
// alone rather than taken over.
func checkResolvers(r *Report, cfg *config.Config) {
	domains := cfg.DNSRouter.ResolverDomains
	managed := resolver.Managed(resolver.Dir)

	if len(domains) == 0 && len(managed) == 0 {
		r.ok("scoped resolvers", "none configured")
		return
	}

	host, portStr, err := net.SplitHostPort(cfg.DNSRouter.Listen)
	if err != nil {
		r.fail("scoped resolvers", "dns_router.listen: "+err.Error(), "fix the config, then: vpnctl reload")
		return
	}
	port, _ := strconv.Atoi(portStr)
	want := fmt.Sprintf("nameserver %s\nport %d", host, port)

	inManaged := map[string]bool{}
	for _, d := range managed {
		inManaged[d] = true
	}

	configured := map[string]bool{}
	var problems, states []string

	for _, entry := range domains {
		configured[entry.Domain] = true

		path := filepath.Join(resolver.Dir, entry.Domain)
		body, err := os.ReadFile(path)
		present := err == nil

		switch {
		case !entry.Enabled && present && inManaged[entry.Domain]:
			// Off but still installed means the system resolver is still
			// sending those names here, so "off" is not true yet.
			problems = append(problems, entry.Domain+" is switched off but its resolver file is still installed")
		case !entry.Enabled:
			states = append(states, entry.Domain+" off")
		case !present:
			problems = append(problems, entry.Domain+" is switched on but has no resolver file")
		case !inManaged[entry.Domain]:
			problems = append(problems, entry.Domain+" is answered by a file vpnctl did not write")
		case !strings.Contains(string(body), want):
			problems = append(problems, entry.Domain+" points somewhere other than "+cfg.DNSRouter.Listen)
		default:
			states = append(states, entry.Domain+" on")
		}
	}

	for _, d := range managed {
		if !configured[d] {
			problems = append(problems, d+" is installed but no longer in the config")
		}
	}

	if len(problems) > 0 {
		detail := strings.Join(problems, "; ")
		if len(states) > 0 {
			detail += " (" + strings.Join(states, ", ") + ")"
		}
		r.warn("scoped resolvers", detail, "vpnctl reload")
		return
	}

	r.ok("scoped resolvers", strings.Join(states, ", ")+" -> "+cfg.DNSRouter.Listen)
}

func checkSingBoxBinary(r *Report, cfg *config.Config) string {
	candidates := []string{cfg.SingBox.Binary, installer.SingBoxPath}

	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, err := os.Stat(c); err != nil {
			continue
		}
		if err := config.CheckExecutable(c, cfg.SingBox.AllowUnsafeBinary); err != nil {
			r.fail("sing-box binary", err.Error(),
				"sudo vpnctl install -from-path  (installs a root-owned copy)")
			return ""
		}
		r.ok("sing-box binary", c)
		return c
	}

	r.fail("sing-box binary", "no usable binary found", "sudo vpnctl install")
	return ""
}

func checkDocument(r *Report, cfg *config.Config, binary string) {
	in, err := singbox.FromConfig(cfg, "vpnctl")
	if err != nil {
		r.fail("sing-box config", err.Error(), "fix the config, then: vpnctl reload")
		return
	}
	doc, err := singbox.Generate(in)
	if err != nil {
		r.fail("sing-box config", err.Error(), "fix the config, then: vpnctl reload")
		return
	}
	if binary == "" {
		r.warn("sing-box config", "generated, but not validated: no binary to check it with", "sudo vpnctl install")
		return
	}
	if err := singbox.Validate(binary, doc); err != nil {
		r.fail("sing-box config", err.Error(), "fix the config, then: vpnctl reload")
		return
	}
	r.ok("sing-box config", fmt.Sprintf("%d bytes, accepted by sing-box", len(doc)))
}

func checkDaemon(r *Report, socketPath string) {
	if !installer.DaemonLoaded() {
		r.fail("daemon", "launchd does not have "+installer.DaemonLabel, "sudo vpnctl install")
		return
	}

	c := &ipc.Client{Path: socketPath, Timeout: 3 * time.Second}
	resp, err := c.Do(ipc.Request{Op: ipc.OpStatus})
	if err != nil {
		r.fail("daemon", "loaded, but its control socket does not answer: "+err.Error(),
			"sudo launchctl kickstart -k system/"+installer.DaemonLabel)
		return
	}

	snap := resp.Status
	detail := fmt.Sprintf("%s (%s)", snap.Overall, snap.Reason)

	// Mirror the daemon's own verdict rather than reporting "ok" for having
	// answered: a reachable daemon that says something is wrong is not ok.
	switch snap.Overall {
	case status.OverallGreen:
		r.ok("daemon", detail)
	case status.OverallYellow:
		r.warn("daemon", detail, "vpnctl status")
	default:
		r.fail("daemon", detail, "vpnctl status && vpnctl logs -source supervisor")
	}

	for _, comp := range snap.Components {
		switch comp.Phase {
		case status.PhaseRunning:
			r.ok("  "+comp.Name, comp.Detail)
		case status.PhaseSafeMode:
			r.fail("  "+comp.Name, comp.Detail, "vpnctl retry")
		case status.PhaseFailed:
			r.fail("  "+comp.Name, strings.TrimSpace(comp.Detail+" "+comp.LastErr),
				"vpnctl restart "+comp.Name)
		default:
			r.warn("  "+comp.Name, string(comp.Phase)+": "+comp.Detail, "vpnctl logs -source supervisor")
		}
	}
}

// checkPorts distinguishes "our daemon holds the port" from "something else
// does", which is the difference between healthy and unfixable-by-restarting.
func checkPorts(r *Report, cfg *config.Config, socketPath string) {
	daemonUp := false
	c := &ipc.Client{Path: socketPath, Timeout: 2 * time.Second}
	if _, err := c.Do(ipc.Request{Op: ipc.OpVersion}); err == nil {
		daemonUp = true
	}

	for _, p := range []struct {
		label, network, addr string
	}{
		{"dns port", "udp", cfg.DNSRouter.Listen},
		{"racer port", "tcp", cfg.Racer.Listen},
	} {
		free := portFree(p.network, p.addr)

		switch {
		case daemonUp && !free:
			r.ok(p.label, p.addr+" held by the daemon")
		case daemonUp && free:
			r.warn(p.label, p.addr+" is not bound even though the daemon is up",
				"vpnctl logs -source supervisor")
		case !daemonUp && free:
			r.ok(p.label, p.addr+" is free")
		default:
			r.fail(p.label, p.addr+" is held by another process while the daemon is down",
				fmt.Sprintf("find it with: lsof -nP -i%s@%s", strings.ToUpper(p.network), p.addr))
		}
	}
}

func portFree(network, addr string) bool {
	switch network {
	case "udp":
		c, err := net.ListenPacket("udp", addr)
		if err != nil {
			return false
		}
		c.Close()
		return true
	default:
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return false
		}
		l.Close()
		return true
	}
}

func checkDocker(ctx context.Context, r *Report, cfg *config.Config) {
	c, err := dockerctl.New(cfg.Docker.Host)
	if err != nil {
		r.fail("docker", err.Error(), "set docker.host in the config")
		return
	}

	if err := c.Ping(ctx); err != nil {
		r.warn("docker", "not reachable at "+dockerctl.DefaultSocket+
			" (it starts with your login session, so this is expected before login)",
			"start your container runtime (OrbStack, Docker Desktop, colima)")
		return
	}
	r.ok("docker", "reachable at "+dockerctl.DefaultSocket)

	tag, err := container.ImageTag()
	if err != nil {
		r.fail("image", err.Error(), "")
		return
	}
	built, err := c.ImageExists(ctx, tag)
	if err != nil {
		r.warn("image", err.Error(), "")
		return
	}
	if !built {
		r.fail("image", tag+" is not built", "sudo vpnctl install")
		return
	}
	r.ok("image", tag)

	list, err := c.ListByLabel(ctx, vpnbox.LabelOwner+"=true")
	if err != nil {
		r.warn("container", err.Error(), "")
		return
	}
	if len(list) == 0 {
		r.fail("container", "no container managed by vpnctl", "sudo vpnctl install")
		return
	}

	ct := list[0]
	ins, err := c.Inspect(ctx, ct.ID)
	if err != nil {
		r.warn("container", err.Error(), "")
		return
	}

	switch {
	case !ins.State.Running:
		r.fail("container", fmt.Sprintf("%s is %s", ct.Name(), ins.State.Status),
			"vpnctl restart vpn")
	case ins.HealthStatus() == "unhealthy":
		r.fail("container", ct.Name()+" is unhealthy (the tunnel is probably down)",
			"vpnctl logs -source vpn")
	case ins.HealthStatus() == "starting":
		r.warn("container", ct.Name()+" is still starting its healthcheck", "wait, then run this again")
	default:
		r.ok("container", fmt.Sprintf("%s, %s", ct.Name(), ins.State.Status))
	}

	// A container whose spec no longer matches the config is about to be
	// recreated by the daemon; saying so avoids surprise at the restart.
	spec, err := vpnbox.Spec(cfg, tag)
	if err == nil && ct.Labels[vpnbox.LabelSpec] != spec.Labels[vpnbox.LabelSpec] {
		r.warn("container spec", "the container predates the current config and will be recreated",
			"vpnctl restart vpn")
	}
}
