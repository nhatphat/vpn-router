// Package config loads vpnctl's single YAML configuration file.
//
// The file is user-owned (~/.config/vpnctl/config.yaml by default) while the
// daemon reading it runs as root, so Validate deliberately refuses anything
// that would let a non-root writer influence what root executes. See
// checkExecutable.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"vpn-router/internal/resolver"
)

// DefaultSingBoxVersion is the sing-box release vpnctl installs and is tested
// against. The generated document uses features from 1.13, so going below that
// will not work.
const DefaultSingBoxVersion = "1.13.19"

// Hashes maps "<version>/<GOOS>-<GOARCH>" to a checksum.
type Hashes map[string]string

// PinKey builds the key for one version on one platform.
func PinKey(version, platform string) string { return version + "/" + platform }

// Platform is the current GOOS-GOARCH, the second half of a pin key.
func Platform() string { return runtime.GOOS + "-" + runtime.GOARCH }

// Lookup returns the pin for a version on this machine, and whether there is
// one. A missing pin is a normal state, not an error: it means nobody has
// recorded a hash for that combination.
func (h Hashes) Lookup(version string) (string, bool) {
	sum, ok := h[PinKey(version, Platform())]
	return sum, ok
}

// defaultSingBoxHashes pins the release named by DefaultSingBoxVersion, so a
// stock install verifies its download without anyone configuring anything.
// The keys are built from that constant, so the version cannot be bumped
// without the pins visibly becoming stale.
func defaultSingBoxHashes() Hashes {
	return Hashes{
		PinKey(DefaultSingBoxVersion, "darwin-arm64"): "5b75c1dec19488675f725adc7a6e3a7301a553117af835dc47669b1fa918976b",
		PinKey(DefaultSingBoxVersion, "darwin-amd64"): "078164e43464f2282ae526151411320582c3e60a0294cec24a627edf205305a6",
	}
}

// Duration is a time.Duration that unmarshals from strings like "900ms".
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) D() time.Duration { return time.Duration(d) }

type Config struct {
	Docker     Docker     `yaml:"docker"`
	VPN        VPN        `yaml:"vpn"`
	DNSRouter  DNSRouter  `yaml:"dns_router"`
	Racer      Racer      `yaml:"racer"`
	SingBox    SingBox    `yaml:"singbox"`
	Supervisor Supervisor `yaml:"supervisor"`
	UI         UI         `yaml:"ui"`

	// Dir is the directory the file was loaded from; relative paths in the
	// file resolve against it. Not settable from YAML.
	Dir  string `yaml:"-"`
	Path string `yaml:"-"`
}

type Docker struct {
	Project    string `yaml:"project"`
	Host       string `yaml:"host"`
	Socks      string `yaml:"socks"`
	Container  string `yaml:"container"`
	VPNDNSFile string `yaml:"vpn_dns_file"`
}

type VPN struct {
	Config     string   `yaml:"config"`
	AuthFile   string   `yaml:"auth_file"`
	EnvFile    string   `yaml:"env_file"`
	RetryDelay Duration `yaml:"retry_delay"`
}

type DNSRouter struct {
	Listen string `yaml:"listen"`
	// ResolverDomains are suffixes macOS should send straight here, by way of
	// a scoped resolver in /etc/resolver. The TUN already captures port 53
	// while sing-box runs, so this is not about routing: it states, per
	// suffix and independently of the tunnel, where those names are
	// answered — so an internal name is never asked of a public resolver.
	ResolverDomains ResolverDomains `yaml:"resolver_domains"`
	PublicDNS       string          `yaml:"public_dns"`
	BindInterface   string          `yaml:"bind_interface"`
	QueryTimeout    Duration        `yaml:"query_timeout"`
	GraceWindow     Duration        `yaml:"grace_window"`
	RefreshInterval Duration        `yaml:"refresh_interval"`
}

type Racer struct {
	Listen      string   `yaml:"listen"`
	DialTimeout Duration `yaml:"dial_timeout"`
	// RelayBuffer is how much the relay moves per read-write cycle.
	//
	// The default is what measurement supports, not what theory suggested.
	// The reasoning that a read-then-write loop caps throughput near
	// buffer/RTT is sound, and the arithmetic matched the slow transfers that
	// prompted this setting almost exactly — but sweeping 32KB to 2MB moved
	// nothing, because the cause was elsewhere entirely. It is kept as a knob
	// for links with a much longer round trip than the one it was measured
	// on, where the ceiling is real.
	RelayBuffer Size `yaml:"relay_buffer"`

	// LearnedTTL bounds how long the racer trusts a path it worked out
	// earlier. The network generation counter expires paths as soon as
	// anything visible changes — the tunnel coming up, the interface getting
	// a new address — and this covers the changes nothing noticed.
	LearnedTTL Duration `yaml:"learned_ttl"`
}

type SingBox struct {
	Version string `yaml:"version"`
	// SHA256 pins published binaries, keyed by "<version>/<GOOS>-<GOARCH>".
	//
	// Both halves of the key are load-bearing. The release is built per
	// architecture, so one hash could only ever verify one kind of machine.
	// And it is built per version, so a pin that does not name its version
	// turns a Version change into a checksum mismatch — which reads as
	// "someone tampered with the download" when it means "nobody has pinned
	// this version yet". A key that cannot match simply means unpinned.
	//
	// The pin describes the published release. A binary copied from local
	// disk (install -from-path) has different provenance — Homebrew, for
	// one, builds from source and produces a different hash — so the pin is
	// not applied to it.
	SHA256 Hashes `yaml:"sha256"`
	Binary string `yaml:"binary"`
	// AllowUnsafeBinary permits executing a sing-box binary that is writable
	// by a non-root user (e.g. Homebrew's copy under /opt/homebrew). Off by
	// default: root must not exec what an unprivileged writer controls.
	AllowUnsafeBinary bool   `yaml:"allow_unsafe_binary"`
	LogLevel          string `yaml:"log_level"`
	ForceVPNRules     string `yaml:"force_vpn_rules"`
	// RouterProcessName is the value of the first route rule's process_name,
	// which keeps the router's own direct traffic from being recaptured by
	// the TUN. Empty means "this executable's own name", resolved at runtime.
	RouterProcessName string         `yaml:"router_process_name"`
	TUN               TUN            `yaml:"tun"`
	RawOverrides      map[string]any `yaml:"raw_overrides"`
}

type TUN struct {
	InterfaceName string   `yaml:"interface_name"`
	Address       []string `yaml:"address"`
	MTU           int      `yaml:"mtu"`
	Stack         string   `yaml:"stack"`
	StrictRoute   bool     `yaml:"strict_route"`
}

type Backoff struct {
	Min Duration `yaml:"min"`
	Max Duration `yaml:"max"`
}

type Breaker struct {
	Failures int      `yaml:"failures"`
	Window   Duration `yaml:"window"`
}

type Supervisor struct {
	HealthInterval   Duration `yaml:"health_interval"`
	SingBoxBackoff   Backoff  `yaml:"singbox_backoff"`
	SingBoxBreaker   Breaker  `yaml:"singbox_breaker"`
	ContainerBackoff Backoff  `yaml:"container_backoff"`
	StateDir         string   `yaml:"state_dir"`
}

type UI struct {
	WebListen      string `yaml:"web_listen"`
	LogBufferLines int    `yaml:"log_buffer_lines"`
}

// Defaults returns a Config pre-filled with the values the three
// hand-started processes use today, so an omitted field never changes
// behaviour.
func Defaults() Config {
	return Config{
		Docker: Docker{
			Project:   "vpn-router",
			Socks:     "127.0.0.1:1080",
			Container: "vpnctl-vpn",
			// Relative to the config file, and shared with the container as
			// a bind mount. See vpnbox.SharedDir for why it cannot live
			// under /usr/local.
			VPNDNSFile: "run/vpn-dns",
		},
		VPN: VPN{
			Config:     "company.ovpn",
			AuthFile:   "auth.txt",
			EnvFile:    ".env",
			RetryDelay: Duration(5 * time.Second),
		},
		DNSRouter: DNSRouter{
			Listen:          "127.0.0.1:15353",
			ResolverDomains: ResolverDomains{},
			PublicDNS:       "1.1.1.1:53",
			BindInterface:   "en0",
			QueryTimeout:    Duration(900 * time.Millisecond),
			GraceWindow:     Duration(200 * time.Millisecond),
			RefreshInterval: Duration(30 * time.Second),
		},
		Racer: Racer{
			Listen:      "127.0.0.1:15080",
			DialTimeout: Duration(1500 * time.Millisecond),
			RelayBuffer: 32 << 10,
			LearnedTTL:  Duration(60 * time.Minute),
		},
		SingBox: SingBox{
			Version:       DefaultSingBoxVersion,
			SHA256:        defaultSingBoxHashes(),
			LogLevel:      "warn",
			ForceVPNRules: "rules/force-vpn.json",
			TUN: TUN{
				InterfaceName: "utun225",
				Address:       []string{"172.19.0.1/30"},
				MTU:           9000,
				Stack:         "gvisor",
				StrictRoute:   true,
			},
			// Non-nil so that a config written as "raw_overrides: {}" is
			// identical to one that omits the key.
			RawOverrides: map[string]any{},
		},
		Supervisor: Supervisor{
			HealthInterval:   Duration(10 * time.Second),
			SingBoxBackoff:   Backoff{Min: Duration(time.Second), Max: Duration(60 * time.Second)},
			SingBoxBreaker:   Breaker{Failures: 5, Window: Duration(60 * time.Second)},
			ContainerBackoff: Backoff{Min: Duration(time.Second), Max: Duration(60 * time.Second)},
			StateDir:         "/usr/local/var/vpnctl",
		},
		UI: UI{
			WebListen:      "127.0.0.1:15900",
			LogBufferLines: 5000,
		},
	}
}

// DefaultPath is where the config lives unless overridden, honouring
// XDG_CONFIG_HOME the way ordinary CLI tools do.
func DefaultPath() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "vpnctl", "config.yaml")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "vpnctl", "config.yaml")
	}
	return "/usr/local/etc/vpnctl/config.yaml"
}

// Load reads and validates the config at path.
func Load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}

	cfg := Defaults()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", abs, err)
	}

	cfg.Path = abs
	if err := cfg.Init(filepath.Dir(abs)); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Init anchors relative paths to dir and validates. Relative paths must be
// resolved before anything is handed to sing-box or the container: sing-box
// resolves them against its own working directory, which for a daemon is "/".
func (c *Config) Init(dir string) error {
	c.Dir = dir
	c.resolvePaths()
	return c.Validate()
}

func (c *Config) resolvePaths() {
	rel := func(p *string) {
		if *p == "" || filepath.IsAbs(*p) {
			return
		}
		*p = filepath.Join(c.Dir, *p)
	}
	rel(&c.Docker.VPNDNSFile)
	rel(&c.VPN.Config)
	rel(&c.VPN.AuthFile)
	rel(&c.VPN.EnvFile)
	rel(&c.SingBox.ForceVPNRules)
	rel(&c.SingBox.Binary)
}

func (c *Config) Validate() error {
	var errs []string
	add := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }

	for _, hp := range []struct{ name, val string }{
		{"dns_router.listen", c.DNSRouter.Listen},
		{"dns_router.public_dns", c.DNSRouter.PublicDNS},
		{"racer.listen", c.Racer.Listen},
		{"docker.socks", c.Docker.Socks},
	} {
		if !strings.Contains(hp.val, ":") {
			add("%s must be host:port, got %q", hp.name, hp.val)
		}
	}

	switch c.SingBox.TUN.Stack {
	case "gvisor", "system", "mixed":
	default:
		add("singbox.tun.stack must be gvisor, system or mixed, got %q", c.SingBox.TUN.Stack)
	}

	if c.SingBox.TUN.MTU <= 0 {
		add("singbox.tun.mtu must be positive")
	}
	if len(c.SingBox.TUN.Address) == 0 {
		add("singbox.tun.address must not be empty")
	}
	if c.SingBox.TUN.InterfaceName == "" {
		add("singbox.tun.interface_name must not be empty")
	}
	if c.DNSRouter.QueryTimeout <= 0 {
		add("dns_router.query_timeout must be positive")
	}
	if c.Racer.DialTimeout <= 0 {
		add("racer.dial_timeout must be positive")
	}
	if c.Racer.RelayBuffer < 4<<10 {
		add("racer.relay_buffer must be at least 4KB, got %s", c.Racer.RelayBuffer)
	}
	if c.Racer.LearnedTTL < 0 {
		add("racer.learned_ttl must not be negative")
	}

	seen := map[string]bool{}
	for _, d := range c.DNSRouter.ResolverDomains {
		if err := resolver.ValidateDomain(d.Domain); err != nil {
			add("dns_router.resolver_domains: %v", err)
			continue
		}
		if seen[d.Domain] {
			add("dns_router.resolver_domains: %q appears twice", d.Domain)
		}
		seen[d.Domain] = true
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid config %s:\n  - %s", c.Path, strings.Join(errs, "\n  - "))
	}
	return nil
}

// CheckExecutable refuses a binary that a non-root user can replace, since
// the daemon runs it as root. Returns nil when safe, or when the config
// explicitly opts out.
func CheckExecutable(path string, allowUnsafe bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := filepath.EvalSymlinks(path)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", path, err)
		}
		return CheckExecutable(target, allowUnsafe)
	}

	unsafeReason := ""
	if st, ok := ownerAndMode(info); ok {
		if st.uid != 0 {
			unsafeReason = fmt.Sprintf("owned by uid %d, not root", st.uid)
		} else if st.mode&0o022 != 0 {
			unsafeReason = "group- or world-writable"
		}
	}

	if unsafeReason == "" {
		return nil
	}
	if allowUnsafe {
		return nil
	}
	return fmt.Errorf("refusing to run %s as root: %s "+
		"(set singbox.allow_unsafe_binary: true to override)", path, unsafeReason)
}

// UnknownFields lists keys in the file that this version does not recognise.
//
// A misspelt key is otherwise completely silent: YAML decoding ignores what it
// does not know, so "grace_windw: 5s" reads as "leave grace_window at its
// default" and nothing anywhere says otherwise. Keys can also be left behind
// by a version that has since dropped them.
//
// It is reported rather than refused. Refusing would turn a stale key into a
// daemon that will not start, which is a worse failure than an ignored line.
func UnknownFields(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)

	var probe Config
	err = dec.Decode(&probe)
	if err == nil {
		return nil, nil
	}

	var typeErr *yaml.TypeError
	if !errors.As(err, &typeErr) {
		// Not an unknown-field problem; Load reports real parse errors.
		return nil, nil
	}

	var out []string
	for _, msg := range typeErr.Errors {
		if strings.Contains(msg, "not found in type") {
			out = append(out, msg)
		}
	}
	return out, nil
}
