package vpnbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpn-router/internal/config"
)

// fixture builds a config directory that looks like a real installation.
func fixture(t *testing.T) *config.Config {
	t.Helper()

	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}

	write("company.ovpn", "client\nremote vpn.example 1194\n", 0o600)
	write("auth.txt", "user\npassword\n", 0o600)
	write(".env", "# comment\nTOTP_SECRET=\"BASE32SECRET\"\nSOCKS_PORT=1080\n", 0o600)
	write("rules/force-vpn.json", `{"version":4,"rules":[]}`, 0o644)
	path := write("config.yaml", config.ExampleYAML, 0o600)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load fixture config: %v", err)
	}
	cfg.Supervisor.StateDir = filepath.Join(dir, "state")
	return cfg
}

func TestLoadEnvFileHandlesCommentsQuotesAndExport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	body := "# a comment\n\nTOTP_SECRET='sekrit'\nexport RETRY_DELAY=7\nQUOTED=\"with space\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	env, err := LoadEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}

	for key, want := range map[string]string{
		"TOTP_SECRET": "sekrit",
		"RETRY_DELAY": "7",
		"QUOTED":      "with space",
	} {
		if env[key] != want {
			t.Errorf("%s = %q, want %q", key, env[key], want)
		}
	}
}

func TestLoadEnvFileRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte("this is not an assignment\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEnvFile(path); err == nil {
		t.Error("expected an error for a malformed env file")
	}
}

// TestSpecNeverPointsIntoASourceCheckout is the test for the property that
// makes an installation independent: every host path the container binds must
// come from the config directory or the state directory, never from a
// checkout of this repository.
func TestSpecNeverPointsIntoASourceCheckout(t *testing.T) {
	cfg := fixture(t)

	spec, err := Spec(cfg, "vpnctl/vpn:abcdef123456")
	if err != nil {
		t.Fatalf("Spec: %v", err)
	}

	allowed := []string{cfg.Dir, cfg.Supervisor.StateDir}
	for _, bind := range spec.HostConfig.Binds {
		host, _, ok := strings.Cut(bind, ":")
		if !ok {
			t.Fatalf("malformed bind %q", bind)
		}

		inside := false
		for _, prefix := range allowed {
			if strings.HasPrefix(host, prefix) {
				inside = true
				break
			}
		}
		if !inside {
			t.Errorf("bind %q is outside the config and state directories %v", host, allowed)
		}
		if !filepath.IsAbs(host) {
			t.Errorf("bind %q is not an absolute path", host)
		}
	}

	if len(spec.HostConfig.Binds) != 3 {
		t.Errorf("expected 3 binds (profile, auth, shared run), got %v", spec.HostConfig.Binds)
	}
}

// TestSpecKeepsThePrivilegesTheTunnelNeeds guards the settings without which
// OpenVPN cannot create its tunnel inside the container.
func TestSpecKeepsThePrivilegesTheTunnelNeeds(t *testing.T) {
	cfg := fixture(t)
	spec, err := Spec(cfg, "vpnctl/vpn:abcdef123456")
	if err != nil {
		t.Fatal(err)
	}

	if len(spec.HostConfig.CapAdd) != 1 || spec.HostConfig.CapAdd[0] != "NET_ADMIN" {
		t.Errorf("CapAdd = %v, want [NET_ADMIN]", spec.HostConfig.CapAdd)
	}
	if len(spec.HostConfig.Devices) != 1 || spec.HostConfig.Devices[0].PathOnHost != "/dev/net/tun" {
		t.Errorf("Devices = %+v, want /dev/net/tun passed through", spec.HostConfig.Devices)
	}

	binding := spec.HostConfig.PortBindings["1080/tcp"]
	if len(binding) != 1 || binding[0].HostIP != "127.0.0.1" {
		t.Errorf("SOCKS must be published on loopback only, got %+v", binding)
	}
}

func TestSpecRefusesAMissingSecret(t *testing.T) {
	cfg := fixture(t)
	if err := os.WriteFile(filepath.Join(cfg.Dir, ".env"), []byte("SOCKS_PORT=1080\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Spec(cfg, "vpnctl/vpn:abcdef123456")
	if err == nil {
		t.Fatal("expected Spec to refuse a config with no TOTP_SECRET")
	}
	if !strings.Contains(err.Error(), "TOTP_SECRET") {
		t.Errorf("the error should name the missing key: %v", err)
	}
}

// TestSpecHashChangesWithTheConfiguration is what makes the container get
// recreated instead of silently running with stale settings.
func TestSpecHashChangesWithTheConfiguration(t *testing.T) {
	cfg := fixture(t)

	base, err := Spec(cfg, "vpnctl/vpn:aaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}

	cfg.Docker.Socks = "127.0.0.1:2080"
	changed, err := Spec(cfg, "vpnctl/vpn:aaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}

	if base.Labels[LabelSpec] == changed.Labels[LabelSpec] {
		t.Error("changing the published port did not change the spec hash")
	}
}

func TestSpecHashIsStableForTheSameConfiguration(t *testing.T) {
	cfg := fixture(t)

	first, err := Spec(cfg, "vpnctl/vpn:aaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Spec(cfg, "vpnctl/vpn:aaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}

	if first.Labels[LabelSpec] != second.Labels[LabelSpec] {
		t.Error("the spec hash is unstable, so the container would be recreated on every check")
	}
}

// TestSpecDoesNotLeakTheSecretIntoLabels keeps the TOTP secret out of places
// that are readable with `docker inspect` by anyone who can reach the socket.
func TestSpecDoesNotLeakTheSecretIntoLabels(t *testing.T) {
	cfg := fixture(t)
	spec, err := Spec(cfg, "vpnctl/vpn:aaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}

	for k, v := range spec.Labels {
		if strings.Contains(v, "BASE32SECRET") {
			t.Errorf("label %q carries the TOTP secret", k)
		}
	}
}

// TestSharedDirIsInsideTheConfigDirectory encodes a platform constraint that
// cost real debugging: a container runtime only bind-mounts host paths its
// virtual machine shares. A mount of a path under /usr/local silently
// resolved inside the runtime's own VM — the container wrote the file, the
// host never saw it, and nothing anywhere reported an error. Keeping the
// shared directory beside the config keeps it in the shared area.
func TestSharedDirIsInsideTheConfigDirectory(t *testing.T) {
	cfg := fixture(t)
	cfg.Supervisor.StateDir = "/usr/local/var/vpnctl"

	shared := SharedDir(cfg)
	if !strings.HasPrefix(shared, cfg.Dir) {
		t.Fatalf("shared dir %q is not under the config dir %q", shared, cfg.Dir)
	}
	if strings.HasPrefix(shared, "/usr/local") {
		t.Errorf("shared dir %q is under /usr/local, which the container runtime does not share", shared)
	}

	spec, err := Spec(cfg, "vpnctl/vpn:aaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, bind := range spec.HostConfig.Binds {
		if strings.HasPrefix(bind, shared+":") {
			found = true
		}
		if strings.HasPrefix(bind, "/usr/local") {
			t.Errorf("bind %q points into /usr/local", bind)
		}
	}
	if !found {
		t.Errorf("no bind mounts %s; the container cannot hand over its DNS servers", shared)
	}
}
