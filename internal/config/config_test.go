package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestEmbeddedExampleMatchesDefaults keeps the documented configuration and
// the compiled defaults from drifting apart: the example is what a new install
// gets, so a value that differs from Defaults() is a silent behaviour change
// for everyone who installs.
func TestEmbeddedExampleMatchesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(ExampleYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("the embedded example does not load: %v", err)
	}

	want := Defaults()
	if err := want.Init(dir); err != nil {
		t.Fatalf("defaults do not validate: %v", err)
	}
	want.Path = loaded.Path

	if !reflect.DeepEqual(*loaded, want) {
		t.Errorf("the embedded example differs from Defaults()\n loaded: %+v\n  want:  %+v", *loaded, want)
	}
}

func TestRelativePathsResolveAgainstTheConfigDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("singbox:\n  force_vpn_rules: rules/force-vpn.json\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(dir, "rules/force-vpn.json")
	if cfg.SingBox.ForceVPNRules != want {
		t.Errorf("force_vpn_rules = %q, want %q", cfg.SingBox.ForceVPNRules, want)
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	cases := map[string]string{
		"bad stack":    "singbox:\n  tun:\n    stack: wireguard\n",
		"bad listen":   "dns_router:\n  listen: not-a-host-port\n",
		"zero mtu":     "singbox:\n  tun:\n    mtu: 0\n",
		"empty tun":    "singbox:\n  tun:\n    interface_name: \"\"\n",
		"zero timeout": "dns_router:\n  query_timeout: 0s\n",
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Errorf("expected %s to be rejected", name)
			}
		})
	}
}

// TestCheckExecutableRefusesUserWritableBinaries covers the rule that keeps a
// non-root writer from choosing what the root daemon executes.
func TestCheckExecutableRefusesUserWritableBinaries(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "sing-box")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Owned by the test user, not root.
	if err := CheckExecutable(bin, false); err == nil {
		t.Error("expected a user-owned binary to be refused")
	}
	if err := CheckExecutable(bin, true); err != nil {
		t.Errorf("allow_unsafe_binary should permit it: %v", err)
	}
}

func TestCheckExecutableFollowsSymlinks(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(real, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	err := CheckExecutable(link, false)
	if err == nil {
		t.Fatal("expected the symlink target to be checked")
	}
	// The message must name the target, since that is the file to fix.
	if !contains(err.Error(), real) {
		t.Errorf("error names %q, want it to mention the target %q", err.Error(), real)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}

// TestDefaultsPinTheVersionTheyShipWith is the test that would have caught the
// mistake this keying exists to prevent: pins that describe one version while
// Version names another. That combination produced a checksum mismatch, which
// reads as tampering when it means nobody pinned that version.
func TestDefaultsPinTheVersionTheyShipWith(t *testing.T) {
	cfg := Defaults()
	pins := cfg.SingBox.SHA256

	for _, platform := range []string{"darwin-arm64", "darwin-amd64"} {
		key := PinKey(cfg.SingBox.Version, platform)
		hash, ok := pins[key]
		if !ok {
			t.Errorf("no pinned checksum for %s", key)
			continue
		}
		if len(hash) != 64 {
			t.Errorf("%s checksum is %d characters, want 64", key, len(hash))
		}
	}

	// Every pin must name a version; a bare platform key would be applied to
	// whatever version happened to be configured.
	for key := range pins {
		if !strings.Contains(key, "/") {
			t.Errorf("pin key %q does not name a version", key)
		}
	}
}

// TestLookupIgnoresPinsForOtherVersions is the behaviour that turns a version
// bump into "unpinned" rather than "mismatch".
func TestLookupIgnoresPinsForOtherVersions(t *testing.T) {
	pins := Hashes{PinKey("1.2.3", Platform()): "abc"}

	if _, ok := pins.Lookup("1.2.3"); !ok {
		t.Error("the pin for the configured version was not found")
	}
	if _, ok := pins.Lookup("1.2.4"); ok {
		t.Error("a pin for a different version was applied")
	}
}
