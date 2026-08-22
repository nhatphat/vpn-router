package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const annotated = `# vpnctl configuration.
#
# Relative paths resolve against this file.

docker:
  project: vpn-router      # inline comment
  socks: 127.0.0.1:1080

dns_router:
  listen: 127.0.0.1:15353
  # Suffixes macOS resolves here directly.
  resolver_domains:
    - corp.example.com
    - domain: staging.example.com
      enabled: false
  public_dns: 1.1.1.1:53

racer:
  listen: 127.0.0.1:15080
`

// TestSetResolverDomainsKeepsEveryOtherLine is the whole reason this edits
// lines instead of re-encoding the document: a graphical toggle must not cost
// the file its own documentation.
func TestSetResolverDomainsKeepsEveryOtherLine(t *testing.T) {
	path := write(t, annotated)

	if err := SetResolverDomains(path, ResolverDomains{
		{Domain: "corp.example.com", Enabled: false},
		{Domain: "staging.example.com", Enabled: true},
	}); err != nil {
		t.Fatal(err)
	}

	got := read(t, path)

	for _, line := range []string{
		"# vpnctl configuration.",
		"# Relative paths resolve against this file.",
		"  project: vpn-router      # inline comment",
		"  # Suffixes macOS resolves here directly.",
		"  public_dns: 1.1.1.1:53",
		"racer:",
		"  listen: 127.0.0.1:15080",
	} {
		if !strings.Contains(got, line) {
			t.Errorf("lost the line %q\n--- got ---\n%s", line, got)
		}
	}

	// And the block itself is what was asked for.
	if !strings.Contains(got, "    - domain: corp.example.com\n      enabled: false\n") {
		t.Errorf("the disabled domain is not written as a mapping:\n%s", got)
	}
	if !strings.Contains(got, "    - staging.example.com\n") {
		t.Errorf("the enabled domain is not written in shorthand:\n%s", got)
	}
}

// TestSetResolverDomainsRoundTrips checks the file it writes is the file it
// reads, which is what makes the menu bar's view and the config agree.
func TestSetResolverDomainsRoundTrips(t *testing.T) {
	path := write(t, annotated)

	want := ResolverDomains{
		{Domain: "a.example.com", Enabled: true},
		{Domain: "b.example.com", Enabled: false},
		{Domain: "c.example.com", Enabled: true},
	}
	if err := SetResolverDomains(path, want); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("the rewritten file does not load: %v", err)
	}

	got := cfg.DNSRouter.ResolverDomains
	if len(got) != len(want) {
		t.Fatalf("read back %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestSetResolverDomainsEmptiesTheBlock(t *testing.T) {
	path := write(t, annotated)

	if err := SetResolverDomains(path, ResolverDomains{}); err != nil {
		t.Fatal(err)
	}

	got := read(t, path)
	if !strings.Contains(got, "  resolver_domains: []") {
		t.Errorf("an empty list should be written inline:\n%s", got)
	}
	if strings.Contains(got, "corp.example.com") {
		t.Errorf("the old entries survived:\n%s", got)
	}
	if !strings.Contains(got, "  public_dns: 1.1.1.1:53") {
		t.Errorf("the following key was eaten:\n%s", got)
	}
}

// TestSetResolverDomainsAddsTheKeyWhenAbsent covers a config written before
// this setting existed.
func TestSetResolverDomainsAddsTheKeyWhenAbsent(t *testing.T) {
	path := write(t, "dns_router:\n  listen: 127.0.0.1:15353\n  public_dns: 1.1.1.1:53\n")

	if err := SetResolverDomains(path, ResolverDomains{{Domain: "corp.example.com", Enabled: true}}); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v\n%s", err, read(t, path))
	}
	if len(cfg.DNSRouter.ResolverDomains) != 1 {
		t.Errorf("read back %v", cfg.DNSRouter.ResolverDomains)
	}
	if cfg.DNSRouter.PublicDNS != "1.1.1.1:53" {
		t.Errorf("public_dns became %q", cfg.DNSRouter.PublicDNS)
	}
}

func TestSetResolverDomainsAddsTheSectionWhenAbsent(t *testing.T) {
	path := write(t, "racer:\n  listen: 127.0.0.1:15080\n")

	if err := SetResolverDomains(path, ResolverDomains{{Domain: "corp.example.com", Enabled: true}}); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v\n%s", err, read(t, path))
	}
	if len(cfg.DNSRouter.ResolverDomains) != 1 {
		t.Errorf("read back %v\n%s", cfg.DNSRouter.ResolverDomains, read(t, path))
	}
	if cfg.Racer.Listen != "127.0.0.1:15080" {
		t.Errorf("the existing section was damaged: racer.listen = %q", cfg.Racer.Listen)
	}
}

func TestSetResolverDomainsPreservesPermissions(t *testing.T) {
	path := write(t, annotated)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := SetResolverDomains(path, ResolverDomains{}); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode became %o; the file sits beside secrets", info.Mode().Perm())
	}
}

// TestToggleRefusesAnUnknownDomain keeps a stale click from introducing a
// suffix nobody declared.
func TestToggleRefusesAnUnknownDomain(t *testing.T) {
	path := write(t, annotated)

	if _, err := ToggleResolverDomain(path, "evil.example.com", true); err == nil {
		t.Fatal("expected the toggle to refuse an undeclared domain")
	}
	if strings.Contains(read(t, path), "evil.example.com") {
		t.Error("the file was modified anyway")
	}
}

func TestToggleFlipsOnlyTheNamedDomain(t *testing.T) {
	path := write(t, annotated)

	list, err := ToggleResolverDomain(path, "staging.example.com", true)
	if err != nil {
		t.Fatal(err)
	}

	corp, _ := list.Find("corp.example.com")
	staging, _ := list.Find("staging.example.com")
	if !corp.Enabled {
		t.Error("corp.example.com was changed")
	}
	if !staging.Enabled {
		t.Error("staging.example.com was not switched on")
	}
	if got := list.Enabled(); len(got) != 2 {
		t.Errorf("Enabled() = %v, want both", got)
	}
}

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
