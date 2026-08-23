package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpn-router/internal/config"
)

// managedFile is what the resolver package writes, marker and all.
const managedFile = "# managed by vpnctl\nnameserver 127.0.0.1\nport 15353\n"

func report(t *testing.T, dir string, paused bool, domains ...config.ResolverDomain) Check {
	t.Helper()

	cfg := config.Defaults()
	cfg.DNSRouter.Listen = "127.0.0.1:15353"
	cfg.DNSRouter.ResolverDomains = domains

	r := &Report{}
	checkResolvers(r, &cfg, dir, paused)

	if len(r.Checks) != 1 {
		t.Fatalf("got %d checks, want 1", len(r.Checks))
	}
	return r.Checks[0]
}

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// TestDoctorDoesNotCallAPausedStackBroken is the check a person runs to find
// out whether anything is wrong. While the stack is stopped the resolver files
// are meant to be gone, so reporting their absence as a fault would send
// someone hunting a problem that is not there.
func TestDoctorDoesNotCallAPausedStackBroken(t *testing.T) {
	dir := t.TempDir()
	on := config.ResolverDomain{Domain: "corp.example.com", Enabled: true}

	if got := report(t, dir, false, on); got.Level != LevelWarn {
		t.Fatalf("running with no file installed: level = %v, want a warning", got.Level)
	}

	got := report(t, dir, true, on)
	if got.Level != LevelOK {
		t.Fatalf("paused with no file installed: level = %v (%s), want ok", got.Level, got.Detail)
	}
	if !strings.Contains(got.Detail, "stopped") {
		t.Fatalf("paused detail = %q, want it to say why nothing is installed", got.Detail)
	}
}

// TestDoctorFlagsAResolverThatSurvivedAPause is the inverse, and the reason
// the check cannot simply be skipped while paused. A file left behind points
// a suffix at a DNS router that is not running, so those names resolve to
// nothing at all — the exact failure removing them on pause prevents.
func TestDoctorFlagsAResolverThatSurvivedAPause(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "corp.example.com", managedFile)

	got := report(t, dir, true, config.ResolverDomain{Domain: "corp.example.com", Enabled: true})
	if got.Level == LevelOK {
		t.Fatalf("a resolver still installed while paused was reported as ok: %q", got.Detail)
	}
	if !strings.Contains(got.Detail, "cannot resolve") {
		t.Fatalf("detail = %q, want it to say those names cannot resolve", got.Detail)
	}
	if got.Fix != "vpnctl start" {
		t.Fatalf("fix = %q, want vpnctl start", got.Fix)
	}
}

// TestDoctorStillReportsAForeignResolverWhilePaused guards the shortcut this
// check nearly took. Returning early on "paused and nothing of ours installed"
// reads as complete, but a file somebody else wrote is not ours and is still
// sending those names somewhere — staying quiet about it would be a report
// that says everything is fine while DNS goes to a third party.
func TestDoctorStillReportsAForeignResolverWhilePaused(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "corp.example.com", "nameserver 10.9.9.9\n")

	got := report(t, dir, true, config.ResolverDomain{Domain: "corp.example.com", Enabled: true})
	if got.Level == LevelOK {
		t.Fatalf("a foreign resolver was reported as ok while paused: %q", got.Detail)
	}
	if !strings.Contains(got.Detail, "did not write") {
		t.Fatalf("detail = %q, want it to name the foreign file", got.Detail)
	}
}
