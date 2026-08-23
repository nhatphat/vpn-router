package supervisor

import (
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"testing"

	"vpn-router/internal/config"
	"vpn-router/internal/logbus"
	"vpn-router/internal/resolver"
	"vpn-router/internal/status"
)

// resolverFixture is a supervisor cut down to the parts applyResolvers uses,
// pointed at a temporary directory instead of /etc/resolver.
type resolverFixture struct {
	s       *Supervisor
	dir     string
	reloads int
}

func newResolverFixture(t *testing.T, domains ...config.ResolverDomain) *resolverFixture {
	t.Helper()

	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.DNSRouter.Listen = "127.0.0.1:15353"
	cfg.DNSRouter.ResolverDomains = domains
	cfg.Supervisor.StateDir = t.TempDir()

	f := &resolverFixture{dir: dir}
	f.s = &Supervisor{
		o: Options{
			Bus:         logbus.New(64),
			ResolverDir: dir,
		},
		comps:      map[string]status.Component{},
		statusSubs: map[int]chan status.Snapshot{},
		pause:      newPauseState(),
		restart:    map[string]chan struct{}{},
		reloadResolvers: func() error {
			f.reloads++
			return nil
		},
	}
	f.s.current = atomic.Pointer[config.Config]{}
	f.s.current.Store(&cfg)
	return f
}

// present lists the resolver files that exist, whoever wrote them.
func (f *resolverFixture) present(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		t.Fatalf("read %s: %v", f.dir, err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

func on(domain string) config.ResolverDomain {
	return config.ResolverDomain{Domain: domain, Enabled: true}
}

func equal(t *testing.T, what string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want %v", what, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s = %v, want %v", what, got, want)
		}
	}
}

// TestPauseRemovesScopedResolversAndResumeWritesThemBack is the whole point of
// the change. A scoped resolver naming a DNS router that is not running is a
// black hole: with the files left behind, stopping vpnctl would stop those
// names resolving at all, including on a network that answers them without
// any tunnel.
func TestPauseRemovesScopedResolversAndResumeWritesThemBack(t *testing.T) {
	f := newResolverFixture(t, on("corp.example.com"), on("staging.example.com"))

	f.s.applyResolvers()
	equal(t, "after start", f.present(t), []string{"corp.example.com", "staging.example.com"})

	if err := f.s.SetPaused(true); err != nil {
		t.Fatalf("pause: %v", err)
	}
	equal(t, "after pause", f.present(t), nil)

	if err := f.s.SetPaused(false); err != nil {
		t.Fatalf("resume: %v", err)
	}
	equal(t, "after resume", f.present(t), []string{"corp.example.com", "staging.example.com"})
}

// TestPauseSignalsTheSystemResolver checks the half that makes removal real.
// Deleting the files changes nothing until mDNSResponder is told, and it must
// be told exactly when something moved: a HUP flushes the machine's entire DNS
// cache, so doing it on an unchanged directory throws away every cached answer
// on the machine for nothing.
func TestPauseSignalsTheSystemResolver(t *testing.T) {
	f := newResolverFixture(t, on("corp.example.com"))

	f.s.applyResolvers()
	if f.reloads != 1 {
		t.Fatalf("writing the resolver signalled mDNSResponder %d times, want 1", f.reloads)
	}

	f.s.applyResolvers() // nothing to do
	if f.reloads != 1 {
		t.Fatalf("an unchanged directory signalled mDNSResponder %d times, want 1", f.reloads)
	}

	f.s.SetPaused(true)
	if f.reloads != 2 {
		t.Fatalf("pausing signalled mDNSResponder %d times, want 2", f.reloads)
	}

	f.s.applyResolvers() // still paused, still nothing to do
	if f.reloads != 2 {
		t.Fatalf("a second pass while paused signalled mDNSResponder %d times, want 2", f.reloads)
	}
}

// TestStartingPausedWritesNoResolvers covers the reboot case. The paused state
// outlives the daemon, so a daemon that comes back paused must not install the
// files its config asks for — it would recreate the black hole on every start.
func TestStartingPausedWritesNoResolvers(t *testing.T) {
	f := newResolverFixture(t, on("corp.example.com"))
	f.s.pause.Set(true)

	f.s.applyResolvers()

	equal(t, "started paused", f.present(t), nil)
}

// TestReloadWhilePausedWritesNoResolvers covers switching a suffix on while
// the stack is stopped. The config records the intent; the directory must
// still reflect that nothing is running.
func TestReloadWhilePausedWritesNoResolvers(t *testing.T) {
	f := newResolverFixture(t)
	f.s.SetPaused(true)

	cfg := *f.s.cfg()
	cfg.DNSRouter.ResolverDomains = config.ResolverDomains{on("corp.example.com")}
	f.s.current.Store(&cfg)
	f.s.applyResolvers()

	equal(t, "enabled while paused", f.present(t), nil)

	if got := f.s.Snapshot().Resolvers; len(got) != 1 || got[0].Installed || !got[0].Enabled {
		t.Fatalf("status = %+v, want the suffix reported as configured but not installed", got)
	}
}

// TestPauseLeavesAForeignResolverAlone is the rule that must survive being
// applied in reverse. Removing a file somebody else wrote would silently
// change where that machine sends its DNS, and pausing is not consent to that
// any more than starting is.
func TestPauseLeavesAForeignResolverAlone(t *testing.T) {
	f := newResolverFixture(t, on("corp.example.com"))

	foreign := filepath.Join(f.dir, "other.example.com")
	body := "nameserver 10.9.9.9\n"
	if err := os.WriteFile(foreign, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	f.s.applyResolvers()
	f.s.SetPaused(true)

	equal(t, "after pause", f.present(t), []string{"other.example.com"})

	got, err := os.ReadFile(foreign)
	if err != nil || string(got) != body {
		t.Fatalf("the foreign resolver was rewritten: %q, %v", got, err)
	}
}

// TestPausedStatusDoesNotReadAsAFault checks the sentence a person actually
// sees. "not installed yet" describes a fault about to be corrected; while the
// stack is stopped, nothing is coming, and saying so would send someone
// looking for a problem that is not there.
func TestPausedStatusDoesNotReadAsAFault(t *testing.T) {
	r := status.Resolver{Domain: "corp.example.com", Enabled: true}

	if note := r.Note(false); note != "not installed yet" {
		t.Fatalf("running note = %q", note)
	}
	if note := r.Note(true); note != "not in effect while vpnctl is stopped" {
		t.Fatalf("paused note = %q", note)
	}

	// A file that survived a pause is the one case worth flagging.
	stuck := status.Resolver{Domain: "corp.example.com", Enabled: true, Installed: true}
	if note := stuck.Note(true); note == "" {
		t.Fatal("a resolver still installed while paused was reported as fine")
	}
	if note := stuck.Note(false); note != "" {
		t.Fatalf("a correctly installed resolver was annotated: %q", note)
	}
}

// TestPauseUsesTheRealResolverDirectoryByDefault guards the seam these tests
// rely on. ResolverDir exists so a test does not write to /etc/resolver; if it
// ever defaulted to empty, the daemon would manage a directory macOS does not
// read and every test here would still pass.
func TestPauseUsesTheRealResolverDirectoryByDefault(t *testing.T) {
	cfg := config.Defaults()
	s, err := New(Options{Cfg: &cfg, Bus: logbus.New(8)})
	if err != nil {
		t.Skipf("cannot build a supervisor here: %v", err)
	}
	if s.o.ResolverDir != resolver.Dir {
		t.Fatalf("ResolverDir = %q, want %q", s.o.ResolverDir, resolver.Dir)
	}
	if s.reloadResolvers == nil {
		t.Fatal("reloadResolvers is nil; a real daemon would never signal mDNSResponder")
	}
}
