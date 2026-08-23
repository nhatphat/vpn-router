package menubar

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"vpn-router/internal/release"
)

// probe is a stand-in for GitHub that counts the questions and can be held
// open, so a test can look at what happens while a request is in flight.
type probe struct {
	mu      sync.Mutex
	calls   int
	release *release.Release
	err     error
	block   chan struct{}
}

func (p *probe) latest(ctx context.Context) (*release.Release, error) {
	p.mu.Lock()
	p.calls++
	block, rel, err := p.block, p.release, p.err
	p.mu.Unlock()

	if block != nil {
		<-block
	}
	return rel, err
}

func (p *probe) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// watcherFor builds a watcher on a clock the test moves by hand.
func watcherFor(p *probe, version string, clock *time.Time) *updateWatcher {
	return &updateWatcher{
		Version:  version,
		Latest:   p.latest,
		Now:      func() time.Time { return *clock },
		Cooldown: time.Hour,
	}
}

// settle waits for the watcher's goroutine to finish, which is what every
// assertion here is really waiting on.
func settle(t *testing.T, w *updateWatcher) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		w.mu.Lock()
		busy := w.asking
		w.mu.Unlock()
		if !busy {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("the update check never finished")
}

func rel(tag string) *release.Release {
	return &release.Release{Tag: tag, HTMLURL: "https://example.invalid/" + tag}
}

// report captures what the menu would be told.
func report(t *testing.T, w *updateWatcher) (updateStatus, bool) {
	t.Helper()
	var (
		mu   sync.Mutex
		got  updateStatus
		seen bool
	)
	w.MenuOpened(func(st updateStatus) {
		mu.Lock()
		got, seen = st, true
		mu.Unlock()
	})
	settle(t, w)
	mu.Lock()
	defer mu.Unlock()
	return got, seen
}

// TestOpeningTheMenuAsksOnceAndNamesBothVersions is the feature: open the
// menu, one question, and an item that says what you are on and what you
// could be on.
func TestOpeningTheMenuAsksOnceAndNamesBothVersions(t *testing.T) {
	clock := time.Unix(1700000000, 0)
	p := &probe{release: rel("v0.4.0")}
	w := watcherFor(p, "0.3.3", &clock)

	got, seen := report(t, w)
	if !seen {
		t.Fatal("the menu was told nothing")
	}
	if p.count() != 1 {
		t.Fatalf("one menu open made %d requests, want 1", p.count())
	}
	if got.Current != "v0.3.3" || got.Newer != "v0.4.0" {
		t.Fatalf("status = %+v, want v0.3.3 -> v0.4.0", got)
	}
}

// TestVersionsAreShownTheSameWay: the running version is compiled in without
// a leading v and the tag comes from GitHub with one, so an unnormalised item
// would read "0.3.3 -> v0.4.0" and invite the question of whether those are
// the same kind of number.
func TestVersionsAreShownTheSameWay(t *testing.T) {
	clock := time.Unix(1700000000, 0)
	p := &probe{release: rel("v0.4.0")}
	w := watcherFor(p, "0.3.3", &clock)

	got, _ := report(t, w)
	if got.Current != "v0.3.3" {
		t.Fatalf("current = %q, want v0.3.3", got.Current)
	}
}

// TestTheSameVersionSaysUpToDate guards the case that happens every day: the
// item is on screen whether or not there is news, so it has to have something
// true to say when there is none.
func TestTheSameVersionSaysUpToDate(t *testing.T) {
	clock := time.Unix(1700000000, 0)
	p := &probe{release: rel("v0.3.3")}
	w := watcherFor(p, "0.3.3", &clock)

	got, seen := report(t, w)
	if !seen {
		t.Fatal("the menu was told nothing, so it would still say \"checking\"")
	}
	if got.Newer != "" {
		t.Fatalf("offered %q as an update to the version already running", got.Newer)
	}
	if got.Failed {
		t.Fatal("a successful check was reported as failed")
	}
	if got.Current != "v0.3.3" {
		t.Fatalf("current = %q, want v0.3.3", got.Current)
	}
}

// TestASecondOpenWithinTheCooldownAsksNothing is why the cooldown exists.
// GitHub allows an unauthenticated caller sixty requests an hour per source
// address, and behind an office NAT that is shared by every machine on it —
// a menu opened repeatedly must not spend the allowance.
func TestASecondOpenWithinTheCooldownAsksNothing(t *testing.T) {
	clock := time.Unix(1700000000, 0)
	p := &probe{release: rel("v0.3.3")}
	w := watcherFor(p, "0.3.3", &clock)

	w.MenuOpened(nil)
	settle(t, w)

	for i := 0; i < 20; i++ {
		clock = clock.Add(time.Minute)
		w.MenuOpened(nil)
		settle(t, w)
	}
	if p.count() != 1 {
		t.Fatalf("21 opens over 20 minutes made %d requests, want 1", p.count())
	}

	clock = clock.Add(time.Hour)
	w.MenuOpened(nil)
	settle(t, w)
	if p.count() != 2 {
		t.Fatalf("after the cooldown expired: %d requests, want 2", p.count())
	}
}

// TestASubmenuDoesNotStartASecondRequest covers how AppKit actually reports
// this. Every submenu posts its own tracking notification, so one person
// opening one menu can arrive here several times — and a slow request must
// not be joined by another.
func TestASubmenuDoesNotStartASecondRequest(t *testing.T) {
	clock := time.Unix(1700000000, 0)
	p := &probe{release: rel("v0.4.0"), block: make(chan struct{})}
	w := watcherFor(p, "0.3.3", &clock)

	w.MenuOpened(nil)
	for i := 0; i < 5; i++ { // hovering over submenus while the first is in flight
		w.MenuOpened(nil)
	}

	close(p.block)
	settle(t, w)

	if p.count() != 1 {
		t.Fatalf("six overlapping opens made %d requests, want 1", p.count())
	}
}

// TestAFailedCheckSaysSoRatherThanClaimingUpToDate. A failure is not worth
// interrupting anyone over, but with the item permanently on screen, staying
// quiet would leave it asserting that the running version is current on the
// strength of a question that was never answered. It must also start the
// cooldown, or a machine with no route to GitHub turns every click into
// another ten-second request.
func TestAFailedCheckSaysSoRatherThanClaimingUpToDate(t *testing.T) {
	clock := time.Unix(1700000000, 0)
	p := &probe{err: errors.New("no route to host")}
	w := watcherFor(p, "0.3.3", &clock)

	got, seen := report(t, w)
	if !seen {
		t.Fatal("a failed check told the menu nothing, leaving it on \"checking\" for good")
	}
	if !got.Failed {
		t.Fatal("a failed check was not reported as one")
	}
	if got.Newer != "" {
		t.Fatalf("a failed check offered %q", got.Newer)
	}

	clock = clock.Add(30 * time.Minute)
	w.MenuOpened(nil)
	settle(t, w)
	if p.count() != 1 {
		t.Fatalf("a failure was retried %d times inside the cooldown, want 1 request total", p.count())
	}
}

// TestAKnownUpdateStopsTheAsking: once the item is on screen the answer cannot
// usefully change, and every later open would be a request whose result is
// already displayed.
func TestAKnownUpdateStopsTheAsking(t *testing.T) {
	clock := time.Unix(1700000000, 0)
	p := &probe{release: rel("v0.4.0")}
	w := watcherFor(p, "0.3.3", &clock)

	w.MenuOpened(nil)
	settle(t, w)

	clock = clock.Add(48 * time.Hour)
	w.MenuOpened(nil)
	settle(t, w)

	if p.count() != 1 {
		t.Fatalf("made %d requests after the update was already found, want 1", p.count())
	}
}

// TestALocalBuildIsOfferedARelease covers the version this is developed with.
// release.IsNewer treats an unparsable version as older than anything
// published, and the menu has to agree — a developer running "dev" who opens
// the menu should still be told a release exists.
func TestALocalBuildIsOfferedARelease(t *testing.T) {
	clock := time.Unix(1700000000, 0)
	p := &probe{release: rel("v0.4.0")}
	w := watcherFor(p, "dev", &clock)

	got, _ := report(t, w)
	if got.Newer != "v0.4.0" {
		t.Fatalf("newer = %q, want v0.4.0 offered to a local build", got.Newer)
	}
	if got.Current != "dev" {
		t.Fatalf("current = %q, want it left alone rather than turned into vdev", got.Current)
	}
}

// TestApplescriptStringSurvivesTheTextItHasToCarry. The dialog exists to show
// a failure, and the failures worth a dialog are the ones with a checksum
// mismatch in them: several lines, quotes around filenames. Escaped wrong,
// the message a person needs becomes an AppleScript syntax error instead.
func TestApplescriptStringSurvivesTheTextItHasToCarry(t *testing.T) {
	cases := []struct{ in, want string }{
		{`plain`, `"plain"`},
		{`he said "no"`, `"he said \"no\""`},
		{`a\b`, `"a\\b"`},
		{"two\nlines", `"two" & return & "lines"`},
		{"crlf\r\nhere", `"crlf" & return & "here"`},
	}
	for _, c := range cases {
		if got := applescriptString(c.in); got != c.want {
			t.Errorf("applescriptString(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

// TestCancellingTheDialogIsNotAFailure: osascript reports a dismissed
// authorisation prompt as an error like any other, and telling somebody their
// update failed because they decided not to update would be nonsense.
func TestCancellingTheDialogIsNotAFailure(t *testing.T) {
	if !cancelled([]byte("0:54: execution error: User canceled. (-128)")) {
		t.Error("a dismissed prompt was treated as a failure")
	}
	if cancelled([]byte("checksum mismatch for vpnctl_0.4.0_darwin_arm64.tar.gz")) {
		t.Error("a checksum mismatch was mistaken for someone pressing Cancel")
	}
}
