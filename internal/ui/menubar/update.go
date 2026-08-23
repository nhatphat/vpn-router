package menubar

import (
	"context"
	"strings"
	"sync"
	"time"
	"unicode"

	"vpn-router/internal/release"
)

// updateStatus is what the menu has to say about versions.
//
// A single value rather than a "there is an update" callback, because the item
// is always on screen: "up to date", "here is one", and "could not ask" are
// three things it must be able to say, and only one of them is news.
type updateStatus struct {
	// Current is the running version, ready to display.
	Current string
	// Newer is the tag of a release worth installing, or empty.
	Newer string
	// Failed reports that the question could not be asked. Distinct from
	// "up to date", which would otherwise be claimed on every failure.
	Failed bool
}

// display gives a version a leading v when it is bare digits, so a tag from
// GitHub and a version compiled into the binary can sit either side of an
// arrow without looking like two different kinds of thing.
func display(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "unknown"
	}
	if unicode.IsDigit(rune(v[0])) {
		return "v" + v
	}
	return v
}

// checkCooldown is the shortest gap between two questions to GitHub.
//
// The trigger is a person opening a menu, which is not a rate anyone controls:
// a menu opened twenty times while hunting for something would otherwise be
// twenty API calls. GitHub allows sixty an hour to an unauthenticated caller,
// counted per source address — and behind an office NAT that hour is shared by
// every machine on it, which is exactly the population this program runs on.
// Being frugal costs an update noticed an hour late; not being frugal costs
// the whole office its allowance.
const checkCooldown = time.Hour

// updateWatcher decides when to ask whether a newer vpnctl exists.
//
// Separate from the menu so the deciding can be tested without a menu bar: the
// interesting behaviour is in when it declines to ask, and none of that needs
// a status item to observe.
type updateWatcher struct {
	// Version is what is running now.
	Version string
	// Latest asks where the releases are. A field so a test can answer
	// without a network.
	Latest func(context.Context) (*release.Release, error)
	// Now is the clock, for the same reason.
	Now func() time.Time
	// Cooldown overrides checkCooldown in tests.
	Cooldown time.Duration
	// Logf records what happened, for the agent log. Nothing here is worth
	// interrupting anyone with, but "why have I never been offered an
	// update" needs an answer somewhere.
	Logf func(string, ...any)

	mu      sync.Mutex
	asking  bool
	lastAsk time.Time
	found   string
}

func (w *updateWatcher) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

func (w *updateWatcher) cooldown() time.Duration {
	if w.Cooldown != 0 {
		return w.Cooldown
	}
	return checkCooldown
}

// MenuOpened is called every time a menu begins tracking, and asks GitHub at
// most once per cooldown. report runs on a background goroutine when an answer
// arrives; on the opens that ask nothing it is not called at all, and the menu
// keeps whatever the last answer said.
//
// A failure reaches the menu as a state rather than a notification. Nobody
// opened a menu in order to be told api.github.com was unreachable — but with
// the item always on screen, silence would leave it claiming to be up to date
// on the strength of a question that was never answered.
func (w *updateWatcher) MenuOpened(report func(updateStatus)) {
	w.mu.Lock()
	switch {
	case w.asking:
		// A submenu opening posts its own notification, and a slow request
		// outlives several opens. Neither should start a second one.
		w.mu.Unlock()
		return
	case w.found != "":
		// Already known, and the answer cannot change usefully: the item is
		// on screen and the only thing left to do is install it.
		w.mu.Unlock()
		return
	case !w.lastAsk.IsZero() && w.now().Sub(w.lastAsk) < w.cooldown():
		w.mu.Unlock()
		return
	}
	w.asking = true
	w.mu.Unlock()

	go w.ask(report)
}

func (w *updateWatcher) ask(report func(updateStatus)) {
	// Cleared last, so the check counts as running until the menu has been
	// updated rather than until the request came back, and a panic in the
	// callback cannot wedge every later check.
	defer func() {
		w.mu.Lock()
		w.asking = false
		w.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	latest := w.Latest
	if latest == nil {
		latest = release.Latest
	}
	rel, err := latest(ctx)
	if w.Logf != nil {
		switch {
		case err != nil:
			w.Logf("update check failed: %v", err)
		case rel == nil:
			w.Logf("update check: no release")
		default:
			w.Logf("update check: running %s, latest %s", w.Version, rel.Tag)
		}
	}

	st := updateStatus{Current: display(w.Version)}
	switch {
	case err != nil || rel == nil:
		st.Failed = true
	case release.IsNewer(rel.Tag, w.Version):
		st.Newer = display(rel.Tag)
	}

	w.mu.Lock()
	// The cooldown starts whether or not the answer was useful. A failing
	// request retried on every menu open is how a machine with no route to
	// GitHub turns each click into a ten-second goroutine.
	w.lastAsk = w.now()
	if st.Newer != "" {
		w.found = st.Newer
	}
	w.mu.Unlock()

	if report != nil {
		report(st)
	}
}
