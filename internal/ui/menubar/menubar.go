// Package menubar is the macOS menu bar front end.
//
// It is an unprivileged process in the user's login session, and it holds no
// state of its own: everything it shows comes from the daemon's status stream,
// and every action it offers is one of the daemon's control operations. That
// split is why it can exist at all — sing-box needs root, a menu bar needs a
// GUI session, and nothing can be both.
package menubar

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/getlantern/systray"

	"vpn-router/internal/config"
	"vpn-router/internal/installer"
	"vpn-router/internal/ipc"
	"vpn-router/internal/status"
	"vpn-router/internal/ui/web"
)

type Options struct {
	SocketPath string
	WebListen  string
	ConfigPath string
	// Version is what is running, for the update check to compare against.
	Version string
}

type app struct {
	o      Options
	client *ipc.Client
	web    *web.Server

	// Menu items whose text changes as the status does.
	header     *systray.MenuItem
	components map[string]*systray.MenuItem
	order      []string
	retry      *systray.MenuItem
	stopStart  *systray.MenuItem
	update     *systray.MenuItem

	// resolverRoot holds a fixed pool of checkboxes. systray can hide and
	// show items but not create them after the menu is built, so the pool is
	// allocated once and only as many entries as the config has are shown.
	resolverRoot  *systray.MenuItem
	resolverItems []*systray.MenuItem
	resolverEmpty *systray.MenuItem

	updates *updateWatcher

	mu          sync.Mutex
	updateTitle string
	lastSeen    status.Overall
	lastPaused  bool
	resolvers   []status.Resolver
}

// maxResolverItems bounds the checkbox pool. A machine with more scoped
// suffixes than this is better served by editing the config than by a menu.
const maxResolverItems = 12

// Run takes over the calling goroutine, which must be the main one: the menu
// bar has to live on the process's first thread.
func Run(o Options) error {
	a := &app{
		o:          o,
		client:     &ipc.Client{Path: o.SocketPath, Timeout: 5 * time.Second},
		components: map[string]*systray.MenuItem{},
		order: []string{
			status.CompVPN, status.CompSingBox,
			status.CompDNSRouter, status.CompRacer,
		},
		lastSeen: "",
	}
	a.web = &web.Server{Addr: o.WebListen, Client: a.client}
	a.updates = &updateWatcher{Version: o.Version, Logf: logf}

	systray.Run(a.onReady, func() {})
	return nil
}

func (a *app) onReady() {
	systray.SetTitle(labelUnknown)
	systray.SetTooltip("vpnctl")

	a.header = systray.AddMenuItem("connecting to the daemon…", "")
	a.header.Disable()

	systray.AddSeparator()
	for _, name := range a.order {
		item := systray.AddMenuItem(fmt.Sprintf("%-11s —", name), "")
		item.Disable()
		a.components[name] = item
	}

	systray.AddSeparator()
	restart := systray.AddMenuItem("Restart", "")
	restartItems := map[string]*systray.MenuItem{}
	for _, name := range append([]string{}, a.order...) {
		restartItems[name] = restart.AddSubMenuItem(name, "")
	}
	restartItems["all"] = restart.AddSubMenuItem("Everything", "")

	a.resolverRoot = systray.AddMenuItem("Resolver domains", "Suffixes macOS resolves through vpnctl")
	a.resolverEmpty = a.resolverRoot.AddSubMenuItem("none configured", "")
	a.resolverEmpty.Disable()
	for i := 0; i < maxResolverItems; i++ {
		item := a.resolverRoot.AddSubMenuItemCheckbox("", "", false)
		item.Hide()
		a.resolverItems = append(a.resolverItems, item)
		go a.onClick(item, func(index int) func() {
			return func() { a.toggleResolver(index) }
		}(i))
	}

	// Above the rest: it is the item somebody reaches for when something is
	// wrong and they want their own network back now.
	a.stopStart = systray.AddMenuItem("Stop", "")
	systray.AddSeparator()

	apply := systray.AddMenuItem("Apply config", "Re-read the config file and restart only what changed")
	a.retry = systray.AddMenuItem("Try again", "Leave safe mode and start sing-box again")
	a.retry.Hide()

	systray.AddSeparator()
	openLogs := systray.AddMenuItem("Open logs…", "")
	openConfig := systray.AddMenuItem("Open config…", "")
	runDoctor := systray.AddMenuItem("Run doctor…", "")

	// Always on screen, and disabled until there is something to click. It
	// answers "am I on the current version" as well as "is there a new one",
	// and the first question is the one people actually open a menu to ask.
	a.update = systray.AddMenuItem("Checking for updates…", "")
	a.update.Disable()

	systray.AddSeparator()
	// Named explicitly: quitting this does not stop the stack, and a menu
	// item called "Quit" would reasonably be read as doing so.
	quit := systray.AddMenuItem("Quit menu bar", "The daemon and the tunnel keep running")

	for name, item := range restartItems {
		go a.onClick(item, func(component string) func() {
			return func() { a.restart(component) }
		}(name))
	}
	go a.onClick(a.stopStart, a.toggleStopped)
	go a.onClick(apply, a.applyConfig)
	go a.onClick(a.retry, a.retryNow)
	go a.onClick(openLogs, a.openLogs)
	go a.onClick(openConfig, a.openConfig)
	go a.onClick(runDoctor, a.runDoctor)
	go a.onClick(a.update, a.runUpdate)
	go a.onClick(quit, systray.Quit)

	// Asking on open, rather than on a timer, ties the one piece of outbound
	// traffic this process makes to somebody actually looking at the menu. A
	// laptop whose owner never opens it never asks.
	watchMenuOpen(a.checkForUpdate)

	go a.followStatus()
}

// onClick keeps the click loops uniform; a MenuItem's channel stays open for
// the lifetime of the menu.
func (a *app) onClick(item *systray.MenuItem, fn func()) {
	for range item.ClickedCh {
		fn()
	}
}

// followStatus keeps the menu in step with the daemon, reconnecting for as
// long as the process lives. The daemon restarts on every reinstall, so a
// dropped stream is routine rather than exceptional.
func (a *app) followStatus() {
	connected := false

	for {
		err := a.client.Stream(ipc.Request{Op: ipc.OpStatusStream}, func(resp *ipc.Response) bool {
			if !connected {
				connected = true
				logf("connected to the daemon")
			}
			if resp.Status != nil {
				a.apply(resp.Status)
			}
			return true
		})

		// Transitions go to stderr, which launchd captures. A menu bar that
		// cannot reach the daemon shows it in the icon, but the reason has to
		// be recoverable afterwards — and this is the one place that knows it.
		if connected || err != nil {
			logf("daemon stream ended: %v", err)
		}
		connected = false

		a.showDisconnected(err)
		time.Sleep(3 * time.Second)
	}
}

// logf writes to stderr, which the LaunchAgent's log captures.
func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "menubar: "+format+"\n", args...)
}

func (a *app) apply(snap *status.Snapshot) {
	label := labelUnknown
	switch {
	case snap.Paused:
		label = labelPaused
	case snap.Overall == status.OverallGreen:
		label = labelOK
	case snap.Overall == status.OverallYellow:
		label = labelWarn
	case snap.Overall == status.OverallRed:
		label = labelError
	}
	systray.SetTitle(label)
	systray.SetTooltip("vpnctl — " + snap.Reason)

	if snap.Paused {
		a.stopStart.SetTitle("Start")
		a.stopStart.SetTooltip("Route traffic through the VPN stack again")
	} else {
		a.stopStart.SetTitle("Stop")
		a.stopStart.SetTooltip("Hand routing back to the machine, without removing anything")
	}

	a.header.SetTitle(snap.Reason)

	inSafeMode := false
	for _, c := range snap.Components {
		item, ok := a.components[c.Name]
		if !ok {
			continue
		}

		label := fmt.Sprintf("%-11s %s", c.Name, c.Phase)
		if c.Detail != "" {
			label += " — " + c.Detail
		}
		item.SetTitle(label)

		if c.Phase == status.PhaseSafeMode {
			inSafeMode = true
		}
	}

	if inSafeMode {
		a.retry.Show()
	} else {
		a.retry.Hide()
	}

	a.mu.Lock()
	a.lastPaused = snap.Paused
	a.mu.Unlock()

	a.applyResolvers(snap.Resolvers, snap.Paused)

	a.announce(snap)
}

// applyResolvers redraws the checkbox pool.
//
// The label carries the state the checkbox cannot: a suffix can be switched on
// in the config while its resolver file is missing, or switched off while a
// file somebody else wrote still sends those names here. A tick alone would
// claim that intent and effect always agree.
func (a *app) applyResolvers(list []status.Resolver, paused bool) {
	a.mu.Lock()
	a.resolvers = list
	a.mu.Unlock()

	if len(list) == 0 {
		a.resolverEmpty.Show()
	} else {
		a.resolverEmpty.Hide()
	}

	for i, item := range a.resolverItems {
		if i >= len(list) {
			item.Hide()
			continue
		}

		entry := list[i]
		label := entry.Domain
		if note := entry.Note(paused); note != "" {
			label += "  (" + note + ")"
		}

		item.SetTitle(label)
		if entry.Enabled {
			item.Check()
		} else {
			item.Uncheck()
		}
		item.Show()
	}
}

// toggleResolver flips one domain in the config file and asks the daemon to
// apply it.
//
// The menu bar writes the config itself rather than asking the daemon to. The
// file belongs to this user and sits in their home directory beside their
// credentials; having a root daemon edit it would put root-owned files there
// and invert who owns the configuration.
func (a *app) toggleResolver(index int) {
	a.mu.Lock()
	if index >= len(a.resolvers) {
		a.mu.Unlock()
		return
	}
	entry := a.resolvers[index]
	a.mu.Unlock()

	if a.o.ConfigPath == "" {
		notify("Cannot change resolvers", "no config path is known")
		return
	}

	want := !entry.Enabled
	if _, err := config.ToggleResolverDomain(a.o.ConfigPath, entry.Domain, want); err != nil {
		notify("Could not change "+entry.Domain, err.Error())
		return
	}

	if _, err := a.client.Do(ipc.Request{Op: ipc.OpReload}); err != nil {
		notify("Saved, but not applied", err.Error())
		return
	}

	if want {
		notify(entry.Domain+" on", "resolved through vpnctl")
	} else {
		notify(entry.Domain+" off", "its scoped resolver was removed")
	}
}

// announce notifies on a change of overall state, and only on a change: a
// notification every ten seconds would train anyone to ignore them.
func (a *app) announce(snap *status.Snapshot) {
	a.mu.Lock()
	previous := a.lastSeen
	a.lastSeen = snap.Overall
	a.mu.Unlock()

	if previous == "" || previous == snap.Overall {
		return
	}

	switch snap.Overall {
	case status.OverallRed:
		notify("Split routing is down", snap.Reason)
	case status.OverallYellow:
		notify("Degraded", snap.Reason)
	case status.OverallGreen:
		notify("Back to normal", snap.Reason)
	}
}

func (a *app) showDisconnected(err error) {
	_ = err
	systray.SetTitle(labelUnknown)
	systray.SetTooltip("vpnctl — daemon unreachable")
	a.header.SetTitle("daemon unreachable")

	for _, name := range a.order {
		a.components[name].SetTitle(fmt.Sprintf("%-11s —", name))
	}

	a.mu.Lock()
	a.lastSeen = ""
	a.mu.Unlock()
}

func (a *app) restart(component string) {
	if _, err := a.client.Do(ipc.Request{Op: ipc.OpRestart, Component: component}); err != nil {
		notify("Restart failed", err.Error())
		return
	}
	notify("Restarting "+component, "")
}

func (a *app) retryNow() {
	if _, err := a.client.Do(ipc.Request{Op: ipc.OpRetry}); err != nil {
		notify("Could not leave safe mode", err.Error())
		return
	}
	notify("Leaving safe mode", "starting sing-box again")
}

// toggleStopped switches the stack off or on.
//
// It goes through the daemon rather than launchd: the daemon keeps running and
// takes everything else down, which is what lets this work from a menu bar
// running as the user, with no password. The state is remembered, so it stays
// off across a reboot until somebody turns it back on.
func (a *app) toggleStopped() {
	a.mu.Lock()
	paused := a.lastPaused
	a.mu.Unlock()

	op := ipc.OpPause
	if paused {
		op = ipc.OpResume
	}

	if _, err := a.client.Do(ipc.Request{Op: op}); err != nil {
		notify("Could not change state", err.Error())
		return
	}

	if paused {
		notify("Started", "routing through the VPN stack again")
	} else {
		notify("Stopped", "the machine is routing its own traffic; nothing was removed")
	}
}

func (a *app) applyConfig() {
	resp, err := a.client.Do(ipc.Request{Op: ipc.OpReload})
	if err != nil {
		// The daemon validates before applying, so a rejected config has
		// changed nothing — worth saying, because the natural fear is that
		// half of it landed.
		notify("Config not applied", err.Error())
		return
	}

	r := resp.Reload
	switch {
	case r == nil || len(r.Restarted) == 0:
		notify("Config unchanged", "nothing needed restarting")
	case r.Disruptive:
		notify("Config applied", "restarting "+strings.Join(r.Restarted, ", ")+
			" — the tunnel drops for a moment")
	default:
		notify("Config applied", "restarting "+strings.Join(r.Restarted, ", "))
	}
}

func (a *app) openLogs() {
	url, err := a.web.URL()
	if err != nil {
		notify("Could not open the log page", err.Error())
		return
	}
	open(url)
}

func (a *app) openConfig() {
	path := a.o.ConfigPath
	if path == "" {
		if rec, err := installer.LoadRecord(); err == nil {
			path = rec.ConfigPath
		}
	}
	if path == "" {
		notify("Cannot find the config", "no installation record")
		return
	}
	// -t opens in the default text editor rather than whatever claims .yaml.
	_ = exec.Command("/usr/bin/open", "-t", path).Start()
}

// checkForUpdate runs on every menu open; the watcher decides whether that
// actually means asking GitHub.
func (a *app) checkForUpdate() {
	a.updates.MenuOpened(a.showVersion)
}

// showVersion writes the answer into the one item that carries it.
//
// A failed check says so rather than falling back to "up to date": the two
// look identical from here, and only one of them is a statement about the
// version you are running.
func (a *app) showVersion(st updateStatus) {
	switch {
	case st.Newer != "":
		title := "Update: " + st.Current + " → " + st.Newer
		a.setUpdateItem(title, "Downloads, verifies and installs it; macOS will ask for your password", true)
	case st.Failed:
		a.setUpdateItem(st.Current+" — could not check for updates", "", false)
	default:
		a.setUpdateItem("Up to date: "+st.Current, "", false)
	}
}

// setUpdateItem remembers the title as well as showing it, because the click
// handler replaces it with "Updating…" and has to put something back if the
// authorisation dialog is dismissed.
func (a *app) setUpdateItem(title, tooltip string, clickable bool) {
	a.mu.Lock()
	a.updateTitle = title
	a.mu.Unlock()

	a.update.SetTitle(title)
	a.update.SetTooltip(tooltip)
	if clickable {
		a.update.Enable()
	} else {
		a.update.Disable()
	}
}

// runUpdate asks for authorisation and installs, without a terminal.
//
// Updating replaces a root-owned binary and reloads a LaunchDaemon, which this
// process cannot do: it runs as the user, deliberately. So it asks the system
// to run one command as root, which puts the machine's own authorisation
// dialog in front of it. That prompt is the point — it is a person agreeing to
// replace a root-owned binary, and the alternative, letting the resident
// daemon install whatever it downloads, would let anything running under this
// account do the same without anybody being asked.
//
// The command names the binary in libexec rather than the /usr/local/bin
// symlink. Both are root-owned here, but /usr/local/bin is a directory that
// installers and package managers make writable on many machines, and handing
// a user-writable path to something that runs as root is how a convenience
// becomes an escalation.
func (a *app) runUpdate() {
	a.mu.Lock()
	previous := a.updateTitle
	a.mu.Unlock()

	a.update.SetTitle("Updating…")
	a.update.Disable()

	// -detach because installing unloads this very launchd job; see
	// detachInstall. Everything that can go wrong first — GitHub, the
	// checksum — has already failed by the time this returns, and comes back
	// here as the error text.
	script := `do shell script "` + installer.BinaryPath + ` update -detach" with administrator privileges`
	out, err := exec.Command("/usr/bin/osascript", "-e", script).CombinedOutput()

	switch {
	case err == nil:
		notify("Updating", "the menu bar restarts when it is done")
		return
	case cancelled(out):
		// Not a failure, and not worth a word.
	default:
		// A dialog rather than a notification: this is a wall of text with
		// the reason in it, and a notification would show the first line of
		// a checksum mismatch and drop the rest.
		alert("vpnctl could not update", strings.TrimSpace(string(out)))
	}

	a.update.SetTitle(previous)
	a.update.Enable()
}

// cancelled recognises the one failure that is a decision. osascript reports a
// dismissed authorisation dialog as an error like any other, and telling
// somebody their update failed because they chose not to do it would be
// nonsense.
func cancelled(out []byte) bool {
	return strings.Contains(string(out), "User canceled") ||
		strings.Contains(string(out), "-128")
}

// alert shows a dialog, for the messages worth reading rather than glancing at.
func alert(title, message string) {
	if message == "" {
		message = "no reason given"
	}
	script := fmt.Sprintf("display dialog %s with title %s with icon caution buttons {\"OK\"} default button \"OK\"",
		applescriptString(message), applescriptString(title))
	_ = exec.Command("/usr/bin/osascript", "-e", script).Start()
}

// runDoctor opens the checks in a terminal, because the answer is a page of
// text with commands to copy, which a notification cannot carry.
func (a *app) runDoctor() {
	script := `tell application "Terminal"
	activate
	do script "vpnctl doctor"
end tell`
	_ = exec.Command("/usr/bin/osascript", "-e", script).Start()
}

func open(url string) {
	_ = exec.Command("/usr/bin/open", url).Start()
}

// notify uses the system notification centre. osascript is a system binary at a
// fixed path, unlike the tools this project deliberately refuses to shell out
// to.
func notify(title, message string) {
	// Truncated here rather than in applescriptString: a notification has
	// room for a line, while a dialog is where the whole of a message goes.
	clip := func(s string) string {
		if len(s) > 200 {
			return s[:197] + "…"
		}
		return s
	}

	script := fmt.Sprintf("display notification %s with title %s",
		applescriptString(clip(message)), applescriptString(clip("vpnctl — "+title)))
	_ = exec.Command("/usr/bin/osascript", "-e", script).Start()
}

// applescriptString renders a Go string as an AppleScript literal.
//
// Everything passed through here is either a constant or text osascript
// itself produced, but it reaches a shell-adjacent interpreter, and an
// unescaped quote in an error message is the kind of thing that turns a
// diagnostic into a syntax error at exactly the moment somebody needs to
// read it.
func applescriptString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	// AppleScript string literals cannot contain a raw newline.
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\n", `" & return & "`)
	return `"` + s + `"`
}
