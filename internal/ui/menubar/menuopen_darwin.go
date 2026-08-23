//go:build darwin

package menubar

// The menu bar has to notice when its own menu is opened, and systray does not
// say: it hands the NSMenu to the status item and never hears about it again.
//
// AppKit does say, to anyone who asks. NSMenu posts
// NSMenuDidBeginTrackingNotification when a menu starts tracking, so observing
// that notification with no object filter catches this process's menu without
// needing a handle on it, and without patching the library.
//
// Submenus post it too, so anything acting on this must tolerate several
// notifications for what a person would call one open.

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa

void vpnctlWatchMenuOpen(void);
*/
import "C"

var onMenuOpen func()

// watchMenuOpen calls fn whenever a menu begins tracking. It must run on the
// main thread, after the application exists — onReady is both.
func watchMenuOpen(fn func()) {
	onMenuOpen = fn
	C.vpnctlWatchMenuOpen()
}

//export vpnctlMenuOpened
func vpnctlMenuOpened() {
	if onMenuOpen != nil {
		onMenuOpen()
	}
}
