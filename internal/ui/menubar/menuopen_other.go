//go:build !darwin

package menubar

// watchMenuOpen has no equivalent away from AppKit. The menu bar is a macOS
// front end — this exists so the package still compiles elsewhere, not so it
// works there.
func watchMenuOpen(fn func()) {}
