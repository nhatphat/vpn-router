package menubar

// The menu bar shows a short label rather than a drawn icon.
//
// Three attempts got here. A coloured dot needs a legend before it means
// anything, and amber against grey is not a distinction to rely on at a
// glance. Drawing coloured words solved the meaning but looked wrong: the only
// font available without shipping one is a 7x13 bitmap face, which sits badly
// next to native menu bar text.
//
// An emoji brings its own colour and its own shape, the system draws it
// properly at whatever size the menu bar is using, and the word beside it says
// which application this is. Nothing to render, nothing to keep in sync with a
// palette.
const (
	labelOK      = "✅ VPN"
	labelWarn    = "⚠️ VPN"
	labelError   = "❌ VPN"
	labelPaused  = "⏸️ VPN"
	labelUnknown = "❔ VPN"
)
