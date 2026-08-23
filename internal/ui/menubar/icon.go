package menubar

import (
	"bytes"
	"image"
	"image/color"
	"image/png"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

// The menu bar shows a short coloured word rather than a coloured dot.
//
// A dot needs a legend: green, amber and grey mean nothing until somebody
// tells you what they mean, and the difference between amber and grey is not
// obvious at a glance in a menu bar. A word says which state it is in, and the
// colour then reinforces it instead of carrying it alone — which also leaves
// the item readable for anyone who cannot separate those hues.
//
// Rendered rather than set as the item's title because a title has no colour;
// only an image can carry one.
const (
	iconHeight = 22
	// baseline sits the 13-pixel face centred in that height.
	baseline = 16
	padding  = 2
)

var (
	green = color.NRGBA{0x1E, 0xA0, 0x4A, 0xff}
	amber = color.NRGBA{0xC7, 0x7A, 0x0A, 0xff}
	red   = color.NRGBA{0xD3, 0x35, 0x2A, 0xff}
	grey  = color.NRGBA{0x80, 0x80, 0x85, 0xff}
)

var (
	iconOK      = label("VPN OK", green)
	iconWarn    = label("VPN !", amber)
	iconError   = label("VPN X", red)
	iconUnknown = label("VPN ?", grey)
	iconPaused  = label("VPN OFF", grey)
)

// label draws text in one colour on transparency, sized to fit.
func label(text string, c color.NRGBA) []byte {
	face := basicfont.Face7x13
	width := font.MeasureString(face, text).Ceil() + padding*2

	img := image.NewNRGBA(image.Rect(0, 0, width, iconHeight))

	d := &font.Drawer{
		Dst:  img,
		Src:  image.NewUniform(c),
		Face: face,
		Dot:  fixed.P(padding, baseline),
	}
	d.DrawString(text)

	return encode(img)
}

// encode is separate so a failure here is a blank icon rather than a panic in
// a package-level initialiser.
func encode(img image.Image) []byte {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil
	}
	return buf.Bytes()
}
