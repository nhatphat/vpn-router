package menubar

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
)

// Icons are drawn rather than shipped as assets, so there is nothing to keep in
// sync with the palette and nothing to lose. A filled disc reads at menu-bar
// size where a glyph does not.
const iconSize = 22

var (
	iconGreen   = disc(color.NRGBA{0x34, 0xC7, 0x59, 0xff})
	iconYellow  = disc(color.NRGBA{0xFF, 0x9F, 0x0A, 0xff})
	iconRed     = disc(color.NRGBA{0xFF, 0x45, 0x3A, 0xff})
	iconUnknown = ring(color.NRGBA{0x8E, 0x8E, 0x93, 0xff})
)

// disc renders an antialiased filled circle.
func disc(c color.NRGBA) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, iconSize, iconSize))
	centre := float64(iconSize) / 2
	radius := centre - 4

	for y := 0; y < iconSize; y++ {
		for x := 0; x < iconSize; x++ {
			d := math.Hypot(float64(x)+0.5-centre, float64(y)+0.5-centre)
			img.SetNRGBA(x, y, shade(c, coverage(radius-d)))
		}
	}
	return encode(img)
}

// ring renders an outline, used for "state unknown" so that a disconnected
// menu bar does not look like a healthy one in a colour nobody notices.
func ring(c color.NRGBA) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, iconSize, iconSize))
	centre := float64(iconSize) / 2
	radius := centre - 4
	const width = 2.0

	for y := 0; y < iconSize; y++ {
		for x := 0; x < iconSize; x++ {
			d := math.Hypot(float64(x)+0.5-centre, float64(y)+0.5-centre)
			// Distance from the stroke's centre line, so both edges soften.
			img.SetNRGBA(x, y, shade(c, coverage(width/2-math.Abs(d-radius))))
		}
	}
	return encode(img)
}

// coverage turns a signed distance in pixels into an alpha ramp one pixel wide.
func coverage(signedDistance float64) float64 {
	return math.Max(0, math.Min(1, signedDistance+0.5))
}

func shade(c color.NRGBA, alpha float64) color.NRGBA {
	return color.NRGBA{c.R, c.G, c.B, uint8(alpha * float64(c.A))}
}

func encode(img image.Image) []byte {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		// Encoding an in-memory image cannot fail for any reason worth
		// handling here; an empty icon is a visible, harmless fallback.
		return nil
	}
	return buf.Bytes()
}
