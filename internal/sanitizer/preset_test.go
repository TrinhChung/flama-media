package sanitizer

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"testing"

	xwebp "golang.org/x/image/webp"
)

func jpegWithOrientation(t *testing.T, w, h, orientation int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{R: 200, G: 100, B: 50, A: 255})
		}
	}
	var enc bytes.Buffer
	if err := jpeg.Encode(&enc, img, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatal(err)
	}
	// Minimal little-endian TIFF with one IFD entry: Orientation (0x0112), SHORT, count 1.
	tiff := []byte("II*\x00\x08\x00\x00\x00\x01\x00")
	entry := make([]byte, 12)
	binary.LittleEndian.PutUint16(entry[0:], 0x0112)
	binary.LittleEndian.PutUint16(entry[2:], 3)
	binary.LittleEndian.PutUint32(entry[4:], 1)
	binary.LittleEndian.PutUint16(entry[8:], uint16(orientation))
	tiff = append(append(tiff, entry...), 0, 0, 0, 0)
	payload := append([]byte("Exif\x00\x00"), tiff...)
	app1 := []byte{0xFF, 0xE1, byte((len(payload) + 2) >> 8), byte(len(payload) + 2)}
	raw := enc.Bytes()
	out := append([]byte{}, raw[:2]...)
	out = append(out, app1...)
	out = append(out, payload...)
	return append(out, raw[2:]...)
}

func decodeWebP(t *testing.T, data []byte) image.Image {
	t.Helper()
	if len(data) < 12 || string(data[0:4]) != "RIFF" || string(data[8:12]) != "WEBP" {
		t.Fatalf("output is not WebP: % x", data[:min(len(data), 12)])
	}
	img, err := xwebp.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func mustPreset(t *testing.T, name string) Preset {
	t.Helper()
	p, ok := ResolvePreset(name)
	if !ok {
		t.Fatalf("preset %q missing", name)
	}
	return p
}

func TestPresetFitResizesToWebPWithoutUpscaling(t *testing.T) {
	media, err := InspectAndSanitizeWithPreset(bytes.NewReader(pngBytes(t, 4000, 3000)), 20<<20, 16384, 50000000, mustPreset(t, "note_image"))
	if err != nil {
		t.Fatal(err)
	}
	if media.ContentType != "image/webp" || media.Extension != ".webp" || media.Width != 1600 || media.Height != 1200 {
		t.Fatalf("fit: %s %s %dx%d", media.ContentType, media.Extension, media.Width, media.Height)
	}
	if b := decodeWebP(t, media.Data).Bounds(); b.Dx() != 1600 || b.Dy() != 1200 {
		t.Fatalf("decoded %v", b)
	}
	small, err := InspectAndSanitizeWithPreset(bytes.NewReader(pngBytes(t, 300, 200)), 20<<20, 16384, 50000000, mustPreset(t, ""))
	if err != nil || small.Width != 300 || small.Height != 200 {
		t.Fatalf("small image changed size: %+v %v", small, err)
	}
}

func TestPresetAppliesJPEGOrientation(t *testing.T) {
	media, err := InspectAndSanitizeWithPreset(bytes.NewReader(jpegWithOrientation(t, 400, 200, 6)), 20<<20, 16384, 50000000, mustPreset(t, "note_image"))
	if err != nil {
		t.Fatal(err)
	}
	if media.Width != 200 || media.Height != 400 {
		t.Fatalf("orientation 6 not applied: %dx%d", media.Width, media.Height)
	}
}

func TestOrientationMapsCornerPixels(t *testing.T) {
	src := image.NewNRGBA(image.Rect(0, 0, 3, 2))
	src.Set(0, 0, color.NRGBA{R: 255, A: 255}) // top-left marker
	cases := map[int]image.Point{2: {2, 0}, 3: {2, 1}, 4: {0, 1}, 5: {0, 0}, 6: {1, 0}, 7: {1, 2}, 8: {0, 2}}
	for o, want := range cases {
		out := applyOrientation(src, o)
		if got := out.NRGBAAt(want.X, want.Y); got.R != 255 {
			t.Fatalf("orientation %d: marker not at %v", o, want)
		}
	}
}

func TestPresetCropsMatchFlask(t *testing.T) {
	avatar, err := InspectAndSanitizeWithPreset(bytes.NewReader(pngBytes(t, 900, 600)), 20<<20, 16384, 50000000, mustPreset(t, "avatar"))
	if err != nil || avatar.Width != 256 || avatar.Height != 256 {
		t.Fatalf("avatar: %+v %v", avatar, err)
	}
	smallAvatar, err := InspectAndSanitizeWithPreset(bytes.NewReader(pngBytes(t, 300, 200)), 20<<20, 16384, 50000000, mustPreset(t, "avatar"))
	if err != nil || smallAvatar.Width != 200 || smallAvatar.Height != 200 {
		t.Fatalf("small avatar: %+v %v", smallAvatar, err)
	}
	cover, err := InspectAndSanitizeWithPreset(bytes.NewReader(pngBytes(t, 2000, 2000)), 20<<20, 16384, 50000000, mustPreset(t, "deck_cover"))
	if err != nil || cover.Width != 1200 || cover.Height != 675 {
		t.Fatalf("cover: %+v %v", cover, err)
	}
}

func TestPresetKeepsAlphaLossless(t *testing.T) {
	img := image.NewNRGBA(image.Rect(0, 0, 64, 64))
	img.Set(10, 10, color.NRGBA{G: 255, A: 128})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	media, err := InspectAndSanitizeWithPreset(bytes.NewReader(buf.Bytes()), 20<<20, 16384, 50000000, mustPreset(t, "note_image"))
	if err != nil {
		t.Fatal(err)
	}
	if got := color.NRGBAModel.Convert(decodeWebP(t, media.Data).At(10, 10)).(color.NRGBA); got.A != 128 || got.G != 255 {
		t.Fatalf("alpha pixel changed: %+v", got)
	}
}

func TestPresetStillEnforcesLimitsAndRejectsSVG(t *testing.T) {
	p := mustPreset(t, "note_image")
	if _, err := InspectAndSanitizeWithPreset(bytes.NewReader(pngBytes(t, 100, 100)), 1<<20, 16384, 1000, p); err == nil {
		t.Fatal("pixel limit ignored")
	}
	if _, err := InspectAndSanitizeWithPreset(bytes.NewReader([]byte(`<svg xmlns="http://www.w3.org/2000/svg"></svg>`)), 1<<20, 16384, 50000000, p); err == nil {
		t.Fatal("SVG accepted")
	}
	if _, ok := ResolvePreset("no_such_preset"); ok {
		t.Fatal("unknown preset accepted")
	}
}
