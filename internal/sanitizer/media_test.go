package sanitizer

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/png"
	"testing"
)

func pngBytes(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestResizeFitsAspectRatioAndStripsTrailingPayload(t *testing.T) {
	raw := append(pngBytes(t, 2400, 1200), []byte("TRAILING_PAYLOAD")...)
	result, err := InspectAndSanitize(bytes.NewReader(raw), 20<<20, 4096, 16000000)
	if err != nil {
		t.Fatal(err)
	}
	if result.Width != 1600 || result.Height != 800 {
		t.Fatalf("resize=%dx%d", result.Width, result.Height)
	}
	if bytes.Contains(result.Data, []byte("TRAILING_PAYLOAD")) {
		t.Fatal("trailing metadata survived reencoding")
	}
}

func TestOriginalPixelLimitPrecedesDecodeAndResize(t *testing.T) {
	raw := pngBytes(t, 100, 100)
	if _, err := InspectAndSanitize(bytes.NewReader(raw), 1<<20, 4096, 1000); !errors.Is(err, ErrDecompressionBomb) {
		t.Fatalf("pixel limit: %v", err)
	}
	if _, err := InspectAndSanitize(bytes.NewReader([]byte(`<svg xmlns="http://www.w3.org/2000/svg"></svg>`)), 1<<20, 4096, 16000000); !errors.Is(err, ErrDisallowedSVG) {
		t.Fatalf("SVG accepted: %v", err)
	}
}

func TestWebMAudioPreservesExistingValidatorSupport(t *testing.T) {
	raw := append([]byte{0x1a, 0x45, 0xdf, 0xa3}, bytes.Repeat([]byte{0}, 32)...)
	media, err := InspectAndSanitize(bytes.NewReader(raw), 1024, 4096, 16000000)
	if err != nil || media.ContentType != "audio/webm" || media.Extension != ".webm" {
		t.Fatalf("WebM: %+v %v", media, err)
	}
}
