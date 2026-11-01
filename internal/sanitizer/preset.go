package sanitizer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"math"

	"github.com/gen2brain/webp"
	"golang.org/x/image/draw"
)

// CropMode mirrors the Flask image processor crop modes.
type CropMode string

const (
	CropFit    CropMode = "fit"
	CropSquare CropMode = "square_crop"
	CropCover  CropMode = "cover_crop"
)

// Preset is one image output profile. Values match app/services/image_processor.py
// so moving processing from Flask to Go does not change stored images.
type Preset struct {
	Name          string
	MaxWidth      int
	MaxHeight     int
	Crop          CropMode
	Quality       int
	LosslessAlpha bool
}

// DefaultPreset is used when an upload ticket names no preset.
const DefaultPreset = "note_image"

var presets = map[string]Preset{
	"avatar":        {Name: "avatar", MaxWidth: 256, MaxHeight: 256, Crop: CropSquare, Quality: 85},
	"avatar_hd":     {Name: "avatar_hd", MaxWidth: 512, MaxHeight: 512, Crop: CropSquare, Quality: 85},
	"deck_cover":    {Name: "deck_cover", MaxWidth: 1200, MaxHeight: 675, Crop: CropCover, Quality: 85},
	"note_image":    {Name: "note_image", MaxWidth: 1600, MaxHeight: 1600, Crop: CropFit, Quality: 90, LosslessAlpha: true},
	"image_library": {Name: "image_library", MaxWidth: 2048, MaxHeight: 2048, Crop: CropFit, Quality: 90},
	"thumbnail":     {Name: "thumbnail", MaxWidth: 256, MaxHeight: 256, Crop: CropFit, Quality: 80},
	"general":       {Name: "general", MaxWidth: 1920, MaxHeight: 1080, Crop: CropFit, Quality: 85},
}

// ResolvePreset returns the named preset; an empty name selects DefaultPreset.
func ResolvePreset(name string) (Preset, bool) {
	if name == "" {
		name = DefaultPreset
	}
	p, ok := presets[name]
	return p, ok
}

// webpMethod trades encode time for size (0 fast .. 6 small). On worker212 the
// pure-Go encoder takes ~0.6 s at method 2 vs ~1.6 s at 4 for 1600x1200, same size.
const webpMethod = 2

// processImagePreset decodes, auto-orients, crops/resizes by preset and re-encodes
// to WebP, which drops every original metadata block.
func processImagePreset(raw []byte, maxDim, maxPixels int, maxBytes int64, p Preset) (*SanitizedMedia, error) {
	cfg, _, err := decodeConfig(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptMediaFile, err)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 {
		return nil, ErrCorruptMediaFile
	}
	if cfg.Width > maxDim || cfg.Height > maxDim {
		return nil, fmt.Errorf("%w: dimension %dx%d exceeds %d", ErrDecompressionBomb, cfg.Width, cfg.Height, maxDim)
	}
	if int64(cfg.Width)*int64(cfg.Height) > int64(maxPixels) {
		return nil, fmt.Errorf("%w: total pixels %d exceeds %d", ErrDecompressionBomb, cfg.Width*cfg.Height, maxPixels)
	}

	img, _, err := decodeImage(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptMediaFile, err)
	}

	// Large camera images are first reduced cheaply so orientation and the final
	// high-quality resample work on at most twice the output size.
	limit := 2 * max(p.MaxWidth, p.MaxHeight)
	if b := img.Bounds(); max(b.Dx(), b.Dy()) > limit {
		w, h := scaleToFit(b.Dx(), b.Dy(), limit, limit)
		small := image.NewNRGBA(image.Rect(0, 0, w, h))
		draw.ApproxBiLinear.Scale(small, small.Bounds(), img, b, draw.Src, nil)
		img = small
	}
	out := applyOrientation(toNRGBA(img), jpegOrientation(raw))

	switch p.Crop {
	case CropSquare:
		out = squareCrop(out, p.MaxWidth)
	case CropCover:
		out = coverCrop(out, p.MaxWidth, p.MaxHeight)
	default:
		out = fitResize(out, p.MaxWidth, p.MaxHeight)
	}

	var buf bytes.Buffer
	opts := webp.Options{Quality: p.Quality, Method: webpMethod}
	if p.LosslessAlpha && !out.Opaque() {
		opts.Lossless = true
	}
	if err := webp.Encode(&buf, out, opts); err != nil {
		return nil, fmt.Errorf("re-encoding failed: %w", err)
	}
	if int64(buf.Len()) > maxBytes {
		return nil, fmt.Errorf("sanitized file exceeds maximum allowed size")
	}
	b := out.Bounds()
	return &SanitizedMedia{Data: buf.Bytes(), ContentType: "image/webp", Extension: ".webp", Width: b.Dx(), Height: b.Dy()}, nil
}

// scaleToFit returns the size that fits inside maxW x maxH keeping aspect ratio, never upscaling.
func scaleToFit(w, h, maxW, maxH int) (int, int) {
	if w <= maxW && h <= maxH {
		return w, h
	}
	scale := math.Min(float64(maxW)/float64(w), float64(maxH)/float64(h))
	return max(1, int(float64(w)*scale)), max(1, int(float64(h)*scale))
}

func resample(src *image.NRGBA, r image.Rectangle, w, h int) *image.NRGBA {
	dst := image.NewNRGBA(image.Rect(0, 0, w, h))
	draw.CatmullRom.Scale(dst, dst.Bounds(), src, r, draw.Src, nil)
	return dst
}

func crop(src *image.NRGBA, r image.Rectangle) *image.NRGBA {
	dst := image.NewNRGBA(image.Rect(0, 0, r.Dx(), r.Dy()))
	draw.Draw(dst, dst.Bounds(), src, r.Min, draw.Src)
	return dst
}

func fitResize(src *image.NRGBA, maxW, maxH int) *image.NRGBA {
	b := src.Bounds()
	w, h := scaleToFit(b.Dx(), b.Dy(), maxW, maxH)
	if w == b.Dx() && h == b.Dy() {
		return src
	}
	return resample(src, b, w, h)
}

func squareCrop(src *image.NRGBA, size int) *image.NRGBA {
	b := src.Bounds()
	side := min(b.Dx(), b.Dy())
	r := image.Rect(0, 0, side, side).Add(image.Pt(b.Min.X+(b.Dx()-side)/2, b.Min.Y+(b.Dy()-side)/2))
	if side > size {
		return resample(src, r, size, size)
	}
	return crop(src, r)
}

func coverCrop(src *image.NRGBA, targetW, targetH int) *image.NRGBA {
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	target := float64(targetW) / float64(targetH)
	var r image.Rectangle
	if float64(w)/float64(h) > target {
		nw := int(float64(h) * target)
		r = image.Rect(0, 0, nw, h).Add(image.Pt(b.Min.X+(w-nw)/2, b.Min.Y))
	} else {
		nh := int(float64(w) / target)
		r = image.Rect(0, 0, w, nh).Add(image.Pt(b.Min.X, b.Min.Y+(h-nh)/2))
	}
	if r.Dx() > targetW || r.Dy() > targetH {
		return resample(src, r, targetW, targetH)
	}
	return crop(src, r)
}

func toNRGBA(src image.Image) *image.NRGBA {
	if n, ok := src.(*image.NRGBA); ok && n.Bounds().Min == (image.Point{}) {
		return n
	}
	b := src.Bounds()
	dst := image.NewNRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(dst, dst.Bounds(), src, b.Min, draw.Src)
	return dst
}

// applyOrientation turns stored pixels upright for EXIF orientation 2..8.
func applyOrientation(src *image.NRGBA, orientation int) *image.NRGBA {
	if orientation < 2 || orientation > 8 {
		return src
	}
	w, h := src.Bounds().Dx(), src.Bounds().Dy()
	dw, dh := w, h
	if orientation >= 5 {
		dw, dh = h, w
	}
	dst := image.NewNRGBA(image.Rect(0, 0, dw, dh))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			var dx, dy int
			switch orientation {
			case 2:
				dx, dy = w-1-x, y
			case 3:
				dx, dy = w-1-x, h-1-y
			case 4:
				dx, dy = x, h-1-y
			case 5:
				dx, dy = y, x
			case 6:
				dx, dy = h-1-y, x
			case 7:
				dx, dy = h-1-y, w-1-x
			case 8:
				dx, dy = y, w-1-x
			}
			copy(dst.Pix[dy*dst.Stride+dx*4:dy*dst.Stride+dx*4+4], src.Pix[y*src.Stride+x*4:y*src.Stride+x*4+4])
		}
	}
	return dst
}

// jpegOrientation reads the EXIF orientation tag of a JPEG; 1 means upright or unknown.
func jpegOrientation(b []byte) int {
	if len(b) < 4 || b[0] != 0xFF || b[1] != 0xD8 {
		return 1
	}
	for i := 2; i+4 <= len(b); {
		if b[i] != 0xFF {
			return 1
		}
		marker := b[i+1]
		if marker == 0xFF { // fill byte
			i++
			continue
		}
		if marker == 0xD9 || marker == 0xDA { // end of image / start of scan
			return 1
		}
		size := int(b[i+2])<<8 | int(b[i+3])
		if size < 2 || i+2+size > len(b) {
			return 1
		}
		if seg := b[i+4 : i+2+size]; marker == 0xE1 && len(seg) >= 6 && string(seg[:6]) == "Exif\x00\x00" {
			return tiffOrientation(seg[6:])
		}
		i += 2 + size
	}
	return 1
}

func tiffOrientation(t []byte) int {
	if len(t) < 8 {
		return 1
	}
	var order binary.ByteOrder
	switch string(t[:2]) {
	case "II":
		order = binary.LittleEndian
	case "MM":
		order = binary.BigEndian
	default:
		return 1
	}
	ifd := int(order.Uint32(t[4:8]))
	if ifd < 8 || ifd+2 > len(t) {
		return 1
	}
	entries := int(order.Uint16(t[ifd:]))
	for k := 0; k < entries; k++ {
		e := ifd + 2 + k*12
		if e+12 > len(t) {
			return 1
		}
		if order.Uint16(t[e:]) == 0x0112 {
			if v := int(order.Uint16(t[e+8:])); v >= 1 && v <= 8 {
				return v
			}
			return 1
		}
	}
	return 1
}
