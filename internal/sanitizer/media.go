package sanitizer

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
)

var (
	ErrUnsupportedMediaType = errors.New("unsupported media type")
	ErrDecompressionBomb    = errors.New("image dimensions exceed safe limits (possible decompression bomb)")
	ErrCorruptMediaFile     = errors.New("corrupted media payload")
	ErrDisallowedSVG        = errors.New("SVG uploads are disallowed for security reasons (XSS/XXE prevention)")
)

type SanitizedMedia struct {
	Data        []byte
	ContentType string
	Extension   string
	Width       int
	Height      int
}

// InspectAndSanitize inspects magic bytes, applies decompression bomb checks,
// and re-encodes image files to strip malicious EXIF/metadata payloads.
func InspectAndSanitize(
	r io.Reader,
	maxBytes int64,
	maxDimension int,
	maxPixels int,
) (*SanitizedMedia, error) {
	// Read payload into memory (bounded by maxBytes)
	lr := io.LimitReader(r, maxBytes+1)
	buf, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("read payload error: %w", err)
	}
	if int64(len(buf)) > maxBytes {
		return nil, fmt.Errorf("file size exceeds maximum allowed size (%d bytes)", maxBytes)
	}
	if len(buf) < 16 {
		return nil, ErrCorruptMediaFile
	}

	// Detect MIME type via magic bytes
	detectedType := http.DetectContentType(buf)

	// Block SVG explicitly
	if bytes.Contains(bytes.ToLower(buf[:min(len(buf), 512)]), []byte("<svg")) ||
		bytes.Contains(bytes.ToLower(buf[:min(len(buf), 512)]), []byte("<?xml")) {
		return nil, ErrDisallowedSVG
	}

	switch detectedType {
	case "image/jpeg":
		return sanitizeImage(buf, "jpeg", ".jpg", "image/jpeg", maxDimension, maxPixels)
	case "image/png":
		return sanitizeImage(buf, "png", ".png", "image/png", maxDimension, maxPixels)
	case "image/gif":
		return sanitizeImage(buf, "gif", ".gif", "image/gif", maxDimension, maxPixels)
	case "audio/mpeg", "audio/mp3", "application/octet-stream":
		// Handle MP3 detection fallback (often flagged as octet-stream by DetectContentType)
		if isMP3(buf) {
			return &SanitizedMedia{
				Data:        buf,
				ContentType: "audio/mpeg",
				Extension:   ".mp3",
			}, nil
		}
		if isOGG(buf) {
			return &SanitizedMedia{
				Data:        buf,
				ContentType: "audio/ogg",
				Extension:   ".ogg",
			}, nil
		}
		return nil, ErrUnsupportedMediaType
	case "audio/wave", "audio/wav", "audio/x-wav":
		if isWAV(buf) {
			return &SanitizedMedia{
				Data:        buf,
				ContentType: "audio/wav",
				Extension:   ".wav",
			}, nil
		}
		return nil, ErrUnsupportedMediaType
	case "audio/ogg", "application/ogg":
		return &SanitizedMedia{
			Data:        buf,
			ContentType: "audio/ogg",
			Extension:   ".ogg",
		}, nil
	default:
		// Extra fallback check for pure MP3 without ID3 header
		if isMP3(buf) {
			return &SanitizedMedia{
				Data:        buf,
				ContentType: "audio/mpeg",
				Extension:   ".mp3",
			}, nil
		}
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedMediaType, detectedType)
	}
}

func sanitizeImage(
	raw []byte,
	format string,
	ext string,
	mime string,
	maxDim int,
	maxPixels int,
) (*SanitizedMedia, error) {
	// 1. DecodeConfig ONLY (checks dimensions without allocating massive RAM)
	cfg, _, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptMediaFile, err)
	}

	if cfg.Width <= 0 || cfg.Height <= 0 {
		return nil, ErrCorruptMediaFile
	}
	if cfg.Width > maxDim || cfg.Height > maxDim {
		return nil, fmt.Errorf("%w: dimension %dx%d exceeds %d", ErrDecompressionBomb, cfg.Width, cfg.Height, maxDim)
	}
	if cfg.Width*cfg.Height > maxPixels {
		return nil, fmt.Errorf("%w: total pixels %d exceeds %d", ErrDecompressionBomb, cfg.Width*cfg.Height, maxPixels)
	}

	// 2. Full Decode to extract raw pixels
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptMediaFile, err)
	}

	// 3. Re-encode into a clean new byte buffer (stripping 100% of EXIF, GPS, camera and polyglot payloads)
	var cleanBuf bytes.Buffer
	switch format {
	case "jpeg":
		err = jpeg.Encode(&cleanBuf, img, &jpeg.Options{Quality: 90})
	case "png":
		err = png.Encode(&cleanBuf, img)
	case "gif":
		err = gif.Encode(&cleanBuf, img, nil)
	default:
		err = png.Encode(&cleanBuf, img)
	}
	if err != nil {
		return nil, fmt.Errorf("re-encoding failed: %w", err)
	}

	return &SanitizedMedia{
		Data:        cleanBuf.Bytes(),
		ContentType: mime,
		Extension:   ext,
		Width:       cfg.Width,
		Height:      cfg.Height,
	}, nil
}

func isMP3(b []byte) bool {
	if len(b) < 3 {
		return false
	}
	// ID3v2 header starts with "ID3"
	if b[0] == 'I' && b[1] == 'D' && b[2] == '3' {
		return true
	}
	// MPEG frame sync (11 bits set: 0xFF followed by 0xE0 or higher)
	if b[0] == 0xFF && (b[1]&0xE0) == 0xE0 {
		return true
	}
	return false
}

func isWAV(b []byte) bool {
	if len(b) < 12 {
		return false
	}
	return string(b[0:4]) == "RIFF" && string(b[8:12]) == "WAVE"
}

func isOGG(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	return string(b[0:4]) == "OggS"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
