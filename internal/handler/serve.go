package handler

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/TrinhChung/flama-media/internal/config"
	"github.com/TrinhChung/flama-media/internal/storage"
)

type ServeHandler struct {
	cfg     *config.Config
	storage *storage.DiskStorage
}

func NewServeHandler(cfg *config.Config, s *storage.DiskStorage) *ServeHandler {
	return &ServeHandler{cfg: cfg, storage: s}
}

// ServeHTTP handles GET /media/proxy/{id}
func (h *ServeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, `{"error": "METHOD_NOT_ALLOWED"}`, http.StatusMethodNotAllowed)
		return
	}

	// Extract asset ID from path: /store/<id>, /media/store/<id>, or /media/proxy/<id>
	path := r.URL.Path
	for _, prefix := range []string{"/media/store/", "/store/", "/media/proxy/"} {
		if strings.HasPrefix(path, prefix) {
			path = strings.TrimPrefix(path, prefix)
			break
		}
	}
	assetID := strings.Trim(path, "/")

	if assetID == "" || strings.Contains(assetID, "/") || strings.Contains(assetID, "..") {
		writeJSONError(w, http.StatusBadRequest, "INVALID_ASSET_ID", "Invalid media asset identifier")
		return
	}

	fullPath, err := h.storage.FindById(assetID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeJSONError(w, http.StatusNotFound, "MEDIA_NOT_FOUND", "Media file not found")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "ACCESS_DENIED", "Access to specified file is denied")
		return
	}

	fileInfo, err := os.Stat(fullPath)
	if err != nil || fileInfo.IsDir() {
		writeJSONError(w, http.StatusNotFound, "MEDIA_NOT_FOUND", "Media file not found")
		return
	}

	ext := strings.ToLower(filepath.Ext(fullPath))
	mimeType := getMimeByExt(ext)

	// Hardened Security Headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("Content-Type", mimeType)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")

	downloadFilename := assetID
	if !strings.HasSuffix(strings.ToLower(assetID), ext) {
		downloadFilename = assetID + ext
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="%s"`, downloadFilename))

	// Weak ETag using modtime and size
	etag := fmt.Sprintf(`"%x-%x"`, fileInfo.ModTime().UnixNano(), fileInfo.Size())
	w.Header().Set("ETag", etag)

	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	file, err := os.Open(fullPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "IO_ERROR", "Cannot read media file")
		return
	}
	defer file.Close()

	http.ServeContent(w, r, fileInfo.Name(), fileInfo.ModTime(), file)
}

func getMimeByExt(ext string) string {
	switch ext {
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	case ".svg":
		return "image/svg+xml"
	case ".mp3":
		return "audio/mpeg"
	case ".ogg":
		return "audio/ogg"
	case ".wav":
		return "audio/wav"
	case ".webm":
		return "audio/webm"
	case ".m4a":
		return "audio/mp4"
	case ".aac":
		return "audio/aac"
	case ".flac":
		return "audio/flac"
	case ".opus":
		return "audio/opus"
	default:
		return "application/octet-stream"
	}
}
