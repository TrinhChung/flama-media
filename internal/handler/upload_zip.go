package handler

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/TrinhChung/flama-media/internal/auth"
	"github.com/TrinhChung/flama-media/internal/config"
	"github.com/TrinhChung/flama-media/internal/sanitizer"
	"github.com/TrinhChung/flama-media/internal/storage"
)

const (
	DefaultMaxZipEntries          = 500
	DefaultMaxZipUncompressedSize = 100 * 1024 * 1024 // 100MB total uncompressed
	DefaultMaxCompressionRatio    = 100               // Max 100:1 compression ratio (Zip Bomb guard)
)

type UploadZipHandler struct {
	cfg     *config.Config
	storage *storage.DiskStorage
}

func NewUploadZipHandler(cfg *config.Config, s *storage.DiskStorage) *UploadZipHandler {
	return &UploadZipHandler{cfg: cfg, storage: s}
}

type ZipItemResult struct {
	OriginalFilename string `json:"original_filename"`
	AssetID          string `json:"asset_id,omitempty"`
	URL              string `json:"url,omitempty"`
	SHA256           string `json:"sha256,omitempty"`
	SizeBytes        int64  `json:"size_bytes,omitempty"`
	ContentType      string `json:"content_type,omitempty"`
	Deduplicated     bool   `json:"deduplicated,omitempty"`
	Error            string `json:"error,omitempty"`
}

type ZipUploadResponse struct {
	TotalEntries  int             `json:"total_entries"`
	AcceptedCount int             `json:"accepted_count"`
	RejectedCount int             `json:"rejected_count"`
	Items         []ZipItemResult `json:"items"`
}

func (h *UploadZipHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "METHOD_NOT_ALLOWED"}`, http.StatusMethodNotAllowed)
		return
	}

	// 1. Verify Authorization Header (HMAC Ticket)
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		writeJSONError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing or invalid Bearer token")
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	ticket, err := auth.VerifyToken(token, h.cfg.SharedSecret)
	if err != nil {
		if errors.Is(err, auth.ErrTokenExpired) {
			writeJSONError(w, http.StatusForbidden, "TOKEN_EXPIRED", "Upload ticket has expired")
			return
		}
		writeJSONError(w, http.StatusForbidden, "INVALID_TOKEN", "Cryptographic signature check failed")
		return
	}

	// Max zip payload size allowed (e.g. 50MB)
	maxZipBytes := h.cfg.MaxUploadBytes * 2
	if ticket.MaxBytes > 0 && ticket.MaxBytes*2 < maxZipBytes {
		maxZipBytes = ticket.MaxBytes * 2
	}

	// 2. Wrap body to prevent DoS / slow chunk attacks
	r.Body = http.MaxBytesReader(w, r.Body, maxZipBytes+1024)

	var zipBytes []byte
	contentType := r.Header.Get("Content-Type")

	// 3. Extract ZIP either from raw body or multipart form
	if strings.HasPrefix(contentType, "application/zip") || strings.HasPrefix(contentType, "application/x-zip-compressed") {
		buf, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "PAYLOAD_TOO_LARGE", "Zip body exceeds allowed limits")
			return
		}
		zipBytes = buf
	} else {
		// Multipart form fallback
		if err := r.ParseMultipartForm(10 << 20); err != nil { // 10MB in RAM
			writeJSONError(w, http.StatusBadRequest, "PAYLOAD_TOO_LARGE", "Multipart body exceeds allowed limits")
			return
		}
		defer func() {
			if r.MultipartForm != nil {
				_ = r.MultipartForm.RemoveAll()
			}
		}()

		file, _, err := r.FormFile("file")
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "MISSING_FILE", "No zip file provided under 'file' field")
			return
		}
		defer file.Close()

		buf, err := io.ReadAll(file)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "READ_ERROR", "Failed to read uploaded zip file")
			return
		}
		zipBytes = buf
	}

	if len(zipBytes) < 22 {
		writeJSONError(w, http.StatusBadRequest, "INVALID_ZIP", "File is too small to be a valid ZIP archive")
		return
	}

	// 4. Open ZIP Archive
	zipReader, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_ZIP", "Corrupted or invalid ZIP archive")
		return
	}

	if len(zipReader.File) == 0 {
		writeJSONError(w, http.StatusBadRequest, "EMPTY_ZIP", "ZIP archive contains no files")
		return
	}
	if len(zipReader.File) > DefaultMaxZipEntries {
		writeJSONError(w, http.StatusBadRequest, "TOO_MANY_FILES",
			fmt.Sprintf("ZIP contains %d files, exceeding maximum allowed limit of %d", len(zipReader.File), DefaultMaxZipEntries))
		return
	}

	var results []ZipItemResult
	var totalUncompressed int64
	acceptedCount := 0
	rejectedCount := 0

	// 5. Safely iterate through ZIP entries with Zip Bomb guards
	for _, f := range zipReader.File {
		// Skip directories
		if f.FileInfo().IsDir() {
			continue
		}

		cleanName := filepath.Clean(f.Name)
		// Zip-Slip / Path Traversal Protection
		if strings.HasPrefix(cleanName, "..") || strings.HasPrefix(cleanName, "/") || strings.HasPrefix(cleanName, "\\") || strings.Contains(f.Name, "../") {
			results = append(results, ZipItemResult{
				OriginalFilename: f.Name,
				Error:            "unsafe filename path (traversal attempt)",
			})
			rejectedCount++
			continue
		}

		// Zip Bomb Check 1: Compression ratio guard
		if f.CompressedSize64 > 0 {
			ratio := f.UncompressedSize64 / f.CompressedSize64
			if ratio > DefaultMaxCompressionRatio {
				writeJSONError(w, http.StatusBadRequest, "ZIP_BOMB_DETECTED",
					fmt.Sprintf("Suspicious compression ratio on file %s (possible zip bomb)", f.Name))
				return
			}
		}

		// Zip Bomb Check 2: Total uncompressed size limit
		totalUncompressed += int64(f.UncompressedSize64)
		if totalUncompressed > DefaultMaxZipUncompressedSize {
			writeJSONError(w, http.StatusBadRequest, "ZIP_BOMB_DETECTED",
				"Total uncompressed content exceeds 100MB limit (possible zip bomb)")
			return
		}

		// Read file content with hard limit
		rc, err := f.Open()
		if err != nil {
			results = append(results, ZipItemResult{
				OriginalFilename: f.Name,
				Error:            "cannot open entry in archive",
			})
			rejectedCount++
			continue
		}

		// Limit reading each entry
		entryLimit := h.cfg.MaxUploadBytes
		sanitized, err := sanitizer.InspectAndSanitize(rc, entryLimit, h.cfg.MaxImageDimension, h.cfg.MaxImagePixels)
		_ = rc.Close()

		if err != nil {
			results = append(results, ZipItemResult{
				OriginalFilename: f.Name,
				Error:            err.Error(),
			})
			rejectedCount++
			continue
		}

		// Save to CAS Deduplication storage
		asset, err := h.storage.Save(sanitized.Data, sanitized.Extension, sanitized.ContentType)
		if err != nil {
			results = append(results, ZipItemResult{
				OriginalFilename: f.Name,
				Error:            "storage persist failure",
			})
			rejectedCount++
			continue
		}

		results = append(results, ZipItemResult{
			OriginalFilename: f.Name,
			AssetID:          asset.ID,
			URL:              "/media/proxy/" + asset.ID,
			SHA256:           asset.SHA256,
			SizeBytes:        asset.SizeBytes,
			ContentType:      asset.ContentType,
			Deduplicated:     asset.Deduplicated,
		})
		acceptedCount++
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(ZipUploadResponse{
		TotalEntries:  len(results),
		AcceptedCount: acceptedCount,
		RejectedCount: rejectedCount,
		Items:         results,
	})
}
