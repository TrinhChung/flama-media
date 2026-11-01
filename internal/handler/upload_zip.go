package handler

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/TrinhChung/flama-media/internal/auth"
	"github.com/TrinhChung/flama-media/internal/config"
	"github.com/TrinhChung/flama-media/internal/reporter"
	"github.com/TrinhChung/flama-media/internal/sanitizer"
	"github.com/TrinhChung/flama-media/internal/storage"
)

const (
	DefaultMaxZipEntries          = 500
	DefaultMaxZipUncompressedSize = 100 * 1024 * 1024 // 100MB total uncompressed
	DefaultMaxCompressionRatio    = 100               // Max 100:1 compression ratio (Zip Bomb guard)
)

type UploadZipHandler struct {
	cfg      *config.Config
	storage  *storage.DiskStorage
	reporter reporter.Reporter
}

func NewUploadZipHandler(cfg *config.Config, s *storage.DiskStorage, rep reporter.Reporter) *UploadZipHandler {
	return &UploadZipHandler{cfg: cfg, storage: s, reporter: rep}
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
	StageID          string `json:"stage_id,omitempty"`
	Filename         string `json:"filename,omitempty"`
	Width            int    `json:"width,omitempty"`
	Height           int    `json:"height,omitempty"`
	ExpiresAt        int64  `json:"expires_at,omitempty"`
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

	clientIP := extractClientIP(r)

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
		if errors.Is(err, auth.ErrInvalidSignature) && h.reporter != nil {
			h.reporter.ReportIncidentAsync(reporter.SecurityIncident{
				IncidentType: "FORGED_TOKEN",
				Detail:       "Signature check failed on zip upload token",
				ClientIP:     clientIP,
				Timestamp:    time.Now().UTC().Format(time.RFC3339),
			})
		}
		writeJSONError(w, http.StatusForbidden, "INVALID_TOKEN", "Cryptographic signature check failed")
		return
	}
	if ticket.Action != "upload" || ticket.UserID <= 0 || ticket.MaxBytes <= 0 {
		writeJSONError(w, http.StatusForbidden, "INVALID_TICKET_SCOPE", "An owner-scoped upload ticket is required")
		return
	}

	// Max zip payload size allowed (e.g. 50MB)
	maxZipBytes := h.cfg.MaxUploadBytes * 2
	if ticket.MaxBytes > 0 && ticket.MaxBytes < maxZipBytes {
		maxZipBytes = ticket.MaxBytes
	}

	// 2. Wrap body to prevent DoS / slow chunk attacks
	r.Body = http.MaxBytesReader(w, r.Body, maxZipBytes+(64<<10))

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
	if int64(len(zipBytes)) > maxZipBytes {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "ZIP archive exceeds allowed limits")
		return
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

		cleanName := path.Clean(strings.ReplaceAll(f.Name, "\\", "/"))
		// Zip-Slip / Path Traversal Protection
		if cleanName == ".." || strings.HasPrefix(cleanName, "../") || strings.HasPrefix(cleanName, "/") || strings.Contains(f.Name, "../") || strings.Contains(f.Name, "..\\") || strings.Contains(cleanName, ":") || f.Mode()&os.ModeSymlink != 0 {
			results = append(results, ZipItemResult{
				OriginalFilename: f.Name,
				Error:            "unsafe filename path (traversal attempt)",
			})
			rejectedCount++
			if h.reporter != nil {
				h.reporter.ReportIncidentAsync(reporter.SecurityIncident{
					UserID:       ticket.UserID,
					IncidentType: "ZIP_SLIP",
					Detail:       fmt.Sprintf("Zip-Slip path traversal attempt: %s", f.Name),
					ClientIP:     clientIP,
					Timestamp:    time.Now().UTC().Format(time.RFC3339),
				})
			}
			continue
		}

		// Zip Bomb Check 1: Compression ratio guard
		if f.CompressedSize64 == 0 && f.UncompressedSize64 > 0 {
			writeJSONError(w, http.StatusBadRequest, "ZIP_BOMB_DETECTED", "Invalid compressed entry size")
			return
		}
		if f.CompressedSize64 > 0 {
			ratio := f.UncompressedSize64 / f.CompressedSize64
			if ratio > DefaultMaxCompressionRatio {
				if h.reporter != nil {
					h.reporter.ReportIncidentAsync(reporter.SecurityIncident{
						UserID:       ticket.UserID,
						IncidentType: "ZIP_BOMB",
						Detail:       fmt.Sprintf("Suspicious compression ratio on file %s (%d:1)", f.Name, ratio),
						ClientIP:     clientIP,
						Timestamp:    time.Now().UTC().Format(time.RFC3339),
					})
				}
				writeJSONError(w, http.StatusBadRequest, "ZIP_BOMB_DETECTED",
					fmt.Sprintf("Suspicious compression ratio on file %s (possible zip bomb)", f.Name))
				return
			}
		}

		// Zip Bomb Check 2: Total uncompressed size limit
		if f.UncompressedSize64 > uint64(DefaultMaxZipUncompressedSize-totalUncompressed) {
			if h.reporter != nil {
				h.reporter.ReportIncidentAsync(reporter.SecurityIncident{
					UserID:       ticket.UserID,
					IncidentType: "ZIP_BOMB",
					Detail:       "Total uncompressed content exceeds 100MB limit (possible zip bomb)",
					ClientIP:     clientIP,
					Timestamp:    time.Now().UTC().Format(time.RFC3339),
				})
			}
			writeJSONError(w, http.StatusBadRequest, "ZIP_BOMB_DETECTED",
				"Total uncompressed content exceeds 100MB limit (possible zip bomb)")
			return
		}
		totalUncompressed += int64(f.UncompressedSize64)

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
		if ticket.MaxBytes < entryLimit {
			entryLimit = ticket.MaxBytes
		}
		sanitized, err := sanitizer.InspectAndSanitizeWithResize(rc, entryLimit, h.cfg.MaxImageDimension, h.cfg.MaxImagePixels, h.cfg.ResizeDimension)
		_ = rc.Close()

		if err != nil {
			if errors.Is(err, sanitizer.ErrDecompressionBomb) && h.reporter != nil {
				h.reporter.ReportIncidentAsync(reporter.SecurityIncident{
					UserID:       ticket.UserID,
					IncidentType: "DECOMPRESSION_BOMB",
					Detail:       fmt.Sprintf("File %s in zip: %v", f.Name, err),
					ClientIP:     clientIP,
					Timestamp:    time.Now().UTC().Format(time.RFC3339),
				})
			} else if errors.Is(err, sanitizer.ErrDisallowedSVG) && h.reporter != nil {
				h.reporter.ReportIncidentAsync(reporter.SecurityIncident{
					UserID:       ticket.UserID,
					IncidentType: "SVG_EXPLOIT",
					Detail:       fmt.Sprintf("SVG file %s detected in zip", f.Name),
					ClientIP:     clientIP,
					Timestamp:    time.Now().UTC().Format(time.RFC3339),
				})
			}
			results = append(results, ZipItemResult{
				OriginalFilename: f.Name,
				Error:            err.Error(),
			})
			rejectedCount++
			continue
		}

		// ZIP extraction produces owner-scoped stages; it does not commit notes.
		asset, err := h.storage.Stage(sanitized.Data, sanitized.Extension, sanitized.ContentType, filepath.Base(cleanName), ticket.UserID, sanitized.Width, sanitized.Height, time.Duration(h.cfg.StageTTLSeconds)*time.Second)
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
			AssetID:          asset.SHA256,
			URL:              "/media/staged/" + asset.StageID,
			SHA256:           asset.SHA256,
			SizeBytes:        asset.SizeBytes,
			ContentType:      asset.ContentType,
			StageID:          asset.StageID,
			Filename:         asset.Filename,
			Width:            asset.Width,
			Height:           asset.Height,
			ExpiresAt:        asset.ExpiresAt,
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
