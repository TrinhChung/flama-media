package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/TrinhChung/flama-media/internal/auth"
	"github.com/TrinhChung/flama-media/internal/config"
	"github.com/TrinhChung/flama-media/internal/sanitizer"
	"github.com/TrinhChung/flama-media/internal/storage"
)

type UploadHandler struct {
	cfg     *config.Config
	storage *storage.DiskStorage
}

func NewUploadHandler(cfg *config.Config, s *storage.DiskStorage) *UploadHandler {
	return &UploadHandler{cfg: cfg, storage: s}
}

type UploadResponse struct {
	AssetID     string `json:"asset_id"`
	URL         string `json:"url"`
	SHA256      string `json:"sha256"`
	SizeBytes   int64  `json:"size_bytes"`
	ContentType string `json:"content_type"`
}

func (h *UploadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "METHOD_NOT_ALLOWED"}`, http.StatusMethodNotAllowed)
		return
	}

	// 1. Verify Authorization Header (HMAC Ticket)
	authHeader := r.Headers.Get("Authorization")
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

	// Determine max upload size allowed (min of ticket limit and server global limit)
	maxBytes := h.cfg.MaxUploadBytes
	if ticket.MaxBytes > 0 && ticket.MaxBytes < maxBytes {
		maxBytes = ticket.MaxBytes
	}

	// 2. Wrap request body with MaxBytesReader to protect against Slowloris / Memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes+1024)

	// 3. Parse Multipart Form (1MB in memory, rest spills to disk if needed)
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		writeJSONError(w, http.StatusBadRequest, "PAYLOAD_TOO_LARGE", "Request body exceeds allowed upload limits")
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	file, _, err := r.FormFile("file")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "MISSING_FILE", "No file found under 'file' form field")
		return
	}
	defer file.Close()

	// 4. Sanitize, verify magic bytes, and re-encode images (stripping EXIF/payloads)
	sanitized, err := sanitizer.InspectAndSanitize(
		file,
		maxBytes,
		h.cfg.MaxImageDimension,
		h.cfg.MaxImagePixels,
	)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "SANITIZATION_FAILED", err.Error())
		return
	}

	// 5. Save to disk under random UUIDv4
	asset, err := h.storage.Save(sanitized.Data, sanitized.Extension, sanitized.ContentType)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "STORAGE_ERROR", "Failed to persist media asset")
		return
	}

	// 6. Return response with canonical Flama proxy URL
	resp := UploadResponse{
		AssetID:     asset.ID,
		URL:         "/media/proxy/" + asset.ID,
		SHA256:      asset.SHA256,
		SizeBytes:   asset.SizeBytes,
		ContentType: asset.ContentType,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}
