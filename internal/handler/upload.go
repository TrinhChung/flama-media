package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/TrinhChung/flama-media/internal/auth"
	"github.com/TrinhChung/flama-media/internal/config"
	"github.com/TrinhChung/flama-media/internal/reporter"
	"github.com/TrinhChung/flama-media/internal/sanitizer"
	"github.com/TrinhChung/flama-media/internal/storage"
)

type UploadHandler struct {
	cfg      *config.Config
	storage  *storage.DiskStorage
	reporter reporter.Reporter
}

func NewUploadHandler(cfg *config.Config, s *storage.DiskStorage, rep reporter.Reporter) *UploadHandler {
	return &UploadHandler{cfg: cfg, storage: s, reporter: rep}
}

type UploadResponse struct {
	AssetID      string `json:"asset_id"`
	URL          string `json:"url"`
	SHA256       string `json:"sha256"`
	SizeBytes    int64  `json:"size_bytes"`
	ContentType  string `json:"content_type"`
	Deduplicated bool   `json:"deduplicated"`
	StageID      string `json:"stage_id"`
	Filename     string `json:"filename"`
	Width        int    `json:"width"`
	Height       int    `json:"height"`
	ExpiresAt    int64  `json:"expires_at"`
}

func (h *UploadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
				Detail:       "Signature check failed on upload token",
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

	// Determine max upload size allowed (min of ticket limit and server global limit)
	maxBytes := h.cfg.MaxUploadBytes
	if ticket.MaxBytes > 0 && ticket.MaxBytes < maxBytes {
		maxBytes = ticket.MaxBytes
	}

	// 2. Wrap request body with MaxBytesReader to protect against Slowloris / Memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes+(64<<10))

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

	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "MISSING_FILE", "No file found under 'file' form field")
		return
	}
	defer file.Close()

	// 4. Sanitize, verify magic bytes, and re-encode images (stripping EXIF/payloads)
	sanitized, err := sanitizer.InspectAndSanitizeWithResize(
		file,
		maxBytes,
		h.cfg.MaxImageDimension,
		h.cfg.MaxImagePixels,
		h.cfg.ResizeDimension,
	)
	if err != nil {
		if errors.Is(err, sanitizer.ErrDecompressionBomb) && h.reporter != nil {
			h.reporter.ReportIncidentAsync(reporter.SecurityIncident{
				UserID:       ticket.UserID,
				IncidentType: "DECOMPRESSION_BOMB",
				Detail:       err.Error(),
				ClientIP:     clientIP,
				Timestamp:    time.Now().UTC().Format(time.RFC3339),
			})
		} else if errors.Is(err, sanitizer.ErrDisallowedSVG) && h.reporter != nil {
			h.reporter.ReportIncidentAsync(reporter.SecurityIncident{
				UserID:       ticket.UserID,
				IncidentType: "SVG_EXPLOIT",
				Detail:       "SVG payload detected, blocked",
				ClientIP:     clientIP,
				Timestamp:    time.Now().UTC().Format(time.RFC3339),
			})
		}
		writeJSONError(w, http.StatusBadRequest, "SANITIZATION_FAILED", err.Error())
		return
	}

	// 5. Stage only. A backend-authorized commit promotes bytes into durable CAS.
	asset, err := h.storage.Stage(sanitized.Data, sanitized.Extension, sanitized.ContentType, header.Filename, ticket.UserID, sanitized.Width, sanitized.Height, time.Duration(h.cfg.StageTTLSeconds)*time.Second)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "STORAGE_ERROR", "Failed to persist media asset")
		return
	}

	// 6. Return response with canonical Flama store URL
	resp := stageUploadResponse(asset)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

func stageUploadResponse(asset *storage.StagedAsset) UploadResponse {
	return UploadResponse{AssetID: asset.SHA256, URL: "/media/staged/" + asset.StageID, SHA256: asset.SHA256, SizeBytes: asset.SizeBytes, ContentType: asset.ContentType, StageID: asset.StageID, Filename: asset.Filename, Width: asset.Width, Height: asset.Height, ExpiresAt: asset.ExpiresAt}
}

func extractClientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}
	ip := r.RemoteAddr
	if colonIdx := strings.LastIndex(ip, ":"); colonIdx != -1 {
		ip = ip[:colonIdx]
	}
	return ip
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}
