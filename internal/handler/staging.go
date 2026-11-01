package handler

import (
	"crypto/hmac"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/TrinhChung/flama-media/internal/config"
	"github.com/TrinhChung/flama-media/internal/storage"
)

type StagingHandler struct {
	cfg     *config.Config
	storage *storage.DiskStorage
}

func NewStagingHandler(cfg *config.Config, store *storage.DiskStorage) *StagingHandler {
	return &StagingHandler{cfg: cfg, storage: store}
}

func (h *StagingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		id := strings.TrimPrefix(r.URL.Path, "/media/staged/")
		file, err := h.storage.OpenStage(id)
		if err != nil {
			stageError(w, err)
			return
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			stageError(w, storage.ErrStageNotFound)
			return
		}
		w.Header().Set("Content-Type", getMimeByExt(filepath.Ext(info.Name())))
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
		http.ServeContent(w, r, info.Name(), info.ModTime(), file)
		return
	}
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	if h.cfg.InternalSecret == "" || !hmac.Equal([]byte(r.Header.Get("X-Internal-Secret")), []byte(h.cfg.InternalSecret)) {
		writeJSONError(w, http.StatusForbidden, "INTERNAL_ACCESS_DENIED", "Internal authentication required")
		return
	}
	var items []storage.StagedAsset
	var err error
	if r.URL.Path == "/media/assets/inspect" {
		var body struct {
			AssetIDs []string `json:"asset_ids"`
		}
		if !decodeStageJSON(w, r, &body) {
			return
		}
		if len(body.AssetIDs) == 0 || len(body.AssetIDs) > 500 {
			writeJSONError(w, 400, "INVALID_ASSET_IDS", "Between 1 and 500 asset IDs required")
			return
		}
		type assetStatus struct {
			AssetID   string `json:"asset_id"`
			Exists    bool   `json:"exists"`
			SizeBytes int64  `json:"size_bytes"`
		}
		statuses := make([]assetStatus, 0, len(body.AssetIDs))
		for _, id := range body.AssetIDs {
			status := assetStatus{AssetID: id}
			if path, err := h.storage.FindById(id); err == nil {
				if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
					status.Exists = true
					status.SizeBytes = info.Size()
				}
			}
			statuses = append(statuses, status)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": statuses})
		return
	} else if r.URL.Path == "/media/commit" {
		var body struct {
			UserID int64                `json:"user_id"`
			Items  []storage.CommitItem `json:"items"`
		}
		if !decodeStageJSON(w, r, &body) {
			return
		}
		items, err = h.storage.CommitStages(body.UserID, body.Items)
	} else if r.URL.Path == "/media/staged/inspect" {
		var body struct {
			UserID   int64    `json:"user_id"`
			StageIDs []string `json:"stage_ids"`
		}
		if !decodeStageJSON(w, r, &body) {
			return
		}
		items, err = h.storage.InspectStages(body.UserID, body.StageIDs)
	} else {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		stageError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
}

func decodeStageJSON(w http.ResponseWriter, r *http.Request, body any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(body) != nil || decoder.Decode(new(any)) != io.EOF {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "A single valid JSON object is required")
		return false
	}
	return true
}

func stageError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, storage.ErrStageNotFound):
		writeJSONError(w, http.StatusNotFound, "STAGE_NOT_FOUND", err.Error())
	case errors.Is(err, storage.ErrStageOwnership):
		writeJSONError(w, http.StatusForbidden, "STAGE_FORBIDDEN", err.Error())
	case errors.Is(err, storage.ErrAliasConflict):
		writeJSONError(w, http.StatusConflict, "ALIAS_CONFLICT", err.Error())
	default:
		writeJSONError(w, http.StatusBadRequest, "STAGE_ERROR", err.Error())
	}
}
