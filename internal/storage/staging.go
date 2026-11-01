package storage

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	stagePattern      = regexp.MustCompile(`^stg_[0-9a-f]{32}$`)
	uuidPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	ErrStageNotFound  = errors.New("staged media does not exist or has expired")
	ErrStageOwnership = errors.New("staged media belongs to another user")
	ErrAliasConflict  = errors.New("media alias is already assigned")
)

// Ubuntu systemd-tmpfiles owns physical cleanup. The API independently rejects
// expired leases, so periodic OS cleanup never extends their authorization.
const DefaultStageTTL = 24 * time.Hour

type StagedAsset struct {
	StageID      string `json:"stage_id"`
	AssetID      string `json:"asset_id"`
	SHA256       string `json:"sha256"`
	SizeBytes    int64  `json:"size_bytes"`
	ContentType  string `json:"content_type"`
	RelativePath string `json:"relative_path"`
	Filename     string `json:"filename"`
	Width        int    `json:"width"`
	Height       int    `json:"height"`
	ExpiresAt    int64  `json:"expires_at"`
}

type stageRecord struct {
	StagedAsset
	UserID    int64  `json:"user_id"`
	Extension string `json:"extension"`
	Committed bool   `json:"committed"`
}

type CommitItem struct {
	StageID string `json:"stage_id"`
	AssetID string `json:"asset_id"`
}

func validMediaExtension(ext string) bool {
	switch ext {
	case ".jpg", ".png", ".gif", ".webp", ".mp3", ".wav", ".ogg", ".webm":
		return true
	}
	return false
}

func atomicWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".write-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0640); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func (s *DiskStorage) stageDir(id string) string { return filepath.Join(s.rootDir, "staging", id) }
func (s *DiskStorage) casRelative(record *stageRecord) string {
	return record.SHA256[:2] + "/" + record.SHA256[2:4] + "/" + record.SHA256 + record.Extension
}

// Stage creates an owner-scoped lease. Deduplication never shares upload leases.
// Its directory is on the CAS filesystem so commit needs only an atomic rename.
func (s *DiskStorage) Stage(data []byte, ext, contentType, filename string, userID int64, width, height int, ttl time.Duration) (*StagedAsset, error) {
	if userID <= 0 || !validMediaExtension(ext) {
		return nil, fmt.Errorf("invalid stage metadata")
	}
	if ttl <= 0 {
		ttl = DefaultStageTTL
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	stageID := "stg_" + hex.EncodeToString(random)
	hash := sha256.Sum256(data)
	sha := hex.EncodeToString(hash[:])
	filename = strings.TrimSpace(filepath.Base(strings.ReplaceAll(filename, "\\", "/")))
	filename = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return '-'
		}
		return r
	}, filename)
	if filename == "" || filename == "." || len(filename) > 255 {
		filename = sha + ext
	}
	record := stageRecord{
		StagedAsset: StagedAsset{StageID: stageID, AssetID: sha, SHA256: sha, SizeBytes: int64(len(data)), ContentType: contentType, Filename: filename, Width: width, Height: height, ExpiresAt: time.Now().Add(ttl).Unix()},
		UserID:      userID, Extension: ext,
	}
	record.RelativePath = s.casRelative(&record)
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := s.stageDir(stageID)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, err
	}
	unlock, err := lockDirectory(dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := atomicWrite(filepath.Join(dir, "payload"+ext), data); err != nil {
		return nil, err
	}
	metadata, _ := json.Marshal(record)
	if err := atomicWrite(filepath.Join(dir, "metadata.json"), metadata); err != nil {
		return nil, err
	}
	return &record.StagedAsset, nil
}

// Callers hold the directory flock throughout metadata/path operations. tmpfiles
// respects BSD directory locks and will skip the entire in-use stage subtree.
func (s *DiskStorage) readStageLocked(stageID string, userID int64) (*stageRecord, func(), error) {
	noop := func() {}
	if !stagePattern.MatchString(stageID) {
		return nil, noop, ErrStageNotFound
	}
	unlock, err := lockDirectory(s.stageDir(stageID))
	if err != nil {
		return nil, noop, ErrStageNotFound
	}
	data, err := os.ReadFile(filepath.Join(s.stageDir(stageID), "metadata.json"))
	if err != nil {
		unlock()
		return nil, noop, ErrStageNotFound
	}
	var record stageRecord
	if json.Unmarshal(data, &record) != nil || record.StageID != stageID || !validMediaExtension(record.Extension) || !shaPattern.MatchString(record.SHA256) || record.ExpiresAt <= time.Now().Unix() {
		unlock()
		return nil, noop, ErrStageNotFound
	}
	if userID > 0 && record.UserID != userID {
		unlock()
		return nil, noop, ErrStageOwnership
	}
	return &record, unlock, nil
}

var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (s *DiskStorage) stagePathLocked(record *stageRecord) string {
	if record.Committed {
		return filepath.Join(s.rootDir, filepath.FromSlash(s.casRelative(record)))
	}
	path := filepath.Join(s.stageDir(record.StageID), "payload"+record.Extension)
	// Recover a crash after rename but before metadata/alias acknowledgement.
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return filepath.Join(s.rootDir, filepath.FromSlash(s.casRelative(record)))
	}
	return path
}

func (s *DiskStorage) InspectStages(userID int64, stageIDs []string) ([]StagedAsset, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if userID <= 0 || len(stageIDs) == 0 || len(stageIDs) > 500 {
		return nil, fmt.Errorf("invalid inspection request")
	}
	items := make([]StagedAsset, 0, len(stageIDs))
	for _, id := range stageIDs {
		record, unlock, err := s.readStageLocked(id, userID)
		if err != nil {
			return nil, err
		}
		_, statErr := os.Stat(s.stagePathLocked(record))
		unlock()
		if statErr != nil {
			return nil, ErrStageNotFound
		}
		items = append(items, record.StagedAsset)
	}
	return items, nil
}

func (s *DiskStorage) OpenStage(stageID string) (*os.File, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, unlock, err := s.readStageLocked(stageID, 0)
	if err != nil {
		return nil, err
	}
	defer unlock()
	// An open FD keeps Linux bytes alive even if tmpfiles unlinks after unlock.
	return os.Open(s.stagePathLocked(record))
}

func (s *DiskStorage) aliasPath(id string) string {
	return filepath.Join(s.rootDir, "aliases", id[:2], id+".json")
}

func (s *DiskStorage) readAliasLocked(id string) (*StagedAsset, error) {
	if !uuidPattern.MatchString(id) {
		return nil, os.ErrNotExist
	}
	data, err := os.ReadFile(s.aliasPath(id))
	if err != nil {
		return nil, err
	}
	var asset StagedAsset
	if json.Unmarshal(data, &asset) != nil || asset.AssetID != id || !shaPattern.MatchString(asset.SHA256) {
		return nil, os.ErrNotExist
	}
	ext := filepath.Ext(asset.RelativePath)
	expected := asset.SHA256[:2] + "/" + asset.SHA256[2:4] + "/" + asset.SHA256 + ext
	if !validMediaExtension(ext) || asset.RelativePath != expected {
		return nil, os.ErrNotExist
	}
	return &asset, nil
}

// CommitStages validates the complete batch, then atomically renames each stage
// into permanent CAS. There is no copy of media bytes on the commit path.
func (s *DiskStorage) CommitStages(userID int64, items []CommitItem) ([]StagedAsset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if userID <= 0 || len(items) == 0 || len(items) > 500 {
		return nil, fmt.Errorf("invalid commit request")
	}
	records := make([]*stageRecord, 0, len(items))
	var unlocks []func()
	defer func() {
		for _, unlock := range unlocks {
			unlock()
		}
	}()
	loadedStages := map[string]*stageRecord{}
	seenAliases := map[string]string{}
	for _, item := range items {
		if !uuidPattern.MatchString(item.AssetID) {
			return nil, fmt.Errorf("invalid commit item")
		}
		record := loadedStages[item.StageID]
		if record == nil {
			loaded, unlock, err := s.readStageLocked(item.StageID, userID)
			if err != nil {
				return nil, err
			}
			unlocks = append(unlocks, unlock)
			record = loaded
			loadedStages[item.StageID] = record
		}
		if sha, ok := seenAliases[item.AssetID]; ok && sha != record.SHA256 {
			return nil, ErrAliasConflict
		}
		seenAliases[item.AssetID] = record.SHA256
		if alias, err := s.readAliasLocked(item.AssetID); err == nil && (alias.SHA256 != record.SHA256 || alias.RelativePath != s.casRelative(record)) {
			return nil, ErrAliasConflict
		}
		info, err := os.Stat(s.stagePathLocked(record))
		if err != nil {
			return nil, ErrStageNotFound
		}
		if !info.Mode().IsRegular() || info.Size() != record.SizeBytes {
			return nil, fmt.Errorf("staged media integrity check failed")
		}
		records = append(records, record)
	}
	result := make([]StagedAsset, 0, len(items))
	for i, record := range records {
		relative := s.casRelative(record)
		final := filepath.Join(s.rootDir, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(final), 0750); err != nil {
			return nil, err
		}
		if _, err := os.Stat(final); errors.Is(err, os.ErrNotExist) {
			if err := os.Rename(filepath.Join(s.stageDir(record.StageID), "payload"+record.Extension), final); err != nil {
				return nil, fmt.Errorf("promote staged media (same filesystem required): %w", err)
			}
			if err := syncDirectory(filepath.Dir(final)); err != nil {
				return nil, err
			}
			if err := syncDirectory(s.stageDir(record.StageID)); err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		}
		record.RelativePath, record.AssetID, record.Committed = relative, items[i].AssetID, true
		aliasData, _ := json.Marshal(record.StagedAsset)
		if err := atomicWrite(s.aliasPath(record.AssetID), aliasData); err != nil {
			return nil, err
		}
		metadata, _ := json.Marshal(record)
		if err := atomicWrite(filepath.Join(s.stageDir(record.StageID), "metadata.json"), metadata); err != nil {
			return nil, err
		}
		_ = os.Remove(filepath.Join(s.stageDir(record.StageID), "payload"+record.Extension))
		result = append(result, record.StagedAsset)
	}
	return result, nil
}
