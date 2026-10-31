package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type SavedAsset struct {
	ID           string `json:"id"`
	SHA256       string `json:"sha256"`
	SizeBytes    int64  `json:"size_bytes"`
	ContentType  string `json:"content_type"`
	Filename     string `json:"filename"`
	RelativePath string `json:"relative_path"`
	Deduplicated bool   `json:"deduplicated"`
}

type DiskStorage struct {
	rootDir string
	mu      sync.RWMutex
}

func NewDiskStorage(rootDir string) (*DiskStorage, error) {
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, fmt.Errorf("resolve storage root: %w", err)
	}

	if err := os.MkdirAll(absRoot, 0750); err != nil {
		return nil, fmt.Errorf("create storage root: %w", err)
	}

	return &DiskStorage{rootDir: absRoot}, nil
}

// Save writes sanitized media bytes to disk using Content-Addressable Storage (CAS) based on SHA-256.
// If the exact content already exists on disk, writing is skipped (Deduplication) to save disk space and I/O.
func (s *DiskStorage) Save(data []byte, ext string, contentType string) (*SavedAsset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Compute SHA256 of sanitized payload
	hash := sha256.Sum256(data)
	hashHex := hex.EncodeToString(hash[:])
	id := hashHex

	// 2. Sharded directory structure based on SHA256: e.g. root/ab/cd/<sha256>.ext
	prefix1 := id[0:2]
	prefix2 := id[2:4]
	filename := id + ext
	dirPath := filepath.Join(s.rootDir, prefix1, prefix2)
	fullPath := filepath.Join(dirPath, filename)
	relPath := filepath.Join(prefix1, prefix2, filename)

	// 3. Deduplication Check: if file already exists with same hash, return it directly without writing
	if fi, err := os.Stat(fullPath); err == nil && !fi.IsDir() {
		return &SavedAsset{
			ID:           id,
			SHA256:       hashHex,
			SizeBytes:    fi.Size(),
			ContentType:  contentType,
			Filename:     filename,
			RelativePath: relPath,
			Deduplicated: true,
		}, nil
	}

	// 4. Create directory if not exists
	if err := os.MkdirAll(dirPath, 0750); err != nil {
		return nil, fmt.Errorf("create shard directory: %w", err)
	}

	// 5. Write atomically via temp file to avoid partial writes during concurrent requests
	tmpFile, err := os.CreateTemp(dirPath, ".upload-*")
	if err != nil {
		return nil, fmt.Errorf("create temp upload file: %w", err)
	}
	tmpName := tmpFile.Name()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpName)
		return nil, fmt.Errorf("write media file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpName)
		return nil, fmt.Errorf("close temp file: %w", err)
	}

	// Set strict 0640 permissions
	_ = os.Chmod(tmpName, 0640)

	// Atomic rename to final CAS path
	if err := os.Rename(tmpName, fullPath); err != nil {
		_ = os.Remove(tmpName)
		return nil, fmt.Errorf("atomic rename media file: %w", err)
	}

	return &SavedAsset{
		ID:           id,
		SHA256:       hashHex,
		SizeBytes:    int64(len(data)),
		ContentType:  contentType,
		Filename:     filename,
		RelativePath: relPath,
		Deduplicated: false,
	}, nil
}

// FindById locates an asset on disk by ID (either SHA-256 or legacy UUID).
func (s *DiskStorage) FindById(id string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Basic validation to prevent path traversal
	if len(id) < 8 || strings.Contains(id, "..") || strings.Contains(id, "/") || strings.Contains(id, "\\") {
		return "", fmt.Errorf("invalid asset id")
	}

	prefix1 := id[0:2]
	prefix2 := id[2:4]
	shardDir := filepath.Join(s.rootDir, prefix1, prefix2)

	entries, err := os.ReadDir(shardDir)
	if err != nil {
		return "", os.ErrNotExist
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), id) {
			fullPath := filepath.Join(shardDir, entry.Name())
			// Extra check: ensure fullPath is inside rootDir
			rel, err := filepath.Rel(s.rootDir, fullPath)
			if err != nil || strings.HasPrefix(rel, "..") {
				return "", fmt.Errorf("path traversal violation")
			}
			return fullPath, nil
		}
	}

	return "", os.ErrNotExist
}
