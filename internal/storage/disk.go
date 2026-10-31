package storage

import (
	"crypto/rand"
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

// Save writes sanitized media bytes to disk using a random UUIDv4 and 2-level hashed directory.
func (s *DiskStorage) Save(data []byte, ext string, contentType string) (*SavedAsset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Generate UUIDv4
	id, err := generateUUIDv4()
	if err != nil {
		return nil, fmt.Errorf("generate asset id: %w", err)
	}

	// 2. Compute SHA256
	hash := sha256.Sum256(data)
	hashHex := hex.EncodeToString(hash[:])

	// 3. Sharded directory structure: e.g. root/ab/cd/<uuid>.ext
	prefix1 := id[0:2]
	prefix2 := id[2:4]
	filename := id + ext
	dirPath := filepath.Join(s.rootDir, prefix1, prefix2)

	if err := os.MkdirAll(dirPath, 0750); err != nil {
		return nil, fmt.Errorf("create shard directory: %w", err)
	}

	fullPath := filepath.Join(dirPath, filename)
	// Write file with strict 0640 permissions
	if err := os.WriteFile(fullPath, data, 0640); err != nil {
		return nil, fmt.Errorf("write media file: %w", err)
	}

	relPath := filepath.Join(prefix1, prefix2, filename)

	return &SavedAsset{
		ID:           id,
		SHA256:       hashHex,
		SizeBytes:    int64(len(data)),
		ContentType:  contentType,
		Filename:     filename,
		RelativePath: relPath,
	}, nil
}

// FindById locates an asset on disk by ID.
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

func generateUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	// Set UUID version 4 and variant
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
