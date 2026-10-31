package storage

import (
	"os"
	"testing"
)

func TestDiskStorage_Deduplication(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "flama-media-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store, err := NewDiskStorage(tempDir)
	if err != nil {
		t.Fatalf("new disk storage: %v", err)
	}

	content := []byte("sample-audio-bytes-1234567890")

	// 1. First save: must NOT be deduplicated (new write)
	asset1, err := store.Save(content, ".mp3", "audio/mpeg")
	if err != nil {
		t.Fatalf("save 1 error: %v", err)
	}
	if asset1.Deduplicated {
		t.Errorf("expected asset1.Deduplicated to be false, got true")
	}

	// 2. Second save with identical content: MUST be deduplicated (skipped write)
	asset2, err := store.Save(content, ".mp3", "audio/mpeg")
	if err != nil {
		t.Fatalf("save 2 error: %v", err)
	}
	if !asset2.Deduplicated {
		t.Errorf("expected asset2.Deduplicated to be true, got false")
	}
	if asset1.ID != asset2.ID {
		t.Errorf("expected same ID %s, got %s", asset1.ID, asset2.ID)
	}
	if asset1.SHA256 != asset2.SHA256 {
		t.Errorf("expected same SHA256 %s, got %s", asset1.SHA256, asset2.SHA256)
	}

	// 3. FindById
	path, err := store.FindById(asset1.ID)
	if err != nil {
		t.Fatalf("find by id error: %v", err)
	}
	if path == "" {
		t.Errorf("expected path to not be empty")
	}
}
