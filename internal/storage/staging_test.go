package storage

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const aliasOne = "20a9f4e1-2e5b-45c7-9b38-6c4f27c2e591"
const aliasTwo = "20a9f4e1-2e5b-45c7-9b38-6c4f27c2e592"

func newStagedTestAsset(t *testing.T, store *DiskStorage, user int64) *StagedAsset {
	t.Helper()
	asset, err := store.Stage([]byte("same sanitized audio media bytes"), ".mp3", "audio/mpeg", "sample.mp3", user, 0, 0, DefaultStageTTL)
	if err != nil {
		t.Fatal(err)
	}
	return asset
}

func TestStagingCommitUsesRenameAndSurvivesRestart(t *testing.T) {
	root := t.TempDir()
	store, err := NewDiskStorage(root)
	if err != nil {
		t.Fatal(err)
	}
	stage := newStagedTestAsset(t, store, 7)
	before, err := os.Stat(filepath.Join(store.stageDir(stage.StageID), "payload.mp3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.FindById(stage.SHA256); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("uncommitted content visible via permanent ID: %v", err)
	}
	restarted, _ := NewDiskStorage(root)
	inspected, err := restarted.InspectStages(7, []string{stage.StageID})
	if err != nil || len(inspected) != 1 || inspected[0].RelativePath == "" {
		t.Fatalf("inspect: %+v %v", inspected, err)
	}
	items := []CommitItem{{StageID: stage.StageID, AssetID: aliasOne}}
	committed, err := restarted.CommitStages(7, items)
	if err != nil {
		t.Fatal(err)
	}
	path, err := restarted.FindById(aliasOne)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("commit copied bytes instead of renaming the inode")
	}
	if committed[0].AssetID != aliasOne || committed[0].SHA256 != stage.SHA256 {
		t.Fatalf("bad receipt: %+v", committed)
	}
	link := filepath.Join(root, aliasOne[0:2], aliasOne[2:4], aliasOne+".mp3")
	if target, err := os.Readlink(link); err != nil || filepath.ToSlash(target) != "../../"+committed[0].RelativePath {
		t.Fatalf("id symlink: %q %v", target, err)
	}
	if linked, err := os.Stat(link); err != nil || !os.SameFile(linked, after) {
		t.Fatalf("id symlink does not reach the CAS file: %v", err)
	}
	if _, err := restarted.CommitStages(7, items); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.stageDir(stage.StageID), "payload.mp3")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stage payload remained after commit")
	}
	file, err := restarted.OpenStage(stage.StageID)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
}

func TestStagingOwnerValidationAndWholeBatchPreflight(t *testing.T) {
	store, _ := NewDiskStorage(t.TempDir())
	first := newStagedTestAsset(t, store, 7)
	second := newStagedTestAsset(t, store, 8)
	if _, err := store.InspectStages(8, []string{first.StageID}); !errors.Is(err, ErrStageOwnership) {
		t.Fatalf("cross-user inspect: %v", err)
	}
	_, err := store.CommitStages(7, []CommitItem{{first.StageID, aliasOne}, {second.StageID, aliasTwo}})
	if !errors.Is(err, ErrStageOwnership) {
		t.Fatalf("cross-user commit: %v", err)
	}
	if _, err := store.FindById(aliasOne); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid batch partially committed")
	}
	if _, err := store.InspectStages(7, []string{"../../outside"}); !errors.Is(err, ErrStageNotFound) {
		t.Fatal("path traversal accepted")
	}
}

func TestStagingDeduplicationDoesNotShareOwnersOrAliases(t *testing.T) {
	store, _ := NewDiskStorage(t.TempDir())
	first := newStagedTestAsset(t, store, 7)
	second := newStagedTestAsset(t, store, 8)
	if first.StageID == second.StageID || first.SHA256 != second.SHA256 {
		t.Fatal("bad lease isolation")
	}
	if _, err := store.CommitStages(7, []CommitItem{{first.StageID, aliasOne}, {first.StageID, aliasTwo}}); err != nil {
		t.Fatal(err)
	}
	path1, _ := store.FindById(aliasOne)
	path2, _ := store.FindById(aliasTwo)
	if path1 != path2 {
		t.Fatal("same upload was not deduplicated")
	}
	if _, err := store.CommitStages(8, []CommitItem{{second.StageID, aliasOne}}); err != nil {
		t.Fatalf("same hash new upload should preserve alias: %v", err)
	}
	other, err := store.Stage([]byte("different sanitized audio"), ".mp3", "audio/mpeg", "other.mp3", 8, 0, 0, DefaultStageTTL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitStages(8, []CommitItem{{other.StageID, aliasOne}}); !errors.Is(err, ErrAliasConflict) {
		t.Fatalf("alias content change accepted: %v", err)
	}
}

func TestRepeatedUploadCanReuseSameNoteFieldAlias(t *testing.T) {
	store, _ := NewDiskStorage(t.TempDir())
	a := newStagedTestAsset(t, store, 7)
	b := newStagedTestAsset(t, store, 7)
	if _, err := store.CommitStages(7, []CommitItem{{a.StageID, aliasOne}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitStages(7, []CommitItem{{b.StageID, aliasOne}}); err != nil {
		t.Fatalf("fresh lease same bytes: %v", err)
	}
	c := newStagedTestAsset(t, store, 7)
	d := newStagedTestAsset(t, store, 7)
	if _, err := store.CommitStages(7, []CommitItem{{c.StageID, aliasTwo}, {d.StageID, aliasTwo}}); err != nil {
		t.Fatalf("batch duplicate alias same bytes: %v", err)
	}
}

func TestStageExpiryRejectsWithoutDeletingOSManagedFile(t *testing.T) {
	store, _ := NewDiskStorage(t.TempDir())
	stage := newStagedTestAsset(t, store, 7)
	path := filepath.Join(store.stageDir(stage.StageID), "metadata.json")
	data, _ := os.ReadFile(path)
	var record stageRecord
	_ = json.Unmarshal(data, &record)
	record.ExpiresAt = time.Now().Add(-time.Second).Unix()
	data, _ = json.Marshal(record)
	_ = os.WriteFile(path, data, 0640)
	if _, err := store.InspectStages(7, []string{stage.StageID}); !errors.Is(err, ErrStageNotFound) {
		t.Fatalf("expired inspect: %v", err)
	}
	if _, err := store.CommitStages(7, []CommitItem{{stage.StageID, aliasOne}}); !errors.Is(err, ErrStageNotFound) {
		t.Fatalf("expired commit: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.stageDir(stage.StageID), "payload.mp3")); err != nil {
		t.Fatal("API removed a file owned by OS cleanup")
	}
}

func TestCommitRecoversRenameBeforeAcknowledgement(t *testing.T) {
	store, _ := NewDiskStorage(t.TempDir())
	stage := newStagedTestAsset(t, store, 7)
	final := filepath.Join(store.rootDir, filepath.FromSlash(stage.RelativePath))
	_ = os.MkdirAll(filepath.Dir(final), 0750)
	if err := os.Rename(filepath.Join(store.stageDir(stage.StageID), "payload.mp3"), final); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitStages(7, []CommitItem{{stage.StageID, aliasOne}}); err != nil {
		t.Fatalf("crash recovery: %v", err)
	}
}
