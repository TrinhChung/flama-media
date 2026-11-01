package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/TrinhChung/flama-media/internal/auth"
	"github.com/TrinhChung/flama-media/internal/config"
	"github.com/TrinhChung/flama-media/internal/storage"
)

func testMediaConfig() *config.Config {
	return &config.Config{SharedSecret: "test-upload-secret", InternalSecret: "test-internal-secret", MaxUploadBytes: 10 << 20, MaxImageDimension: 4096, MaxImagePixels: 16000000, ResizeDimension: 1600, StageTTLSeconds: 86400}
}

func TestUploadTicketScopeIsEnforcedForSingleAndZIP(t *testing.T) {
	cfg := testMediaConfig()
	store, _ := storage.NewDiskStorage(t.TempDir())
	for _, ticket := range []auth.UploadTicket{{UserID: 42, MaxBytes: 1024, Exp: time.Now().Add(time.Hour).Unix(), Action: "fetch_url"}, {UserID: 0, MaxBytes: 1024, Exp: time.Now().Add(time.Hour).Unix(), Action: "upload"}, {UserID: 42, MaxBytes: 0, Exp: time.Now().Add(time.Hour).Unix(), Action: "upload"}} {
		for _, handler := range []http.Handler{NewUploadHandler(cfg, store, nil), NewUploadZipHandler(cfg, store, nil)} {
			req := httptest.NewRequest(http.MethodPost, "/media/upload", nil)
			req.Header.Set("Authorization", "Bearer "+createTicketToken(cfg.SharedSecret, ticket))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("bad ticket scope accepted: %+v status%d", ticket, w.Code)
			}
		}
	}
}

func TestUploadStagesThenBackendCommitCreatesAlias(t *testing.T) {
	cfg := testMediaConfig()
	store, _ := storage.NewDiskStorage(t.TempDir())
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, _ := writer.CreateFormFile("file", "sound.mp3")
	_, _ = part.Write(append([]byte("ID3"), bytes.Repeat([]byte{0}, 40)...))
	_ = writer.Close()
	req := httptest.NewRequest(http.MethodPost, "/media/upload", &body)
	req.Header.Set("Authorization", "Bearer "+createValidToken(cfg.SharedSecret))
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	NewUploadHandler(cfg, store, nil).ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("upload %d: %s", w.Code, w.Body.String())
	}
	var uploaded UploadResponse
	_ = json.Unmarshal(w.Body.Bytes(), &uploaded)
	if uploaded.StageID == "" || uploaded.URL != "/media/staged/"+uploaded.StageID {
		t.Fatalf("not a stage: %+v", uploaded)
	}
	if _, err := store.FindById(uploaded.AssetID); !os.IsNotExist(err) {
		t.Fatal("upload wrote permanent CAS")
	}
	staging := NewStagingHandler(cfg, store)
	preview := httptest.NewRecorder()
	staging.ServeHTTP(preview, httptest.NewRequest(http.MethodGet, uploaded.URL, nil))
	if preview.Code != 200 || preview.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("preview %d", preview.Code)
	}
	commitBody := []byte(`{"user_id":42,"items":[{"stage_id":"` + uploaded.StageID + `","asset_id":"20a9f4e1-2e5b-45c7-9b38-6c4f27c2e591"}]}`)
	denied := httptest.NewRecorder()
	staging.ServeHTTP(denied, httptest.NewRequest(http.MethodPost, "/media/commit", bytes.NewReader(commitBody)))
	if denied.Code != 403 {
		t.Fatal("unauthenticated commit accepted")
	}
	commit := httptest.NewRequest(http.MethodPost, "/media/commit", bytes.NewReader(commitBody))
	commit.Header.Set("X-Internal-Secret", cfg.InternalSecret)
	ack := httptest.NewRecorder()
	staging.ServeHTTP(ack, commit)
	if ack.Code != 200 {
		t.Fatalf("commit %d: %s", ack.Code, ack.Body.String())
	}
	permanent, err := store.FindById("20a9f4e1-2e5b-45c7-9b38-6c4f27c2e591")
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(permanent)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	data, _ := io.ReadAll(file)
	if !bytes.HasPrefix(data, []byte("ID3")) {
		t.Fatal("media changed")
	}
}

func TestInternalInspectDoesNotAcceptTrailingJSON(t *testing.T) {
	cfg := testMediaConfig()
	store, _ := storage.NewDiskStorage(t.TempDir())
	h := NewStagingHandler(cfg, store)
	r := httptest.NewRequest(http.MethodPost, "/media/staged/inspect", bytes.NewBufferString(`{"user_id":42,"stage_ids":[]} {}`))
	r.Header.Set("X-Internal-Secret", cfg.InternalSecret)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("trailing JSON status=%d", w.Code)
	}
}

func TestPermanentInspectionAndAliasHead(t *testing.T) {
	cfg := testMediaConfig()
	store, _ := storage.NewDiskStorage(t.TempDir())
	asset, err := store.Stage([]byte("ID3safe audio bytes"), ".mp3", "audio/mpeg", "audio.mp3", 42, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	const id = "20a9f4e1-2e5b-45c7-9b38-6c4f27c2e591"
	if _, err := store.CommitStages(42, []storage.CommitItem{{StageID: asset.StageID, AssetID: id}}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/media/assets/inspect", bytes.NewBufferString(`{"asset_ids":["`+id+`","20a9f4e1-2e5b-45c7-9b38-6c4f27c2e592"]}`))
	r.Header.Set("X-Internal-Secret", cfg.InternalSecret)
	w := httptest.NewRecorder()
	NewStagingHandler(cfg, store).ServeHTTP(w, r)
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"exists":true`)) || !bytes.Contains(w.Body.Bytes(), []byte(`"exists":false`)) {
		t.Fatalf("inspect=%d: %s", w.Code, w.Body.String())
	}
	for _, path := range []string{"/store/" + id, "/store/" + id + ".mp3"} {
		head := httptest.NewRecorder()
		NewServeHandler(cfg, store).ServeHTTP(head, httptest.NewRequest(http.MethodHead, path, nil))
		if head.Code != 200 || head.Body.Len() != 0 || head.Header().Get("Content-Type") != "audio/mpeg" {
			t.Fatalf("HEAD %s=%d", path, head.Code)
		}
	}
}
