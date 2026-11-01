package handler

import (
	"archive/zip"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/TrinhChung/flama-media/internal/auth"
	"github.com/TrinhChung/flama-media/internal/config"
	"github.com/TrinhChung/flama-media/internal/reporter"
	"github.com/TrinhChung/flama-media/internal/storage"
)

type mockReporter struct {
	mu        sync.Mutex
	incidents []reporter.SecurityIncident
}

func (m *mockReporter) ReportIncidentAsync(incident reporter.SecurityIncident) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.incidents = append(m.incidents, incident)
}

func (m *mockReporter) Close() {}

func createValidToken(secret string) string {
	ticket := auth.UploadTicket{
		UserID:   42,
		MaxBytes: 10485760,
		Exp:      time.Now().Unix() + 300,
		Action:   "upload",
	}
	return createTicketToken(secret, ticket)
}

func createTicketToken(secret string, ticket auth.UploadTicket) string {
	raw, _ := json.Marshal(ticket)
	b64 := base64.RawURLEncoding.EncodeToString(raw)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(b64))
	sig := hex.EncodeToString(mac.Sum(nil))

	return b64 + "." + sig
}

func TestUploadZipHandler_ZipSlipProtection(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "flama-zip-test-*")
	defer os.RemoveAll(tempDir)

	cfg := &config.Config{
		SharedSecret:   "test-secret",
		MaxUploadBytes: 10 * 1024 * 1024,
	}
	store, _ := storage.NewDiskStorage(tempDir)
	rep := &mockReporter{}
	h := NewUploadZipHandler(cfg, store, rep)

	// Create a zip with a malicious traversal path
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	f, _ := zw.Create("../../evil.sh")
	_, _ = f.Write([]byte("#!/bin/bash\necho hacked"))
	_ = zw.Close()

	req := httptest.NewRequest(http.MethodPost, "/media/upload-zip", &zipBuf)
	req.Header.Set("Content-Type", "application/zip")
	req.Header.Set("Authorization", "Bearer "+createValidToken(cfg.SharedSecret))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK with rejected entry, got %d", w.Code)
	}

	var resp ZipUploadResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.RejectedCount != 1 {
		t.Errorf("expected 1 rejected file for zip slip, got %d", resp.RejectedCount)
	}
	if resp.AcceptedCount != 0 {
		t.Errorf("expected 0 accepted files, got %d", resp.AcceptedCount)
	}

	// Verify incident was reported with user_id 42 and type ZIP_SLIP
	rep.mu.Lock()
	defer rep.mu.Unlock()
	if len(rep.incidents) != 1 {
		t.Fatalf("expected 1 reported incident, got %d", len(rep.incidents))
	}
	if rep.incidents[0].IncidentType != "ZIP_SLIP" {
		t.Errorf("expected incident type ZIP_SLIP, got %s", rep.incidents[0].IncidentType)
	}
	if rep.incidents[0].UserID != 42 {
		t.Errorf("expected incident user_id 42, got %d", rep.incidents[0].UserID)
	}
}

func TestZIPUploadStagesAcceptedMediaAndRejectsBackslashTraversal(t *testing.T) {
	cfg := testMediaConfig()
	store, _ := storage.NewDiskStorage(t.TempDir())
	h := NewUploadZipHandler(cfg, store, nil)
	var body bytes.Buffer
	zw := zip.NewWriter(&body)
	good, _ := zw.Create("audio/sound.mp3")
	_, _ = good.Write(append([]byte("ID3"), bytes.Repeat([]byte{0}, 30)...))
	bad, _ := zw.Create(`..\outside.mp3`)
	_, _ = bad.Write(append([]byte("ID3"), bytes.Repeat([]byte{0}, 30)...))
	_ = zw.Close()
	r := httptest.NewRequest(http.MethodPost, "/media/upload-zip", &body)
	r.Header.Set("Authorization", "Bearer "+createValidToken(cfg.SharedSecret))
	r.Header.Set("Content-Type", "application/zip")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("zip %d: %s", w.Code, w.Body.String())
	}
	var result ZipUploadResponse
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if result.AcceptedCount != 1 || result.RejectedCount != 1 || result.Items[0].StageID == "" {
		t.Fatalf("zip result %+v", result)
	}
	if _, err := store.FindById(result.Items[0].SHA256); !os.IsNotExist(err) {
		t.Fatal("ZIP committed media before note save")
	}
}

func TestZIPPayloadHardLimitAndCompressionBomb(t *testing.T) {
	cfg := testMediaConfig()
	cfg.MaxUploadBytes = 64
	store, _ := storage.NewDiskStorage(t.TempDir())
	h := NewUploadZipHandler(cfg, store, nil)
	r := httptest.NewRequest(http.MethodPost, "/media/upload-zip", bytes.NewReader(bytes.Repeat([]byte{0}, 200)))
	r.Header.Set("Authorization", "Bearer "+createValidToken(cfg.SharedSecret))
	r.Header.Set("Content-Type", "application/zip")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatalf("oversized ZIP status=%d", w.Code)
	}
	cfg.MaxUploadBytes = 10 << 20
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	file, _ := zw.Create("bomb.mp3")
	_, _ = file.Write(bytes.Repeat([]byte{0}, 1<<20))
	_ = zw.Close()
	r = httptest.NewRequest(http.MethodPost, "/media/upload-zip", &buf)
	r.Header.Set("Authorization", "Bearer "+createValidToken(cfg.SharedSecret))
	r.Header.Set("Content-Type", "application/zip")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 400 || !bytes.Contains(w.Body.Bytes(), []byte("ZIP_BOMB_DETECTED")) {
		t.Fatalf("compression bomb status=%d: %s", w.Code, w.Body.String())
	}
}
