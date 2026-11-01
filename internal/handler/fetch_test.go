package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TrinhChung/flama-media/internal/auth"
)

func TestFetchRequiresFetchTicketAndRejectsPrivateTargets(t *testing.T) {
	cfg := testMediaConfig()
	h := NewFetchHandler(cfg)
	post := func(ticket auth.UploadTicket, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/media/fetch-url", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+createTicketToken(cfg.SharedSecret, ticket))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	exp := time.Now().Add(time.Minute).Unix()
	if w := post(auth.UploadTicket{UserID: 1, MaxBytes: 1024, Exp: exp, Action: "upload"}, `{"url":"https://example.com/a.png"}`); w.Code != http.StatusForbidden {
		t.Fatalf("upload ticket accepted for fetch: %d", w.Code)
	}
	fetchTicket := auth.UploadTicket{MaxBytes: 1024, Exp: exp, Action: "fetch_url"}
	if w := post(fetchTicket, `{"url":"https://example.com/a.png","extra":1}`); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown field accepted: %d", w.Code)
	}
	w := post(fetchTicket, `{"url":"http://127.0.0.1/a.png"}`)
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if w.Code != http.StatusBadRequest || resp["error"] != "URL_NOT_ALLOWED" {
		t.Fatalf("loopback fetch: %d %v", w.Code, resp)
	}
}
