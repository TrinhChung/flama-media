package handler

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TrinhChung/flama-media/internal/auth"
	"github.com/TrinhChung/flama-media/internal/config"
	"github.com/TrinhChung/flama-media/internal/fetcher"
)

// FetchHandler downloads a public URL for the backend (image crawl, page
// scraping) so outbound requests never leave from the app server. It is only
// reachable over the private network: the gateway middleware requires the
// gateway secret and OV nginx does not route this path.
type FetchHandler struct {
	cfg     *config.Config
	fetcher *fetcher.Fetcher
}

func NewFetchHandler(cfg *config.Config) *FetchHandler {
	return &FetchHandler{cfg: cfg, fetcher: fetcher.New()}
}

const maxHTMLBytes = 1 << 20

func (h *FetchHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	ticket, err := auth.VerifyToken(token, h.cfg.SharedSecret)
	if err != nil {
		writeJSONError(w, http.StatusForbidden, "INVALID_TOKEN", "A valid fetch ticket is required")
		return
	}
	if ticket.Action != "fetch_url" || ticket.MaxBytes <= 0 {
		writeJSONError(w, http.StatusForbidden, "INVALID_TICKET_SCOPE", "A fetch_url ticket is required")
		return
	}
	var body struct {
		URL            string  `json:"url"`
		Kind           string  `json:"kind"`
		TimeoutSeconds float64 `json:"timeout_seconds"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil || decoder.Decode(new(any)) != io.EOF {
		writeJSONError(w, http.StatusBadRequest, "INVALID_JSON", "A single valid JSON object is required")
		return
	}
	kind := fetcher.Kind(body.Kind)
	if kind == "" {
		kind = fetcher.KindImage
	}
	if kind != fetcher.KindImage && kind != fetcher.KindHTML {
		writeJSONError(w, http.StatusBadRequest, "INVALID_KIND", "kind must be image or html")
		return
	}
	maxBytes := min64(ticket.MaxBytes, h.cfg.MaxUploadBytes)
	if kind == fetcher.KindHTML {
		maxBytes = min64(maxBytes, maxHTMLBytes)
	}
	timeout := time.Duration(body.TimeoutSeconds * float64(time.Second))
	if timeout <= 0 || timeout > 20*time.Second {
		timeout = 20 * time.Second
	}

	res, err := h.fetcher.Fetch(r.Context(), body.URL, kind, maxBytes, timeout)
	host := ""
	if u, perr := url.Parse(body.URL); perr == nil {
		host = u.Hostname()
	}
	if err != nil {
		log.Printf("[FETCH] user=%d kind=%s host=%s rejected: %v", ticket.UserID, kind, host, err)
		switch {
		case errors.Is(err, fetcher.ErrURLNotAllowed):
			writeJSONError(w, http.StatusBadRequest, "URL_NOT_ALLOWED", err.Error())
		case errors.Is(err, fetcher.ErrTooLarge):
			writeJSONError(w, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "Remote file exceeds the allowed size")
		case errors.Is(err, fetcher.ErrTypeNotAllowed):
			writeJSONError(w, http.StatusUnsupportedMediaType, "MEDIA_TYPE_NOT_ALLOWED", err.Error())
		default:
			writeJSONError(w, http.StatusBadGateway, "FETCH_FAILED", err.Error())
		}
		return
	}
	log.Printf("[FETCH] user=%d kind=%s host=%s ok bytes=%d", ticket.UserID, kind, host, len(res.Data))
	w.Header().Set("Content-Type", res.ContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Flama-Final-Url", res.FinalURL)
	w.Header().Set("X-Flama-Filename", res.Filename)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(res.Data)
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
