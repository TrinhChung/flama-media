package stroke

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Options deliberately separates media storage on212 from the stroke-only
// receiver onOV. Neither process mounts the other machine's data directory.
type Options struct {
	Role           string
	InternalSecret string
	DatasetRoot    string
	StoreURL       string
	StoreSecret    string
	StorageRoot    string
}

type Item struct {
	Char      string `json:"char"`
	Hex       string `json:"hex"`
	ImageKey  string `json:"image_key"`
	URL       string `json:"url"`
	Available bool   `json:"available"`
	SHA256    string `json:"sha256,omitempty"`
	SizeBytes int64  `json:"size_bytes,omitempty"`
	Error     string `json:"error,omitempty"`
	Cached    bool   `json:"cached,omitempty"`
}

type service struct {
	opts     Options
	client   *http.Client
	upstream *http.Client
	mu       sync.Mutex
	slots    chan struct{}
}

// Register mounts authenticated internal APIs only. Public /store/stroke_*.svg
// remains served by OV Nginx from StorageRoot.
func Register(mux *http.ServeMux, opts Options) error {
	role := strings.ToLower(strings.TrimSpace(opts.Role))
	if role == "" || role == "disabled" {
		return nil
	}
	if role != "worker" && role != "receiver" {
		return errors.New("STROKE_ROLE must be worker, receiver or disabled")
	}
	if strings.TrimSpace(opts.InternalSecret) == "" {
		return errors.New("stroke internal secret is required")
	}
	if role == "worker" {
		u, err := url.Parse(opts.StoreURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || opts.StoreSecret == "" {
			return errors.New("stroke worker requires STROKE_STORE_URL and STROKE_STORE_SECRET")
		}
	} else {
		if opts.StorageRoot == "" {
			return errors.New("stroke receiver requires STROKE_STORAGE_ROOT")
		}
		root, err := filepath.Abs(opts.StorageRoot)
		if err != nil {
			return err
		}
		opts.StorageRoot = root
		if err := os.MkdirAll(root, 0750); err != nil {
			return err
		}
	}
	s := &service{opts: opts, client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, upstream: &http.Client{Timeout: 5 * time.Second, CheckRedirect: canonicalRedirect}, slots: make(chan struct{}, 8)}
	if role == "worker" {
		mux.HandleFunc("POST /internal/strokes/generate", s.authorized(s.generate))
	} else {
		mux.HandleFunc("PUT /internal/strokes/{filename}", s.authorized(s.receive))
		mux.HandleFunc("HEAD /internal/strokes/{filename}", s.authorized(s.stat))
	}
	return nil
}

func canonicalRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > 3 || req.URL.Scheme != "https" || (req.URL.Host != "raw.githubusercontent.com" && req.URL.Host != "cdn.jsdelivr.net") {
		return errors.New("canonical dataset redirect rejected")
	}
	return nil
}

func (s *service) authorized(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Internal-Secret")), []byte(s.opts.InternalSecret)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func validCJK(c rune) bool {
	for _, v := range [][2]rune{{0x4e00, 0x9fff}, {0x3400, 0x4dbf}, {0x20000, 0x2a6df}, {0x2a700, 0x2b73f}, {0x2b740, 0x2b81f}, {0x2b820, 0x2ceaf}, {0x2ceb0, 0x2ebef}, {0x30000, 0x3134f}, {0xf900, 0xfaff}, {0x2f800, 0x2fa1f}} {
		if c >= v[0] && c <= v[1] {
			return true
		}
	}
	return false
}

func normalizeLocale(v string) (string, bool) {
	switch strings.ToLower(strings.ReplaceAll(v, "_", "-")) {
	case "ja", "ja-jp", "jp":
		return "ja", true
	case "zh", "zh-hans", "zh-cn":
		return "zh", true
	case "zh-hant", "zh-tw", "zh-hk":
		return "zh-hant", true
	}
	return "", false
}

func (s *service) generate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var body struct {
		Characters []string `json:"characters"`
		Locale     string   `json:"locale"`
		Force      bool     `json:"force"`
	}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&body); err != nil {
		http.Error(w, "invalid stroke request", 400)
		return
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "invalid stroke request", 400)
		return
	}
	locale, ok := normalizeLocale(body.Locale)
	if !ok || len(body.Characters) > 100 {
		http.Error(w, "invalid locale or too many characters", 400)
		return
	}
	for _, ch := range body.Characters {
		c, n := utf8.DecodeRuneInString(ch)
		if n != len(ch) || !validCJK(c) {
			http.Error(w, "only CJK characters are supported", 400)
			return
		}
	}
	items := make([]Item, len(body.Characters))
	var wg sync.WaitGroup
	for i, ch := range body.Characters {
		select {
		case s.slots <- struct{}{}:
		case <-r.Context().Done():
			http.Error(w, "request cancelled", 408)
			return
		}
		wg.Add(1)
		go func(i int, ch string) {
			defer wg.Done()
			defer func() { <-s.slots }()
			items[i] = s.generateOneForce(r.Context(), ch, locale, body.Force)
		}(i, ch)
	}
	wg.Wait()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
}

func (s *service) storeRequest(ctx context.Context, method, key string, data []byte) (*http.Response, error) {
	endpoint := strings.TrimRight(s.opts.StoreURL, "/") + "/" + key + ".svg"
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Internal-Secret", s.opts.StoreSecret)
	req.Header.Set("Content-Type", "image/svg+xml")
	return s.client.Do(req)
}

func (s *service) generateOne(ctx context.Context, ch, locale string) Item {
	return s.generateOneForce(ctx, ch, locale, false)
}

func (s *service) generateOneForce(ctx context.Context, ch, locale string, force bool) Item {
	c, _ := utf8.DecodeRuneInString(ch)
	h := fmt.Sprintf("%x", c)
	key := "stroke_" + strings.ReplaceAll(locale, "-", "_") + "_" + h
	item := Item{Char: ch, Hex: h, ImageKey: key, URL: "/store/" + key + ".svg"}
	if !force {
		resp, err := s.storeRequest(ctx, http.MethodHead, key, nil)
		if err != nil {
			item.Error = "STROKE_STORE_UNAVAILABLE"
			return item
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			sum := resp.Header.Get("X-Content-SHA256")
			size, _ := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
			if len(sum) == 64 && size > 0 {
				item.Available = true
				item.Cached = true
				item.SHA256 = sum
				item.SizeBytes = size
				return item
			}
			item.Error = "STROKE_STORE_INVALID_RESPONSE"
			return item
		}
		if resp.StatusCode != http.StatusNotFound {
			item.Error = "STROKE_STORE_UNAVAILABLE"
			return item
		}
	}
	raw, err := s.source(ctx, c, locale)
	if err != nil {
		item.Error = "STROKE_SOURCE_UNAVAILABLE"
		return item
	}
	data, err := Normalize(raw, h)
	if err != nil {
		item.Error = "STROKE_SOURCE_INVALID"
		return item
	}
	resp, err := s.storeRequest(ctx, http.MethodPut, key, data)
	if err != nil {
		item.Error = "STROKE_STORE_UNAVAILABLE"
		return item
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		item.Error = "STROKE_STORE_UNAVAILABLE"
		return item
	}
	sum := sha256.Sum256(data)
	item.Available = true
	item.SHA256 = hex.EncodeToString(sum[:])
	item.SizeBytes = int64(len(data))
	return item
}

func (s *service) source(ctx context.Context, c rune, locale string) ([]byte, error) {
	h := fmt.Sprintf("%x", c)
	padded := fmt.Sprintf("%05x", c)
	if s.opts.DatasetRoot != "" {
		// A provisioned dataset is read only; generated files are sent to OV.
		for _, name := range []string{h, padded} {
			p := filepath.Join(s.opts.DatasetRoot, locale, name+".svg")
			f, err := os.Open(p)
			if err == nil {
				data, readErr := io.ReadAll(io.LimitReader(f, maxSVGBytes+1))
				_ = f.Close()
				if readErr == nil && len(data) <= maxSVGBytes {
					return data, nil
				}
			}
		}
	}
	kvg := "https://raw.githubusercontent.com/KanjiVG/kanjivg/master/kanji/" + padded + ".svg"
	mmah := "https://raw.githubusercontent.com/skishore/makemeahanzi/master/svgs/" + strconv.FormatInt(int64(c), 10) + ".svg"
	urls := []string{kvg, mmah}
	if locale != "ja" {
		urls = []string{mmah, kvg}
	}
	for _, u := range urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Flama-Strokes/1.0")
		resp, err := s.upstream.Do(req)
		if err != nil {
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxSVGBytes+1))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK && readErr == nil && len(data) <= maxSVGBytes {
			return data, nil
		}
	}
	return nil, errors.New("canonical stroke data unavailable")
}

var filenameRE = regexp.MustCompile(`^stroke_(ja|zh|zh_hant)_([a-f0-9]{4,6})\.svg$`)

func (s *service) path(r *http.Request) (string, bool) {
	name := r.PathValue("filename")
	m := filenameRE.FindStringSubmatch(name)
	if len(m) != 3 {
		return "", false
	}
	cp, err := strconv.ParseInt(m[2], 16, 32)
	if err != nil || !validCJK(rune(cp)) || fmt.Sprintf("%x", cp) != m[2] {
		return "", false
	}
	return filepath.Join(s.opts.StorageRoot, name), true
}

func (s *service) stat(w http.ResponseWriter, r *http.Request) {
	p, ok := s.path(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Open(p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxSVGBytes {
		http.NotFound(w, r)
		return
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxSVGBytes+1))
	if err != nil {
		http.Error(w, "stroke read failed", 500)
		return
	}
	w.Header().Set("X-Content-SHA256", hex.EncodeToString(h.Sum(nil)))
	w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
	w.WriteHeader(http.StatusOK)
}

func (s *service) receive(w http.ResponseWriter, r *http.Request) {
	p, ok := s.path(r)
	if !ok {
		http.Error(w, "invalid stroke filename", 400)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSVGBytes)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "stroke exceeds limit", 413)
		return
	}
	root, err := parseSVG(data)
	if err != nil || root.get("class") == "" || !strings.Contains(root.get("class"), "flama-stroke-char") {
		http.Error(w, "invalid generated stroke SVG", 400)
		return
	}
	// Re-serialize the parsed allowlisted tree, never the original wire bytes.
	// This also removes unknown attributes and namespace metadata at the receiver.
	var clean bytes.Buffer
	encoder := xml.NewEncoder(&clean)
	if err := writeNode(encoder, root); err != nil {
		http.Error(w, "invalid stroke SVG", 400)
		return
	}
	if err := encoder.Flush(); err != nil {
		http.Error(w, "invalid stroke SVG", 400)
		return
	}
	data = clean.Bytes()
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.CreateTemp(s.opts.StorageRoot, ".stroke-*")
	if err != nil {
		http.Error(w, "stroke storage unavailable", 500)
		return
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0640); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp, p)
	}
	if err != nil {
		http.Error(w, "stroke storage failed", 500)
		return
	}
	sum := sha256.Sum256(data)
	w.Header().Set("X-Content-SHA256", hex.EncodeToString(sum[:]))
	w.Header().Set("X-Content-Size", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusCreated)
}
