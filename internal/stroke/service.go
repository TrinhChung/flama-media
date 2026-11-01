package stroke

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Options configures the stroke worker on worker212. Generated SVGs are kept in
// StorageRoot on worker212; the OV gateway runs nginx only and copies a file
// from GET /store/stroke_*.svg the first time it misses (proxy_store).
type Options struct {
	Role           string
	InternalSecret string
	DatasetRoot    string
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
	// Placeholder marks a generated box with the character as text, used when
	// no canonical stroke data exists for it.
	Placeholder bool `json:"placeholder,omitempty"`
}

type service struct {
	opts     Options
	upstream *http.Client
	mu       sync.Mutex
	slots    chan struct{}
}

// Service is the registered stroke worker; nil when strokes are disabled.
type Service struct{ s *service }

// Register mounts POST /internal/strokes/generate (internal secret) and returns
// the worker so the caller can route GET /store/stroke_*.svg to it.
func Register(mux *http.ServeMux, opts Options) (*Service, error) {
	role := strings.ToLower(strings.TrimSpace(opts.Role))
	if role == "" || role == "disabled" {
		return nil, nil
	}
	if role != "worker" {
		return nil, errors.New("STROKE_ROLE must be worker or disabled (OV runs nginx only)")
	}
	if strings.TrimSpace(opts.InternalSecret) == "" {
		return nil, errors.New("stroke internal secret is required")
	}
	if opts.StorageRoot == "" {
		return nil, errors.New("stroke worker requires STROKE_STORAGE_ROOT")
	}
	root, err := filepath.Abs(opts.StorageRoot)
	if err != nil {
		return nil, err
	}
	opts.StorageRoot = root
	if err := os.MkdirAll(root, 0750); err != nil {
		return nil, err
	}
	s := &service{opts: opts, upstream: &http.Client{Timeout: 5 * time.Second, CheckRedirect: canonicalRedirect}, slots: make(chan struct{}, 8)}
	mux.HandleFunc("POST /internal/strokes/generate", s.authorized(s.generate))
	return &Service{s: s}, nil
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

func (s *service) generateOne(ctx context.Context, ch, locale string) Item {
	return s.generateOneForce(ctx, ch, locale, false)
}

func strokeKey(c rune, locale string) (key, hexCode string) {
	hexCode = fmt.Sprintf("%x", c)
	return "stroke_" + strings.ReplaceAll(locale, "-", "_") + "_" + hexCode, hexCode
}

func (s *service) generateOneForce(ctx context.Context, ch, locale string, force bool) Item {
	c, _ := utf8.DecodeRuneInString(ch)
	key, h := strokeKey(c, locale)
	item := Item{Char: ch, Hex: h, ImageKey: key, URL: "/store/" + key + ".svg"}
	if !force {
		if sum, size, ok := s.statLocal(key); ok {
			item.Available, item.Cached, item.SHA256, item.SizeBytes = true, true, sum, size
			return item
		}
	}
	data, placeholder, errCode := s.build(ctx, c, locale)
	if errCode != "" {
		item.Error = errCode
		return item
	}
	item.Placeholder = placeholder
	if err := s.writeLocal(key, data); err != nil {
		item.Error = "STROKE_STORE_UNAVAILABLE"
		return item
	}
	sum := sha256.Sum256(data)
	item.Available = true
	item.SHA256 = hex.EncodeToString(sum[:])
	item.SizeBytes = int64(len(data))
	return item
}

// build returns the normalized canonical SVG, or the placeholder when every
// source answered that the character does not exist. Network errors are not
// turned into placeholders, so a later request can still get the real data.
func (s *service) build(ctx context.Context, c rune, locale string) ([]byte, bool, string) {
	raw, err := s.source(ctx, c, locale)
	if errors.Is(err, errSourceNotFound) {
		return Placeholder(c, locale), true, ""
	}
	if err != nil {
		return nil, false, "STROKE_SOURCE_UNAVAILABLE"
	}
	data, err := Normalize(raw, fmt.Sprintf("%x", c))
	if err != nil {
		return nil, false, "STROKE_SOURCE_INVALID"
	}
	return data, false, ""
}

func (s *service) localPath(key string) string {
	return filepath.Join(s.opts.StorageRoot, key+".svg")
}

func (s *service) statLocal(key string) (string, int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Open(s.localPath(key))
	if err != nil {
		return "", 0, false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > maxSVGBytes {
		return "", 0, false
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxSVGBytes+1))
	if err != nil {
		return "", 0, false
	}
	return hex.EncodeToString(h.Sum(nil)), n, true
}

// writeLocal stores an SVG atomically (temp file, fsync, rename).
func (s *service) writeLocal(key string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.CreateTemp(s.opts.StorageRoot, ".stroke-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0644); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp, s.localPath(key))
	}
	return err
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
	notFound := 0
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
		if resp.StatusCode == http.StatusNotFound {
			notFound++
		}
	}
	if notFound == len(urls) {
		return nil, errSourceNotFound
	}
	return nil, errors.New("canonical stroke data unavailable")
}

var errSourceNotFound = errors.New("no canonical stroke data for this character")

// Placeholder mirrors app/services/strokes/dataset_builder.generate_kanji_placeholder_svg:
// a dashed practice box with the character drawn as text.
func Placeholder(c rune, locale string) []byte {
	fonts := "'Noto Sans CJK JP', 'Hiragino Sans', 'Yu Gothic', 'Meiryo', sans-serif"
	switch locale {
	case "zh-hant":
		fonts = "'PingFang TC', 'Microsoft JhengHei', 'Noto Sans TC', sans-serif"
	case "zh":
		fonts = "'PingFang SC', 'Microsoft YaHei', 'SimHei', 'Noto Sans SC', sans-serif"
	}
	ch := html.EscapeString(string(c))
	return []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 109 109" width="100%" height="100%" preserveAspectRatio="xMidYMid meet" class="flama-stroke-char" data-char="` + ch + `" data-hex="` + fmt.Sprintf("%x", c) + `">` +
		`<rect width="107" height="107" x="1" y="1" fill="none" stroke="#e2e8f0" stroke-width="1.5" stroke-dasharray="3 3" rx="8" />` +
		`<line x1="54.5" y1="1" x2="54.5" y2="108" stroke="#f1f5f9" stroke-width="1" stroke-dasharray="2 2" />` +
		`<line x1="1" y1="54.5" x2="108" y2="54.5" stroke="#f1f5f9" stroke-width="1" stroke-dasharray="2 2" />` +
		`<text x="54.5" y="78" font-family="` + fonts + `" font-size="64" text-anchor="middle" fill="#1e293b" font-weight="500">` + ch + `</text>` +
		`</svg>`)
}

var filenameRE = regexp.MustCompile(`^stroke_(ja|zh|zh_hant)_([a-f0-9]{4,6})\.svg$`)

func parseFilename(name string) (key, locale string, c rune, ok bool) {
	m := filenameRE.FindStringSubmatch(name)
	if len(m) != 3 {
		return "", "", 0, false
	}
	cp, err := strconv.ParseInt(m[2], 16, 32)
	if err != nil || !validCJK(rune(cp)) || fmt.Sprintf("%x", cp) != m[2] {
		return "", "", 0, false
	}
	return strings.TrimSuffix(name, ".svg"), strings.ReplaceAll(m[1], "_", "-"), rune(cp), true
}

// WrapStore serves GET/HEAD /store/stroke_<locale>_<hex>.svg from StorageRoot,
// generating a missing file first, and passes every other path to next.
func (svc *Service) WrapStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, isStore := strings.CutPrefix(r.URL.Path, "/store/")
		if !isStore || !strings.HasPrefix(name, "stroke_") {
			next.ServeHTTP(w, r)
			return
		}
		svc.s.serve(w, r, name)
	})
}

func (s *service) serve(w http.ResponseWriter, r *http.Request, name string) {
	key, locale, c, ok := parseFilename(name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if _, _, exists := s.statLocal(key); !exists {
		select {
		case s.slots <- struct{}{}:
		case <-r.Context().Done():
			http.Error(w, "request cancelled", http.StatusRequestTimeout)
			return
		}
		data, _, errCode := s.build(r.Context(), c, locale)
		<-s.slots
		if errCode != "" || s.writeLocal(key, data) != nil {
			http.NotFound(w, r)
			return
		}
	}
	f, err := os.Open(s.localPath(key))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	http.ServeContent(w, r, name, info.ModTime(), f)
}
