package stroke

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const kvgFixture = `<svg xmlns="http://www.w3.org/2000/svg" width="109" height="109" viewBox="0 0 109 109"><g style="fill:none;stroke:#000"><path id="kvg:04e00-s1" d="M11 54 C25 55 75 53 96 54"/></g><g><text transform="matrix(1 0 0 1 5 50)">1</text></g></svg>`
const mmahFixture = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024"><style>@keyframes keyframes0 { from {stroke-dashoffset: 100;} to {stroke-dashoffset: 0;} } #make-me-a-hanzi-animation-0 {animation: keyframes0 1s;}</style><defs><clipPath id="make-me-a-hanzi-clip-0"><path d="M 10 30 L 30 50"/></clipPath></defs><g transform="scale(1,-1) translate(0,-900)"><path id="make-me-a-hanzi-animation-0" clip-path="url(#make-me-a-hanzi-clip-0)" d="M 100 800 L 900 800"/></g></svg>`

func TestNormalizePreservesKanjiVisuals(t *testing.T) {
	data, err := Normalize([]byte(kvgFixture), "4e00")
	if err != nil {
		t.Fatal(err)
	}
	root, err := parseSVG(data)
	if err != nil {
		t.Fatal(err)
	}
	if root.get("viewBox") != "0 0 109 109" || root.get("width") != "100%" {
		t.Fatal("root layout changed")
	}
	var path, text *node
	walk(root, func(n *node) {
		if n.get("id") == "kvg:04e00-s1" {
			path = n
		}
		if n.name == "text" {
			text = n
		}
	})
	if path == nil || path.get("d") != "M11 54 C25 55 75 53 96 54" || !strings.Contains(path.get("style"), "0.45s cubic-bezier(0.4, 0, 0.2, 1) 0.00s") {
		t.Fatal("canonical path or animation changed")
	}
	if text == nil || text.get("transform") != "matrix(1 0 0 1 5 50)" || text.text != "1" {
		t.Fatal("stroke number changed")
	}
	for _, expected := range []string{"flama-kvg-bg-layer", "--flama-stroke-c1: #e11d48", "stroke-dasharray=\"2,2\""} {
		if !bytes.Contains(data, []byte(expected)) {
			t.Fatalf("missing %s", expected)
		}
	}
}

func TestNormalizeMMAHScopesAnimationAndGrid(t *testing.T) {
	data, err := Normalize([]byte(mmahFixture), "4e00")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"mmah-4e00-animation-0", "mmah-4e00-clip-0", "mmah-4e00-kf-0", "flama-grid-box", "flama-mmah-numbers", "viewBox=\"0 0 1024 1024\"", "x=\"82\" y=\"88\""} {
		if !bytes.Contains(data, []byte(expected)) {
			t.Fatalf("missing %s in %s", expected, data)
		}
	}
	if bytes.Contains(data, []byte("make-me-a-hanzi-")) {
		t.Fatal("unscoped IDs")
	}
}

func TestNormalizeRejectsActiveAndMalformedSVG(t *testing.T) {
	for _, raw := range []string{`<svg><script>alert(1)</script></svg>`, `<svg><path style="fill:url(https://example.com/x)"/></svg>`, `<svg><style>@import 'https://example.com/x';</style></svg>`, `<svg>&evil;</svg>`, `<svg>`, `<svg/><svg/>`, `<svg><text>一</text></svg>`} {
		if _, err := Normalize([]byte(raw), "4e00"); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestPreviouslyNormalizedMMAHKeepsChineseGridAndAttribution(t *testing.T) {
	first, err := Normalize([]byte(mmahFixture), "4e00")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Normalize(first, "4e00")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(second, []byte("flama-kvg-bg-layer")) || bytes.Count(second, []byte(`class="flama-grid-box"`)) != 1 || bytes.Count(second, []byte(`id="flama-stroke-attribution"`)) != 1 {
		t.Fatalf("re-normalized MMAH lost Chinese layout: %s", second)
	}
	if !bytes.Contains(second, []byte("Arphic Public License")) {
		t.Fatal("source attribution missing")
	}
}

func newWorker(t *testing.T) (*http.ServeMux, *Service, string, string) {
	t.Helper()
	root, dataset := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(dataset, "ja"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataset, "ja", "4e00.svg"), []byte(kvgFixture), 0640); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	svc, err := Register(mux, Options{Role: "worker", InternalSecret: "backend-secret", DatasetRoot: dataset, StorageRoot: root})
	if err != nil || svc == nil {
		t.Fatalf("register: %v", err)
	}
	return mux, svc, root, dataset
}

func TestWorkerGeneratesOn212AndReusesStoredStroke(t *testing.T) {
	mux, _, root, dataset := newWorker(t)
	call := func(force bool) Item {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"characters": []string{"一"}, "locale": "ja", "force": force})
		req := httptest.NewRequest(http.MethodPost, "/internal/strokes/generate", bytes.NewReader(body))
		req.Header.Set("X-Internal-Secret", "backend-secret")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("status %d %s", w.Code, w.Body.String())
		}
		var result struct {
			Items []Item `json:"items"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result.Items[0]
	}
	first := call(false)
	if !first.Available || first.Cached || first.URL != "/store/stroke_ja_4e00.svg" {
		t.Fatalf("bad receipt %+v", first)
	}
	stored, err := os.ReadFile(filepath.Join(root, "stroke_ja_4e00.svg"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(stored)
	if first.SHA256 != hex.EncodeToString(sum[:]) || first.SizeBytes != int64(len(stored)) {
		t.Fatal("receipt does not match the stored file")
	}
	second := call(false)
	if !second.Available || !second.Cached || first.SHA256 != second.SHA256 {
		t.Fatalf("stored stroke not reused: %+v", second)
	}
	if err := os.WriteFile(filepath.Join(dataset, "ja", "4e00.svg"), []byte(strings.ReplaceAll(kvgFixture, "M11 54", "M12 54")), 0640); err != nil {
		t.Fatal(err)
	}
	third := call(true)
	if !third.Available || third.Cached || third.SHA256 == first.SHA256 {
		t.Fatalf("force did not regenerate: %+v", third)
	}
	files, err := os.ReadDir(root)
	if err != nil || len(files) != 1 {
		t.Fatalf("unexpected temporary files: %v", files)
	}
	req := httptest.NewRequest(http.MethodPost, "/internal/strokes/generate", strings.NewReader(`{"characters":["一"],"locale":"ja"}`))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("generate without secret: %d", w.Code)
	}
}

func TestStoreServesAndGeneratesMissingStrokesOnly(t *testing.T) {
	_, svc, root, _ := newWorker(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := svc.WrapStore(next)
	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w
	}
	w := get("/store/stroke_ja_4e00.svg")
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/svg+xml" || !strings.Contains(w.Body.String(), "flama-stroke-char") {
		t.Fatalf("missing stroke not generated: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "sandbox") {
		t.Fatal("stroke served without sandbox CSP")
	}
	if _, err := os.Stat(filepath.Join(root, "stroke_ja_4e00.svg")); err != nil {
		t.Fatal("generated stroke not stored")
	}
	for _, path := range []string{"/store/stroke_ja_004e00.svg", "/store/stroke_ja_1234.svg", "/store/stroke_xx_4e00.svg", "/store/stroke_ja_4e00.svg.bak"} {
		if w := get(path); w.Code != http.StatusNotFound {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	if w := get("/store/0b8ef6f9-6c3a-4c55-8a39-4a8c1d6a0f11"); w.Code != http.StatusTeapot {
		t.Fatal("media ids must reach the media store handler")
	}
}

func TestReceiverRoleIsGone(t *testing.T) {
	if _, err := Register(http.NewServeMux(), Options{Role: "receiver", InternalSecret: "secret", StorageRoot: t.TempDir()}); err == nil {
		t.Fatal("receiver role accepted; OV runs nginx only")
	}
	if svc, err := Register(http.NewServeMux(), Options{Role: "disabled"}); svc != nil || err != nil {
		t.Fatalf("disabled role: %v %v", svc, err)
	}
}

type failTransport struct{}

func (failTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
}

func TestMissingCanonicalStrokeIsUnavailable(t *testing.T) {
	root := t.TempDir()
	s := &service{opts: Options{StorageRoot: root}, upstream: &http.Client{Transport: failTransport{}}, slots: make(chan struct{}, 1)}
	item := s.generateOne(context.Background(), "一", "ja")
	if item.Available || item.Error != "STROKE_SOURCE_UNAVAILABLE" {
		t.Fatalf("bad missing result %+v", item)
	}
	files, _ := os.ReadDir(root)
	if len(files) != 0 {
		t.Fatal("missing stroke created a file")
	}
}
