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

func TestWorkerGeneratesOn212StoresOnlyOnOVAndReusesStoredStroke(t *testing.T) {
	root := t.TempDir()
	receiverMux := http.NewServeMux()
	if err := Register(receiverMux, Options{Role: "receiver", InternalSecret: "receiver-secret", StorageRoot: root}); err != nil {
		t.Fatal(err)
	}
	receiver := httptest.NewServer(receiverMux)
	defer receiver.Close()
	dataset := t.TempDir()
	if err := os.Mkdir(filepath.Join(dataset, "ja"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataset, "ja", "4e00.svg"), []byte(kvgFixture), 0640); err != nil {
		t.Fatal(err)
	}
	workerMux := http.NewServeMux()
	if err := Register(workerMux, Options{Role: "worker", InternalSecret: "backend-secret", DatasetRoot: dataset, StoreURL: receiver.URL + "/internal/strokes", StoreSecret: "receiver-secret"}); err != nil {
		t.Fatal(err)
	}
	call := func(force bool) Item {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"characters": []string{"一"}, "locale": "ja", "force": force})
		req := httptest.NewRequest(http.MethodPost, "/internal/strokes/generate", bytes.NewReader(body))
		req.Header.Set("X-Internal-Secret", "backend-secret")
		w := httptest.NewRecorder()
		workerMux.ServeHTTP(w, req)
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
		t.Fatal("receipt does not match OV disk")
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
}

func TestReceiverRequiresSecretRejectsTraversalAndStripsUnknownAttrs(t *testing.T) {
	root := t.TempDir()
	mux := http.NewServeMux()
	if err := Register(mux, Options{Role: "receiver", InternalSecret: "secret", StorageRoot: root}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path, body, secret string
		status             int
	}{
		{"/internal/strokes/stroke_ja_4e00.svg", kvgFixture, "", 401},
		{"/internal/strokes/stroke_ja_004e00.svg", kvgFixture, "secret", 400},
		{"/internal/strokes/stroke_ja_1234.svg", kvgFixture, "secret", 400},
		{"/internal/strokes/stroke_ja_4e00.svg", `<svg class="flama-stroke-char"><script/></svg>`, "secret", 400},
		{"/internal/strokes/stroke_ja_4e00.svg", `<svg xmlns="http://www.w3.org/2000/svg" class="flama-stroke-char" onload="alert(1)"><path d="M0 0 L1 1" href="https://example.com"/></svg>`, "secret", 201},
	} {
		r := httptest.NewRequest(http.MethodPut, test.path, strings.NewReader(test.body))
		r.Header.Set("X-Internal-Secret", test.secret)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != test.status {
			t.Fatalf("%s wanted %d got %d %s", test.path, test.status, w.Code, w.Body.String())
		}
	}
	data, err := os.ReadFile(filepath.Join(root, "stroke_ja_4e00.svg"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("onload")) || bytes.Contains(data, []byte("href")) {
		t.Fatal("receiver wrote unfiltered bytes")
	}
}

type failTransport struct{}

func (failTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
}

func TestMissingCanonicalStrokeIsUnavailable(t *testing.T) {
	root := t.TempDir()
	mux := http.NewServeMux()
	_ = Register(mux, Options{Role: "receiver", InternalSecret: "secret", StorageRoot: root})
	server := httptest.NewServer(mux)
	defer server.Close()
	s := &service{opts: Options{StoreURL: server.URL + "/internal/strokes", StoreSecret: "secret"}, client: server.Client(), upstream: &http.Client{Transport: failTransport{}}}
	item := s.generateOne(context.Background(), "一", "ja")
	if item.Available || item.Error != "STROKE_SOURCE_UNAVAILABLE" {
		t.Fatalf("bad missing result %+v", item)
	}
	files, _ := os.ReadDir(root)
	if len(files) != 0 {
		t.Fatal("missing stroke created a file")
	}
}
