package fetcher

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/png"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func pngData(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 4, 4))); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// loopbackOnly lets tests reach httptest servers while still exercising the dial check.
func loopbackOnly(ip net.IP) bool { return ip.IsLoopback() }

// httptest servers listen on a random port; tests rewrite that to an allowed URL shape.
func fetchTest(t *testing.T, f *Fetcher, srv *httptest.Server, path string, kind Kind, max int64) (*Result, error) {
	t.Helper()
	// validateURL only allows default ports, so drive the request through a
	// transport-level redirect of the host:port to the test server.
	tr := f.client.Transport.(*http.Transport)
	orig := tr.DialContext
	addr := strings.TrimPrefix(srv.URL, "http://")
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "example.test:80" {
			address = addr
		}
		return orig(ctx, network, address)
	}
	defer func() { tr.DialContext = orig }()
	return f.Fetch(context.Background(), "http://example.test"+path, kind, max, 5*time.Second)
}

func TestFetchReturnsCheckedImage(t *testing.T) {
	img := pngData(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != userAgent {
			t.Errorf("user agent %q", r.Header.Get("User-Agent"))
		}
		w.Header().Set("Content-Type", "text/plain") // declared type is not trusted
		_, _ = w.Write(img)
	}))
	defer srv.Close()
	res, err := fetchTest(t, newFetcher(loopbackOnly), srv, "/pics/cat%20one.png", KindImage, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if res.ContentType != "image/png" || !bytes.Equal(res.Data, img) || res.Filename != "catone.png" {
		t.Fatalf("result %s %q", res.ContentType, res.Filename)
	}
}

func TestFetchBlocksNonPublicDestinationsAtDialTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	if _, err := fetchTest(t, New(), srv, "/x.png", KindImage, 1<<20); !errors.Is(err, ErrURLNotAllowed) {
		t.Fatalf("loopback reached: %v", err)
	}
}

func TestFetchRejectsBadURLs(t *testing.T) {
	f := New()
	for _, raw := range []string{"ftp://example.com/a.png", "http://user:pw@example.com/a.png", "http://example.com:8080/a.png", "http://localhost/a.png", "file:///etc/passwd", "http:///a.png"} {
		if _, err := f.Fetch(context.Background(), raw, KindImage, 1024, time.Second); !errors.Is(err, ErrURLNotAllowed) {
			t.Fatalf("%s accepted: %v", raw, err)
		}
	}
}

func TestFetchRedirectToNonPublicIsBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://10.0.0.1/secret.png", http.StatusFound)
	}))
	defer srv.Close()
	// Allow only the test server's loopback address so the redirect target fails the dial check.
	if _, err := fetchTest(t, newFetcher(loopbackOnly), srv, "/start", KindImage, 1<<20); !errors.Is(err, ErrURLNotAllowed) {
		t.Fatalf("redirect followed: %v", err)
	}
}

func TestFetchEnforcesSizeTypeAndStatus(t *testing.T) {
	img := pngData(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big.png":
			_, _ = w.Write(append(img, bytes.Repeat([]byte{0}, 4096)...))
		case "/page":
			_, _ = w.Write([]byte("<!doctype html><html><head><title>x</title></head></html>"))
		case "/svg":
			_, _ = w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg"></svg>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	f := newFetcher(loopbackOnly)
	if _, err := fetchTest(t, f, srv, "/big.png", KindImage, 1024); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("size limit: %v", err)
	}
	if _, err := fetchTest(t, f, srv, "/svg", KindImage, 1<<20); !errors.Is(err, ErrTypeNotAllowed) {
		t.Fatalf("svg accepted as image: %v", err)
	}
	if _, err := fetchTest(t, f, srv, "/page", KindImage, 1<<20); !errors.Is(err, ErrTypeNotAllowed) {
		t.Fatalf("html accepted as image: %v", err)
	}
	if res, err := fetchTest(t, f, srv, "/page", KindHTML, 1<<20); err != nil || !strings.HasPrefix(res.ContentType, "text/html") {
		t.Fatalf("html: %+v %v", res, err)
	}
	if _, err := fetchTest(t, f, srv, "/missing", KindImage, 1<<20); !errors.Is(err, ErrFetchFailed) {
		t.Fatalf("404: %v", err)
	}
}

func TestIsPublicIP(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "172.20.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fc00::1", "fe80::1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "224.0.0.1", "198.51.100.7"} {
		if IsPublicIP(net.ParseIP(s)) {
			t.Fatalf("%s treated as public", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !IsPublicIP(net.ParseIP(s)) {
			t.Fatalf("%s treated as private", s)
		}
	}
}
