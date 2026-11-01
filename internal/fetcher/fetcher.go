// Package fetcher downloads public URLs for the backend so outbound requests
// leave from the media worker, never from the app server, and cannot reach
// private, loopback or otherwise non-public addresses.
package fetcher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"syscall"
	"time"
)

var (
	ErrURLNotAllowed  = errors.New("url not allowed")
	ErrTooLarge       = errors.New("remote payload exceeds limit")
	ErrTypeNotAllowed = errors.New("remote content type not allowed")
	ErrFetchFailed    = errors.New("remote fetch failed")
)

// Kind selects what the caller expects back.
type Kind string

const (
	KindImage Kind = "image"
	KindHTML  Kind = "html"
)

// MaxRedirects bounds redirect chains; every hop is re-validated.
const MaxRedirects = 3

const userAgent = "FlamaMediaFetcher/1.0 (+https://flama.vn)"

type Result struct {
	Data        []byte
	ContentType string
	FinalURL    string
	Filename    string
}

type Fetcher struct {
	client  *http.Client
	allowIP func(net.IP) bool
}

// New returns a fetcher that only connects to public unicast addresses.
func New() *Fetcher { return newFetcher(IsPublicIP) }

func newFetcher(allow func(net.IP) bool) *Fetcher {
	f := &Fetcher{allowIP: allow}
	// The address check runs on the IP actually being dialed, after DNS, so a
	// hostname cannot be re-pointed (DNS rebinding) between check and connect.
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if ip := net.ParseIP(host); err != nil || ip == nil || !f.allowIP(ip) {
			return fmt.Errorf("%w: destination is not a public address", ErrURLNotAllowed)
		}
		return nil
	}}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		ForceAttemptHTTP2:      true,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		MaxIdleConns:           8,
		IdleConnTimeout:        30 * time.Second,
	}
	f.client = &http.Client{Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > MaxRedirects {
			return fmt.Errorf("%w: too many redirects", ErrURLNotAllowed)
		}
		return validateURL(req.URL)
	}}
	return f
}

func validateURL(u *url.URL) error {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Hostname() == "" {
		return fmt.Errorf("%w: only public http(s) URLs are allowed", ErrURLNotAllowed)
	}
	if port := u.Port(); port != "" && port != "80" && port != "443" {
		return fmt.Errorf("%w: only ports 80 and 443 are allowed", ErrURLNotAllowed)
	}
	if strings.EqualFold(strings.TrimSuffix(u.Hostname(), "."), "localhost") {
		return fmt.Errorf("%w: localhost is not allowed", ErrURLNotAllowed)
	}
	return nil
}

// Fetch downloads rawURL within timeout and maxBytes and checks the content by magic bytes.
func (f *Fetcher) Fetch(ctx context.Context, rawURL string, kind Kind, maxBytes int64, timeout time.Duration) (*Result, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || len(rawURL) > 2048 {
		return nil, fmt.Errorf("%w: invalid URL", ErrURLNotAllowed)
	}
	if err := validateURL(u); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid URL", ErrURLNotAllowed)
	}
	req.Header.Set("User-Agent", userAgent)
	if kind == KindHTML {
		req.Header.Set("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1")
	} else {
		req.Header.Set("Accept", "image/webp,image/png,image/jpeg,image/gif;q=0.9,*/*;q=0.1")
	}

	resp, err := f.client.Do(req)
	if err != nil {
		if errors.Is(err, ErrURLNotAllowed) {
			return nil, err
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w: timed out", ErrFetchFailed)
		}
		return nil, fmt.Errorf("%w: %v", ErrFetchFailed, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: upstream status %d", ErrFetchFailed, resp.StatusCode)
	}
	if resp.ContentLength > maxBytes {
		return nil, ErrTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: reading body", ErrFetchFailed)
	}
	if int64(len(data)) > maxBytes {
		return nil, ErrTooLarge
	}

	contentType, err := checkContent(kind, data, resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}
	return &Result{Data: data, ContentType: contentType, FinalURL: resp.Request.URL.String(), Filename: safeFilename(resp.Request.URL.Path)}, nil
}

func checkContent(kind Kind, data []byte, declared string) (string, error) {
	detected := http.DetectContentType(data)
	if kind == KindHTML {
		declaredType, params, _ := mime.ParseMediaType(declared)
		if strings.HasPrefix(detected, "text/html") || declaredType == "text/html" || declaredType == "application/xhtml+xml" {
			if charset := params["charset"]; charset != "" {
				return "text/html; charset=" + charset, nil
			}
			return "text/html", nil
		}
		return "", fmt.Errorf("%w: expected an HTML page", ErrTypeNotAllowed)
	}
	switch detected {
	case "image/jpeg", "image/png", "image/gif", "image/webp":
		return detected, nil
	}
	return "", fmt.Errorf("%w: %s", ErrTypeNotAllowed, detected)
}

func safeFilename(p string) string {
	var b strings.Builder
	for _, r := range path.Base(p) {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	name := strings.Trim(b.String(), ".")
	if name == "" {
		return "remote"
	}
	if len(name) > 120 {
		name = name[:120]
	}
	return name
}

var blockedNets = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, cidr := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32",
		"2002::/16", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		nets = append(nets, n)
	}
	return nets
}()

// IsPublicIP reports whether ip is a globally routable unicast address.
func IsPublicIP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		ip = v4 // IPv4-mapped IPv6 is checked as IPv4
	}
	for _, n := range blockedNets {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}
