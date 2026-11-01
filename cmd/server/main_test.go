package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TrinhChung/flama-media/internal/config"
)

func TestInternalAuthenticationBypassesPublicGatewayOnlyForInternalRoutes(t *testing.T) {
	cfg := &config.Config{InternalSecret: "internal", GatewaySecret: "gateway", TrustedProxies: []string{"192.0.2.1"}}
	h := gatewaySecurityMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	for _, tc := range []struct {
		path, secret string
		status       int
	}{{"/media/commit", "internal", 204}, {"/media/staged/inspect", "internal", 204}, {"/media/assets/inspect", "internal", 204}, {"/internal/strokes/generate", "internal", 204}, {"/media/commit", "gateway", 403}, {"/media/upload", "internal", 403}} {
		r := httptest.NewRequest(http.MethodPost, tc.path, nil)
		r.Header.Set("X-Internal-Secret", tc.secret)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%s=%d expected %d", tc.path, w.Code, tc.status)
		}
	}
}

func TestDirectUploadCORSPreflightRequiresAllowedOrigin(t *testing.T) {
	cfg := &config.Config{AllowedOrigins: "https://app.example.test"}
	h := corsMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	for _, tc := range []struct {
		origin string
		status int
	}{{"https://app.example.test", 204}, {"https://evil.example.test", 403}} {
		r := httptest.NewRequest(http.MethodOptions, "/media/upload", nil)
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("Access-Control-Request-Headers", "authorization")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("origin %s=%d", tc.origin, w.Code)
		}
		if w.Header().Get("Access-Control-Allow-Credentials") != "" {
			t.Fatal("upload requires no application cookies")
		}
	}
}
