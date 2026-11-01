package main

import (
	"context"
	"crypto/hmac"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/TrinhChung/flama-media/internal/config"
	"github.com/TrinhChung/flama-media/internal/handler"
	"github.com/TrinhChung/flama-media/internal/reporter"
	"github.com/TrinhChung/flama-media/internal/storage"
	"github.com/TrinhChung/flama-media/internal/stroke"
)

func main() {
	log.Println("[INFO] Initializing Flama Media Service (Go)...")
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("[FATAL] Invalid configuration: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", handler.HealthCheck)
	if err := stroke.Register(mux, stroke.Options{Role: cfg.StrokeRole, InternalSecret: cfg.InternalSecret, DatasetRoot: cfg.StrokeDatasetRoot, StoreURL: cfg.StrokeStoreURL, StoreSecret: cfg.StrokeStoreSecret, StorageRoot: cfg.StrokeStorageRoot}); err != nil {
		log.Fatalf("[FATAL] Stroke configuration: %v", err)
	}

	// OV runs the receiver role only. It must never initialize media storage or
	// register media upload/serve routes; durable media belongs on Worker 212.
	if cfg.StrokeRole != "receiver" {

		// Initialize disk storage
		store, err := storage.NewDiskStorage(cfg.StorageRoot)
		if err != nil {
			log.Fatalf("[FATAL] Failed to initialize storage: %v", err)
		}

		// Initialize security incident reporter to Chung VPS
		incidentReporter := reporter.NewHTTPReporter(cfg.SecurityCallbackURL, cfg.InternalSecret)
		defer incidentReporter.Close()

		// Handlers
		uploadHandler := handler.NewUploadHandler(cfg, store, incidentReporter)
		uploadZipHandler := handler.NewUploadZipHandler(cfg, store, incidentReporter)
		serveHandler := handler.NewServeHandler(cfg, store)
		stagingHandler := handler.NewStagingHandler(cfg, store)
		mux.Handle("POST /media/commit", stagingHandler)
		mux.Handle("POST /media/staged/inspect", stagingHandler)
		mux.Handle("POST /media/assets/inspect", stagingHandler)
		mux.Handle("GET /media/staged/", stagingHandler)
		mux.Handle("HEAD /media/staged/", stagingHandler)

		// Single media upload routes
		mux.Handle("POST /media/upload", uploadHandler)
		mux.Handle("POST /upload", uploadHandler)

		// Batch ZIP media upload routes (Anki packages, media zip packages)
		mux.Handle("POST /media/upload-zip", uploadZipHandler)
		mux.Handle("POST /upload-zip", uploadZipHandler)

		// Media serve routes (Supports /store/, /media/store/, and legacy /media/proxy/)
		mux.Handle("GET /store/", serveHandler)
		mux.Handle("HEAD /store/", serveHandler)
		mux.Handle("GET /media/store/", serveHandler)
		mux.Handle("HEAD /media/store/", serveHandler)
		mux.Handle("GET /media/proxy/", serveHandler)
		mux.Handle("HEAD /media/proxy/", serveHandler)
	}

	// Apply Middlewares: Gateway Security Check + Request Logging
	wrappedMux := loggingMiddleware(gatewaySecurityMiddleware(cfg, corsMiddleware(cfg, mux)))

	server := &http.Server{
		Addr:         net.JoinHostPort(cfg.ListenHost, cfg.Port),
		Handler:      wrappedMux,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown handling
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("[INFO] Flama Media Service running on port %s", cfg.Port)
		log.Printf("[INFO] Storage root: %s", cfg.StorageRoot)
		log.Printf("[INFO] Security callback URL: %s", cfg.SecurityCallbackURL)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] ListenAndServe failed: %v", err)
		}
	}()

	<-stop
	log.Println("[INFO] Shutting down Flama Media Service gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("[FATAL] Server forced shutdown: %v", err)
	}
	log.Println("[INFO] Server exited successfully.")
}

// gatewaySecurityMiddleware enforces the architectural rule:
// All requests must pass through the OV Gateway (Nginx) before reaching 212.
func gatewaySecurityMiddleware(cfg *config.Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health check is always allowed for local diagnostics
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/media/commit" || r.URL.Path == "/media/staged/inspect" || r.URL.Path == "/media/assets/inspect" || strings.HasPrefix(r.URL.Path, "/internal/strokes/") {
			if cfg.InternalSecret == "" || !hmac.Equal([]byte(r.Header.Get("X-Internal-Secret")), []byte(cfg.InternalSecret)) {
				http.Error(w, `{"error":"INTERNAL_ACCESS_DENIED"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if cfg.StrokeRole == "receiver" {
			http.NotFound(w, r)
			return
		}

		// 1. If GATEWAY_SECRET is configured, require matching header from OV Nginx
		if cfg.GatewaySecret != "" {
			reqSecret := r.Header.Get("X-Flama-Gateway-Secret")
			if reqSecret == "" || !hmac.Equal([]byte(reqSecret), []byte(cfg.GatewaySecret)) {
				log.Printf("[SECURITY] Rejected direct request without valid gateway secret from: %s", r.RemoteAddr)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"DIRECT_ACCESS_FORBIDDEN","message":"Direct access to worker node 212 is disallowed. Requests must enter via OV gateway."}`))
				return
			}
		}

		// 2. If TrustedProxies are configured, verify remote address
		if len(cfg.TrustedProxies) > 0 {
			clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				clientIP = r.RemoteAddr
			}

			trusted := false
			for _, proxy := range cfg.TrustedProxies {
				_, subnet, err := net.ParseCIDR(proxy)
				if clientIP == proxy || (err == nil && subnet.Contains(net.ParseIP(clientIP))) {
					trusted = true
					break
				}
			}
			if !trusted {
				log.Printf("[SECURITY] Rejected untrusted IP: %s", clientIP)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"UNTRUSTED_UPSTREAM","message":"Remote IP not in trusted gateway list."}`))
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func corsMiddleware(cfg *config.Config, next http.Handler) http.Handler {
	allowed := map[string]bool{}
	for _, origin := range strings.Split(cfg.AllowedOrigins, ",") {
		if origin = strings.TrimSpace(origin); origin != "" && origin != "*" {
			allowed[origin] = true
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			if !allowed[origin] {
				http.Error(w, `{"error":"ORIGIN_FORBIDDEN"}`, http.StatusForbidden)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Max-Age", "600")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		duration := time.Since(start)
		log.Printf("[HTTP] %s %s - %v (Forwarded-For: %s)",
			r.Method, r.URL.Path, duration, r.Header.Get("X-Forwarded-For"))
	})
}
