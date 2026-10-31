package main

import (
	"context"
	"log"
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
)

func main() {
	log.Println("[INFO] Initializing Flama Media Service (Go)...")
	cfg := config.Load()

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

	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("GET /health", handler.HealthCheck)

	// Single media upload routes
	mux.Handle("POST /media/upload", uploadHandler)
	mux.Handle("POST /upload", uploadHandler)

	// Batch ZIP media upload routes (Anki packages, media zip packages)
	mux.Handle("POST /media/upload-zip", uploadZipHandler)
	mux.Handle("POST /upload-zip", uploadZipHandler)

	// Media serve route (canonical Flama format)
	mux.Handle("GET /media/proxy/", serveHandler)
	mux.Handle("HEAD /media/proxy/", serveHandler)

	// Apply Middlewares: Gateway Security Check + Request Logging
	wrappedMux := gatewaySecurityMiddleware(cfg, loggingMiddleware(mux))

	server := &http.Server{
		Addr:         ":" + cfg.Port,
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

		// 1. If GATEWAY_SECRET is configured, require matching header from OV Nginx
		if cfg.GatewaySecret != "" {
			reqSecret := r.Header.Get("X-Flama-Gateway-Secret")
			if reqSecret == "" || reqSecret != cfg.GatewaySecret {
				log.Printf("[SECURITY] Rejected direct request without valid gateway secret from: %s", r.RemoteAddr)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"DIRECT_ACCESS_FORBIDDEN","message":"Direct access to worker node 212 is disallowed. Requests must enter via OV gateway."}`))
				return
			}
		}

		// 2. If TrustedProxies are configured, verify remote address
		if len(cfg.TrustedProxies) > 0 {
			clientIP := r.RemoteAddr
			if colonIdx := strings.LastIndex(clientIP, ":"); colonIdx != -1 {
				clientIP = clientIP[:colonIdx]
			}

			trusted := false
			for _, proxy := range cfg.TrustedProxies {
				if clientIP == proxy || proxy == "*" {
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

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		duration := time.Since(start)
		log.Printf("[HTTP] %s %s - %v (Forwarded-For: %s)",
			r.Method, r.URL.Path, duration, r.Header.Get("X-Forwarded-For"))
	})
}
