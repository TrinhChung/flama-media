package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port                string
	SharedSecret        string
	GatewaySecret       string // Header X-Flama-Gateway-Secret for OV to 212 verification
	InternalSecret      string // Header X-Internal-Secret sent when reporting incidents to Chung VPS
	SecurityCallbackURL string // Webhook URL on Chung VPS to report attacks
	StorageRoot         string
	TempRoot            string
	MaxUploadBytes      int64
	MaxImageDimension   int
	MaxImagePixels      int
	AllowedOrigins      string
	TrustedProxies      []string
	StageTTLSeconds     int
	ResizeDimension     int
	ListenHost          string
	StrokeRole          string
	StrokeDatasetRoot   string
	StrokeStorageRoot   string
}

func Load() *Config {
	port := getEnv("PORT", "4792")
	secret := strings.TrimSpace(os.Getenv("MEDIA_SHARED_SECRET"))

	gatewaySecret := getEnv("GATEWAY_SECRET", "")
	internalSecret := strings.TrimSpace(os.Getenv("INTERNAL_SECURITY_SECRET"))
	securityCallbackURL := getEnv("SECURITY_CALLBACK_URL", "")

	trustedProxiesStr := getEnv("TRUSTED_PROXIES", "")
	var trustedProxies []string
	if trustedProxiesStr != "" {
		for _, p := range strings.Split(trustedProxiesStr, ",") {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				trustedProxies = append(trustedProxies, trimmed)
			}
		}
	}

	return &Config{
		Port:                port,
		SharedSecret:        secret,
		GatewaySecret:       gatewaySecret,
		InternalSecret:      internalSecret,
		SecurityCallbackURL: securityCallbackURL,
		StorageRoot:         getEnv("MEDIA_STORAGE_ROOT", "./data/media"),
		TempRoot:            getEnv("MEDIA_TEMP_ROOT", "./data/tmp"),
		MaxUploadBytes:      getInt64Env("MAX_UPLOAD_BYTES", 20*1024*1024), // 20MB
		MaxImageDimension:   getIntEnv("MAX_IMAGE_DIMENSION", 16384), // images are resized after decoding
		MaxImagePixels:      getIntEnv("MAX_IMAGE_PIXELS", 50000000), // 50 MP covers phone cameras
		AllowedOrigins:      getEnv("ALLOWED_ORIGINS", ""),
		TrustedProxies:      trustedProxies,
		StageTTLSeconds:     getIntEnv("MEDIA_STAGE_TTL_SECONDS", 86400),
		ResizeDimension:     getIntEnv("IMAGE_RESIZE_DIMENSION", 1600),
		ListenHost:          getEnv("LISTEN_HOST", "127.0.0.1"),
		StrokeRole:          strings.ToLower(strings.TrimSpace(getEnv("STROKE_ROLE", "disabled"))),
		StrokeDatasetRoot:   getEnv("STROKE_DATASET_ROOT", ""),
		StrokeStorageRoot:   getEnv("STROKE_STORAGE_ROOT", ""),
	}
}

func (c *Config) Validate() error {
	if c.InternalSecret == "" {
		return fmt.Errorf("INTERNAL_SECURITY_SECRET is required")
	}
	if c.SharedSecret == "" || c.GatewaySecret == "" {
		return fmt.Errorf("MEDIA_SHARED_SECRET and GATEWAY_SECRET are required")
	}
	if c.MaxUploadBytes <= 0 || c.MaxUploadBytes > 1<<30 || c.MaxImageDimension <= 0 || c.MaxImagePixels <= 0 || c.ResizeDimension <= 0 || c.StageTTLSeconds <= 0 {
		return fmt.Errorf("media limits must be positive and bounded")
	}
	for _, origin := range strings.Split(c.AllowedOrigins, ",") {
		if strings.TrimSpace(origin) == "*" {
			return fmt.Errorf("ALLOWED_ORIGINS requires explicit origins")
		}
	}
	for _, proxy := range c.TrustedProxies {
		if proxy == "*" {
			return fmt.Errorf("TRUSTED_PROXIES cannot allow every upstream")
		}
	}
	return nil
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func getIntEnv(key string, fallback int) int {
	valStr := os.Getenv(key)
	if valStr == "" {
		return fallback
	}
	val, err := strconv.Atoi(valStr)
	if err != nil {
		return fallback
	}
	return val
}

func getInt64Env(key string, fallback int64) int64 {
	valStr := os.Getenv(key)
	if valStr == "" {
		return fallback
	}
	val, err := strconv.ParseInt(valStr, 10, 64)
	if err != nil {
		return fallback
	}
	return val
}
