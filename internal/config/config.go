package config

import (
	"log"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port              string
	SharedSecret      string
	GatewaySecret     string // Header X-Flama-Gateway-Secret for OV to 212 verification
	StorageRoot       string
	TempRoot          string
	MaxUploadBytes    int64
	MaxImageDimension int
	MaxImagePixels    int
	AllowedOrigins    string
	TrustedProxies    []string
}

func Load() *Config {
	port := getEnv("PORT", "4792")
	secret := os.Getenv("MEDIA_SHARED_SECRET")
	if secret == "" {
		log.Println("[WARN] MEDIA_SHARED_SECRET is not set! Using default insecure development secret.")
		secret = "flama-dev-insecure-media-secret-change-in-production-123456789"
	}

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
		Port:              port,
		SharedSecret:      secret,
		GatewaySecret:     getEnv("GATEWAY_SECRET", ""), // Optional extra security token between OV and 212
		StorageRoot:       getEnv("MEDIA_STORAGE_ROOT", "./data/media"),
		TempRoot:          getEnv("MEDIA_TEMP_ROOT", "./data/tmp"),
		MaxUploadBytes:    getInt64Env("MAX_UPLOAD_BYTES", 20*1024*1024), // 20MB
		MaxImageDimension: getIntEnv("MAX_IMAGE_DIMENSION", 4096),
		MaxImagePixels:    getIntEnv("MAX_IMAGE_PIXELS", 16000000), // 16 MegaPixels
		AllowedOrigins:    getEnv("ALLOWED_ORIGINS", "*"),
		TrustedProxies:    trustedProxies,
	}
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
