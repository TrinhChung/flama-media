package handler

import (
	"encoding/json"
	"net/http"
	"time"
)

// Injected at build time via -ldflags
var (
	Version   = "dev"
	CommitSHA = "none"
	BuildTime = "unknown"
)

type HealthResponse struct {
	Status    string    `json:"status"`
	Service   string    `json:"service"`
	Version   string    `json:"version"`
	Commit    string    `json:"commit"`
	BuildTime string    `json:"build_time"`
	Timestamp time.Time `json:"timestamp"`
}

func HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(HealthResponse{
		Status:    "healthy",
		Service:   "flama-media",
		Version:   Version,
		Commit:    CommitSHA,
		BuildTime: BuildTime,
		Timestamp: time.Now().UTC(),
	})
}
