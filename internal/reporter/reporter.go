package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type SecurityIncident struct {
	UserID       int64  `json:"user_id,omitempty"`
	IncidentType string `json:"incident_type"`
	Detail       string `json:"detail"`
	ClientIP     string `json:"client_ip,omitempty"`
	Timestamp    string `json:"timestamp"`
}

type Reporter interface {
	ReportIncidentAsync(incident SecurityIncident)
	Close()
}

type HTTPReporter struct {
	callbackURL string
	secret      string
	client      *http.Client
	queue       chan SecurityIncident
	done        chan struct{}
}

func NewHTTPReporter(callbackURL, secret string) *HTTPReporter {
	r := &HTTPReporter{
		callbackURL: callbackURL,
		secret:      secret,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		queue: make(chan SecurityIncident, 256),
		done:  make(chan struct{}),
	}
	go r.worker()
	return r
}

func (r *HTTPReporter) ReportIncidentAsync(incident SecurityIncident) {
	if r == nil || r.callbackURL == "" {
		log.Printf("[WARN] Security incident detected but no reporter configured: %+v", incident)
		return
	}
	select {
	case r.queue <- incident:
	default:
		log.Printf("[ERROR] Security incident queue full, dropping incident: %+v", incident)
	}
}

func (r *HTTPReporter) worker() {
	for inc := range r.queue {
		if err := r.send(inc); err != nil {
			log.Printf("[ERROR] Failed to send security incident to callback %s: %v", r.callbackURL, err)
		}
	}
	close(r.done)
}

func (r *HTTPReporter) send(inc SecurityIncident) error {
	body, err := json.Marshal(inc)
	if err != nil {
		return fmt.Errorf("marshal incident error: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, r.callbackURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request error: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "flama-media-reporter/1.0")
	if r.secret != "" {
		req.Header.Set("X-Internal-Secret", r.secret)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("do request error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status code from incident callback: %d", resp.StatusCode)
	}

	log.Printf("[SECURITY] Successfully reported incident %s (user_id=%d) to %s", inc.IncidentType, inc.UserID, r.callbackURL)
	return nil
}

func (r *HTTPReporter) Close() {
	if r == nil {
		return
	}
	close(r.queue)
	select {
	case <-r.done:
	case <-time.After(2 * time.Second):
		log.Println("[WARN] Timeout waiting for security reporter worker to finish")
	}
}
