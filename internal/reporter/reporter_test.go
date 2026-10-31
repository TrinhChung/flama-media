package reporter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPReporter_ReportIncidentAsync(t *testing.T) {
	receivedChan := make(chan SecurityIncident, 1)
	receivedSecret := make(chan string, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSecret <- r.Header.Get("X-Internal-Secret")
		var inc SecurityIncident
		if err := json.NewDecoder(r.Body).Decode(&inc); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		receivedChan <- inc
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	testSecret := "test_secret_xyz_123"
	rep := NewHTTPReporter(server.URL, testSecret)
	defer rep.Close()

	testIncident := SecurityIncident{
		UserID:       42,
		IncidentType: "ZIP_SLIP",
		Detail:       "traversal attempt ../../evil.png",
		ClientIP:     "192.168.1.100",
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
	}

	rep.ReportIncidentAsync(testIncident)

	select {
	case sec := <-receivedSecret:
		if sec != testSecret {
			t.Errorf("expected secret %q, got %q", testSecret, sec)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for secret header")
	}

	select {
	case inc := <-receivedChan:
		if inc.UserID != testIncident.UserID {
			t.Errorf("expected user_id %d, got %d", testIncident.UserID, inc.UserID)
		}
		if inc.IncidentType != testIncident.IncidentType {
			t.Errorf("expected type %s, got %s", testIncident.IncidentType, inc.IncidentType)
		}
		if inc.Detail != testIncident.Detail {
			t.Errorf("expected detail %s, got %s", testIncident.Detail, inc.Detail)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for incident")
	}
}
