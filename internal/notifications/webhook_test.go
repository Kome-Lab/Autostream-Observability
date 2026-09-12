package notifications

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/example/autostream-observability/internal/store"
)

func TestWebhookErrorDoesNotLeakURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "secret-token", http.StatusForbidden)
	}))
	defer server.Close()

	notifier := WebhookNotifier{Type: "discord", URL: server.URL + "/api/webhooks/id/secret-token", Timeout: time.Second, AllowPrivate: true}
	results, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "inc-1", Rule: "encoder_process_exited", Severity: "critical", Status: "open", SummaryJA: "Encoder process stopped.", ServiceID: "enc-01"})
	if err == nil {
		t.Fatal("expected error")
	}
	result := results[0]
	if strings.Contains(result.Target, "secret-token") || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("secret leaked: result=%#v err=%v", result, err)
	}
}

func TestWebhookRetriesTransientStatus(t *testing.T) {
	var attempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			http.Error(w, "temporary", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	notifier := WebhookNotifier{
		Type:           "generic",
		URL:            server.URL + "/hook/secret",
		Timeout:        time.Second,
		RetryMax:       2,
		RetryBaseDelay: time.Millisecond,
		AllowPrivate:   true,
	}
	results, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "inc-1", Rule: "test", Severity: "error", Status: "open", SummaryJA: "test", ServiceID: "obs-01"})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || len(results) != 1 || results[0].Status != "success" {
		t.Fatalf("unexpected retry result: attempts=%d results=%#v", attempts, results)
	}
}

func TestWebhookDoesNotRetryPermanentStatus(t *testing.T) {
	var attempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer server.Close()

	notifier := WebhookNotifier{
		Type:           "generic",
		URL:            server.URL + "/hook/secret",
		Timeout:        time.Second,
		RetryMax:       3,
		RetryBaseDelay: time.Millisecond,
		AllowPrivate:   true,
	}
	if _, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "inc-1", Rule: "test", Severity: "error", Status: "open", SummaryJA: "test", ServiceID: "obs-01"}); err == nil {
		t.Fatal("expected permanent webhook failure")
	}
	if attempts != 1 {
		t.Fatalf("permanent failure was retried %d times", attempts)
	}
}

func TestWebhookRequestFailureDoesNotLeakURLInDeliveryResult(t *testing.T) {
	notifier := WebhookNotifier{Type: "generic", URL: "http://127.0.0.1:1/hook/secret-token", Timeout: 10 * time.Millisecond, AllowPrivate: true}
	results, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "inc-1", Rule: "test", Severity: "error", Status: "open", SummaryJA: "test", ServiceID: "obs-01"})
	if err == nil {
		t.Fatal("expected error")
	}
	if len(results) != 1 {
		t.Fatalf("unexpected results: %#v", results)
	}
	if strings.Contains(results[0].Error, "secret-token") || strings.Contains(results[0].Error, "127.0.0.1") || strings.Contains(results[0].Target, "secret-token") {
		t.Fatalf("secret leaked in result: %#v", results[0])
	}
	if results[0].Error != "notification webhook delivery failed" {
		t.Fatalf("unexpected sanitized error: %q", results[0].Error)
	}
}

func TestWebhookRejectsNonHTTPURL(t *testing.T) {
	notifier := WebhookNotifier{Type: "generic", URL: "ftp://example.com/hook/secret-token", Timeout: time.Second}
	results, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "inc-1", Rule: "test", Severity: "error", Status: "open", SummaryJA: "test", ServiceID: "obs-01"})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("secret leaked in error: %v", err)
	}
	if len(results) != 1 || results[0].Status != "failure" || !strings.Contains(results[0].Error, "http or https") {
		t.Fatalf("unexpected result: %#v err=%v", results, err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
