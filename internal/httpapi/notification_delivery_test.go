package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/example/autostream-observability/internal/auth"
	"github.com/example/autostream-observability/internal/notifications"
	"github.com/example/autostream-observability/internal/store"
)

func TestListNotificationDeliveriesRequiresAuthorization(t *testing.T) {
	handler := newTestServer(store.NewMemoryStore())
	req := httptest.NewRequest(http.MethodGet, "/notification-deliveries", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
	}
}

func TestNotificationDeliveryHistoryDoesNotExposeWebhookErrorSecrets(t *testing.T) {
	st := store.NewMemoryStore()
	handler := NewServerWithStoreAuthAndNotifier("observability", st, auth.NewVerifierFromRawTokens("service-token"), failingNotifier{})
	ingestReq := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(`{"type":"error","name":"encoder.process.exited","service_id":"enc-01","service_type":"encoder_recorder","stream_id":"stream-01"}`))
	ingestReq.Header.Set("Authorization", "Bearer service-token")
	ingestRes := httptest.NewRecorder()
	handler.ServeHTTP(ingestRes, ingestReq)
	if ingestRes.Code != http.StatusAccepted {
		t.Fatalf("ingest status = %d body = %s", ingestRes.Code, ingestRes.Body.String())
	}
	listReq := httptest.NewRequest(http.MethodGet, "/notification-deliveries", nil)
	listReq.Header.Set("Authorization", "Bearer service-token")
	listRes := httptest.NewRecorder()
	handler.ServeHTTP(listRes, listReq)
	if listRes.Code != http.StatusOK {
		t.Fatalf("list status = %d body = %s", listRes.Code, listRes.Body.String())
	}
	body := listRes.Body.String()
	if strings.Contains(body, "secret-token") || strings.Contains(body, "discord.com/api/webhooks") {
		t.Fatalf("webhook secret leaked in delivery history: %s", body)
	}
	if !strings.Contains(body, "notification webhook delivery failed") {
		t.Fatalf("expected sanitized delivery error: %s", body)
	}
}

func TestDeliverNotificationEventOutlivesRequestCancellationWithinBoundedDeadline(t *testing.T) {
	st := store.NewMemoryStore()
	notifier := &eventRecordingNotifier{}
	server := &Server{serviceType: "observability", store: st, notifier: notifier}
	requestContext, cancelRequest := context.WithCancel(context.Background())
	cancelRequest()
	request := httptest.NewRequest(http.MethodPost, "/signals", nil).WithContext(requestContext)

	results := server.deliverNotificationEvent(request, "incident.opened", store.Incident{ID: "inc-detached", Rule: "encoder_down", Severity: "critical", Status: "open", SummaryJA: "Encoder stopped."})
	if len(results) != 1 || results[0].Status != "success" || len(notifier.events) != 1 {
		t.Fatalf("request cancellation stopped notification delivery: results=%#v events=%#v", results, notifier.events)
	}
	if !notifier.hasDeadline {
		t.Fatal("detached notification delivery has no bounded deadline")
	}
	remaining := time.Until(notifier.deadline)
	if remaining <= 0 || remaining > notificationFanoutTimeout {
		t.Fatalf("unexpected detached delivery deadline: remaining=%s", remaining)
	}
	deliveries, err := st.ListNotificationDeliveries(t.Context())
	if err != nil || len(deliveries) != 1 || deliveries[0].IncidentID != "inc-detached" {
		t.Fatalf("detached delivery history was not saved: deliveries=%#v err=%v", deliveries, err)
	}
}

func TestSaveNotificationDeliveryResultsLogsSafeFailureAndContinues(t *testing.T) {
	const (
		targetSecret   = "https://discord.com/api/webhooks/id/target-secret"
		bodySecret     = "notification body contains body-secret"
		databaseSecret = "database connection failed with db-secret"
	)
	st := &failingNotificationDeliveryStore{
		Store: store.NewMemoryStore(),
		err:   errors.New(databaseSecret),
	}
	var output bytes.Buffer
	server := &Server{store: st, logger: log.New(&output, "", 0)}

	server.saveNotificationDeliveryResults(t.Context(), "incident.opened", store.Incident{
		ID:        "incident-secret-id",
		Rule:      "encoder_down",
		Severity:  "critical",
		SummaryJA: bodySecret,
	}, []notifications.DeliveryResult{
		{EventType: "admin.audit", Channel: "email", Target: targetSecret, Status: "success", Error: "smtp_auth_failed"},
		{Channel: "discord", Target: "https://example.com/second-target-secret", Status: "success"},
	})

	if st.attempts != 2 {
		t.Fatalf("notification delivery save attempts = %d, want 2", st.attempts)
	}
	logged := output.String()
	for _, want := range []string{
		`event_type="admin.audit" channel="email" status="failure"`,
		`event_type="incident.opened" channel="discord" status="success"`,
	} {
		if !strings.Contains(logged, want) {
			t.Fatalf("safe save failure log missing %q: %s", want, logged)
		}
	}
	for _, forbidden := range []string{targetSecret, "second-target-secret", bodySecret, databaseSecret, "smtp_auth_failed", "incident-secret-id"} {
		if strings.Contains(logged, forbidden) {
			t.Fatalf("notification delivery save failure log leaked %q: %s", forbidden, logged)
		}
	}
}

func TestNotificationDeliveryHistoryRedactsSecretsAfterSafeMarkers(t *testing.T) {
	st := store.NewMemoryStore()
	if _, err := st.SaveNotificationDelivery(t.Context(), store.NotificationDelivery{
		EventType: "admin.audit",
		Channel:   "discord",
		Status:    "success",
		Metadata: map[string]any{
			"action":  "raw.secret.token",
			"rule":    "secrets.ast_svc_raw_token",
			"summary": "<redacted> / opaque-value-that-must-not-survive",
		},
	}); err != nil {
		t.Fatal(err)
	}
	handler := NewServerWithStoreAuthAndNotifier("observability", st, auth.NewVerifierFromRawTokens("service-token"), &eventRecordingNotifier{})
	req := httptest.NewRequest(http.MethodGet, "/notification-deliveries", nil)
	req.Header.Set("Authorization", "Bearer service-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("list status = %d body = %s", res.Code, res.Body.String())
	}
	for _, raw := range []string{"raw.secret.token", "ast_svc_raw_token", "opaque-value-that-must-not-survive"} {
		if strings.Contains(res.Body.String(), raw) {
			t.Fatalf("compound marker secret %q leaked in delivery history: %s", raw, res.Body.String())
		}
	}
}

func TestNotificationPartialFailureKeepsSuccessfulDeliveries(t *testing.T) {
	st := store.NewMemoryStore()
	handler := NewServerWithStoreAuthAndNotifier("observability", st, auth.NewVerifierFromRawTokens("service-token"), partialFailureNotifier{})
	ingestReq := httptest.NewRequest(http.MethodPost, "/signals", bytes.NewBufferString(`{"type":"error","name":"encoder.process.exited","service_id":"enc-01","service_type":"encoder_recorder","stream_id":"stream-01"}`))
	ingestReq.Header.Set("Authorization", "Bearer service-token")
	ingestRes := httptest.NewRecorder()
	handler.ServeHTTP(ingestRes, ingestReq)
	if ingestRes.Code != http.StatusAccepted {
		t.Fatalf("ingest status = %d body = %s", ingestRes.Code, ingestRes.Body.String())
	}
	listReq := httptest.NewRequest(http.MethodGet, "/notification-deliveries", nil)
	listReq.Header.Set("Authorization", "Bearer service-token")
	listRes := httptest.NewRecorder()
	handler.ServeHTTP(listRes, listReq)
	if listRes.Code != http.StatusOK {
		t.Fatalf("list status = %d body = %s", listRes.Code, listRes.Body.String())
	}
	body := listRes.Body.String()
	if strings.Contains(body, "secret-token") || strings.Contains(body, "discord.com/api/webhooks") || strings.Contains(body, "smtp-password") {
		t.Fatalf("notification secret leaked in delivery history: %s", body)
	}
	var deliveries []store.NotificationDelivery
	if err := json.Unmarshal(listRes.Body.Bytes(), &deliveries); err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 2 {
		t.Fatalf("expected success and failure deliveries to be preserved, got %#v", deliveries)
	}
	seen := map[string]string{}
	for _, delivery := range deliveries {
		seen[delivery.Channel] = delivery.Status
		if delivery.EventType != "incident.opened" || delivery.IncidentID == "" {
			t.Fatalf("unexpected delivery metadata: %#v", delivery)
		}
	}
	if seen["email"] != "success" || seen["discord"] != "failure" {
		t.Fatalf("expected email success and discord failure deliveries, got %#v", deliveries)
	}
}

type failingNotificationDeliveryStore struct {
	store.Store
	err      error
	attempts int
}

func (s *failingNotificationDeliveryStore) SaveNotificationDelivery(context.Context, store.NotificationDelivery) (store.NotificationDelivery, error) {
	s.attempts++
	return store.NotificationDelivery{}, s.err
}
