package notifications

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/example/autostream-observability/internal/store"
)

func TestWebhookDeliveryPreservesRetryBudgetPayloadAndDeadline(t *testing.T) {
	var contexts []context.Context
	var bodies []string
	var delays []time.Duration
	closed := 0
	notifier := WebhookNotifier{
		Type: "generic", URL: "https://webhook.example.test/hook/secret-token",
		Timeout: time.Minute, RetryMax: 3, RetryBaseDelay: time.Second,
		HTTP: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("request boundary changed: method=%s headers=%#v", request.Method, request.Header)
			}
			if _, ok := request.Context().Deadline(); !ok {
				t.Fatal("attempt has no timeout")
			}
			if len(contexts) > 0 && contexts[len(contexts)-1].Err() != context.Canceled {
				t.Fatal("previous attempt context remains live")
			}
			contexts = append(contexts, request.Context())
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			bodies = append(bodies, string(body))
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: make(http.Header), Body: &characterizationResponseBody{Reader: strings.NewReader(""), closed: &closed}}, nil
		})},
		Sleep: func(_ context.Context, delay time.Duration) error {
			delays = append(delays, delay)
			return nil
		},
	}
	results, err := notifier.NotifyIncidentEvent(t.Context(), "incident.updated", store.Incident{ID: "incident-1", Rule: "encoder_down", Status: "open"})
	if err == nil || err.Error() != "webhook returned status 503" || len(results) != 1 || results[0].Error != err.Error() || results[0].Status != "failure" {
		t.Fatalf("result = %#v error = %v", results, err)
	}
	if len(contexts) != 4 || closed != 4 || !reflect.DeepEqual(delays, []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}) {
		t.Fatalf("attempts=%d closed=%d delays=%v", len(contexts), closed, delays)
	}
	for index, ctx := range contexts {
		if ctx.Err() != context.Canceled || bodies[index] != bodies[0] {
			t.Fatalf("attempt %d did not preserve payload or cancel its context", index)
		}
	}
}

func TestWebhookDeliveryStopsWhenRetryWaitIsCanceled(t *testing.T) {
	attempts := 0
	waits := 0
	notifier := WebhookNotifier{
		Type: "generic", URL: "https://webhook.example.test/hook/secret-token", RetryMax: 3, RetryBaseDelay: time.Second,
		HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			attempts++
			return nil, errors.New("transport detail must not escape")
		})},
		Sleep: func(context.Context, time.Duration) error {
			waits++
			return context.Canceled
		},
	}
	results, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "incident-1"})
	if attempts != 1 || waits != 1 || err == nil || err.Error() != "notification webhook delivery failed" || len(results) != 1 || results[0].Error != err.Error() {
		t.Fatalf("attempts=%d waits=%d results=%#v error=%v", attempts, waits, results, err)
	}
}

func TestEmailDeliveryPreservesWrappedTypedErrorAndSafeProjection(t *testing.T) {
	cause := codedEmailRelayError("smtp_auth_failed")
	wrapped := fmt.Errorf("private provider detail: %w", cause)
	relay := &recordingEmailRelay{err: wrapped}
	notifier := EmailNotifier{Channel: store.NotificationChannel{Type: "email", UseGlobalSMTP: true, EmailRecipients: []string{"ops@example.test"}}, Relay: relay}
	results, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "incident-1"})
	var typed codedEmailRelayError
	if err != wrapped || !errors.As(err, &typed) || typed != cause || relay.attempts != 1 {
		t.Fatalf("typed cause or single attempt changed: error=%v attempts=%d", err, relay.attempts)
	}
	if len(results) != 1 || results[0].Error != "smtp_auth_failed" || SanitizeChannelDeliveryError("email", wrapped) != "smtp_auth_failed" {
		t.Fatalf("safe projection = %#v", results)
	}
}

type characterizationResponseBody struct {
	io.Reader
	closed *int
}

func (body *characterizationResponseBody) Close() error {
	*body.closed++
	return nil
}
