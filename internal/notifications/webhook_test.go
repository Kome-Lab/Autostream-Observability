package notifications

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"strings"
	"testing"
	"time"

	"github.com/example/autostream-observability/internal/store"
)

func TestDiscordWebhookPayload(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	notifier := WebhookNotifier{Type: "discord", URL: server.URL + "/api/webhooks/id/token", Timeout: time.Second, AllowPrivate: true}
	results, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "inc-1", Rule: "encoder_process_exited", Severity: "critical", Status: "open", SummaryJA: "Encoder process stopped.", ServiceID: "enc-01", StreamID: "stream-01"})
	if err != nil {
		t.Fatal(err)
	}
	result := results[0]
	if result.Status != "success" || strings.Contains(result.Target, "token") {
		t.Fatalf("unexpected result: %#v", result)
	}
	content, ok := got["content"].(string)
	if !ok || !strings.Contains(content, "CRITICAL") || !strings.Contains(content, "enc-01") {
		t.Fatalf("unexpected payload: %#v", got)
	}
}

func TestGenericWebhookPayload(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	notifier := WebhookNotifier{Type: "generic", URL: server.URL + "/hook/secret", Timeout: time.Second, AllowPrivate: true}
	if _, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "inc-1", Rule: "gdrive_upload_failed", Severity: "error", Status: "open", SummaryJA: "Google Drive upload failed.", ServiceID: "enc-01"}); err != nil {
		t.Fatal(err)
	}
	if got["event_type"] != "incident.opened" || got["rule"] != "gdrive_upload_failed" {
		t.Fatalf("unexpected payload: %#v", got)
	}
}

func TestGenericWebhookUsesRequestedIncidentLifecycleEvent(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	notifier := WebhookNotifier{Type: "generic", URL: server.URL + "/hook/secret", Timeout: time.Second, AllowPrivate: true}
	results, err := notifier.NotifyIncidentEvent(t.Context(), "incident.resolved", store.Incident{ID: "inc-1", Rule: "gdrive_upload_failed", Severity: "error", Status: "resolved", SummaryJA: "Google Drive upload failed.", ServiceID: "enc-01"})
	if err != nil {
		t.Fatal(err)
	}
	if got["event_type"] != "incident.resolved" || len(results) != 1 || results[0].EventType != "incident.resolved" {
		t.Fatalf("unexpected lifecycle notification: payload=%#v results=%#v", got, results)
	}
}

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

func TestChannelNotifierUsesEnabledChannelsAndFilters(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	st := store.NewMemoryStore()
	if _, err := st.CreateNotificationChannel(t.Context(), store.NotificationChannel{Name: "critical", Type: "generic", Enabled: true, WebhookURL: server.URL + "/hook/secret", SeverityFilter: []string{"critical"}, EventTypeFilter: []string{"incident.opened"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateNotificationChannel(t.Context(), store.NotificationChannel{Name: "warning", Type: "generic", Enabled: true, WebhookURL: server.URL + "/ignored", SeverityFilter: []string{"warning"}}); err != nil {
		t.Fatal(err)
	}
	notifier := ChannelNotifier{Store: st, Timeout: time.Second, AllowPrivate: true}
	results, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "inc-1", Rule: "encoder_process_exited", Severity: "critical", Status: "open", SummaryJA: "Encoder process stopped.", ServiceID: "enc-01"})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(results) != 1 || strings.Contains(results[0].Target, "secret") {
		t.Fatalf("unexpected channel delivery: calls=%d results=%#v", calls, results)
	}
}

func TestChannelNotifierAppliesLifecycleEventFilter(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	st := store.NewMemoryStore()
	if _, err := st.CreateNotificationChannel(t.Context(), store.NotificationChannel{
		Name:            "resolved only",
		Type:            "generic",
		Enabled:         true,
		WebhookURL:      server.URL + "/hook/secret",
		EventTypeFilter: []string{"incident.resolved"},
	}); err != nil {
		t.Fatal(err)
	}
	notifier := ChannelNotifier{Store: st, Timeout: time.Second, AllowPrivate: true}
	incident := store.Incident{ID: "inc-1", Rule: "encoder_process_exited", Severity: "critical", Status: "resolved", SummaryJA: "Encoder process stopped.", ServiceID: "enc-01"}
	if results, err := notifier.NotifyIncidentEvent(t.Context(), "incident.updated", incident); err != nil || len(results) != 0 {
		t.Fatalf("unexpected non-matching delivery: results=%#v err=%v", results, err)
	}
	results, err := notifier.NotifyIncidentEvent(t.Context(), "incident.resolved", incident)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(results) != 1 || results[0].EventType != "incident.resolved" {
		t.Fatalf("unexpected lifecycle-filter delivery: calls=%d results=%#v", calls, results)
	}
}

func TestChannelNotifierPreservesMultipleMatchingDeliveryResults(t *testing.T) {
	var webhookCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhookCalls++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	st := store.NewMemoryStore()
	if _, err := st.CreateNotificationChannel(t.Context(), store.NotificationChannel{
		Name:             "ops discord",
		Type:             "discord",
		Enabled:          true,
		WebhookURL:       server.URL + "/api/webhooks/id/secret-token",
		MaskedWebhookURL: "https://<WEBHOOK_HOST>/<WEBHOOK_PATH>",
		SeverityFilter:   []string{"critical"},
		EventTypeFilter:  []string{"incident.opened"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateNotificationChannel(t.Context(), store.NotificationChannel{
		Name:              "ops email incomplete",
		Type:              "email",
		Enabled:           true,
		EmailRecipients:   []string{"ops@example.com"},
		MaskedEmailTarget: "o***s@<EMAIL_DOMAIN>",
		SeverityFilter:    []string{"critical"},
		EventTypeFilter:   []string{"incident.opened"},
	}); err != nil {
		t.Fatal(err)
	}
	notifier := ChannelNotifier{Store: st, Timeout: time.Second, AllowPrivate: true}
	results, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "inc-1", Rule: "encoder_process_exited", Severity: "critical", Status: "open", SummaryJA: "Encoder process stopped.", ServiceID: "enc-01"})
	if err != nil {
		t.Fatal(err)
	}
	if webhookCalls != 1 || len(results) != 2 {
		t.Fatalf("expected one webhook call and two delivery results, calls=%d results=%#v", webhookCalls, results)
	}
	seen := map[string]DeliveryResult{}
	for _, result := range results {
		seen[result.Channel] = result
		if result.EventType != "incident.opened" {
			t.Fatalf("unexpected event type in delivery result: %#v", result)
		}
		if strings.Contains(result.Target, "secret-token") || strings.Contains(result.Target, "ops@example.com") || strings.Contains(result.Error, "secret-token") || strings.Contains(result.Error, "ops@example.com") {
			t.Fatalf("notification result leaked secret-like target: %#v", result)
		}
	}
	if seen["discord"].Status != "success" || !strings.Contains(seen["discord"].Target, "<WEBHOOK_PATH>") {
		t.Fatalf("unexpected discord delivery result: %#v", seen["discord"])
	}
	if seen["email"].Status != "failure" || seen["email"].Target != "o***s@<EMAIL_DOMAIN>" || seen["email"].Error == "" {
		t.Fatalf("unexpected email delivery result: %#v", seen["email"])
	}
}

func TestMaskWebhookURL(t *testing.T) {
	got := MaskWebhookURL("https://example.com/api/webhooks/<WEBHOOK_ID>/<WEBHOOK_TOKEN>")
	if got != "https://<WEBHOOK_HOST>/<WEBHOOK_PATH>" {
		t.Fatalf("unexpected mask: %s", got)
	}
}

func TestValidateWebhookURLRejectsPrivateTargetsByDefault(t *testing.T) {
	for _, raw := range []string{
		"http://localhost/hook",
		"http://127.0.0.1/hook",
		"http://10.0.0.1/hook",
		"http://169.254.169.254/latest/meta-data",
		"http://[::1]/hook",
		"http://user:password@example.com/hook",
	} {
		if err := ValidateWebhookURLWithPolicy(raw, false); err == nil {
			t.Fatalf("expected private or credentialed URL to be rejected: %s", raw)
		}
	}
}

func TestValidateWebhookURLIgnoresPrivateWebhookAllowanceInProduction(t *testing.T) {
	raw := "http://127.0.0.1/hook"

	t.Run("development explicit allowance", func(t *testing.T) {
		t.Setenv("OBSERVABILITY_ALLOW_PRIVATE_WEBHOOKS", "true")
		if err := ValidateWebhookURL(raw); err != nil {
			t.Fatalf("development private webhook allowance rejected: %v", err)
		}
	})

	t.Run("production ignores explicit allowance", func(t *testing.T) {
		t.Setenv("OBSERVABILITY_ENV", "production")
		t.Setenv("OBSERVABILITY_ALLOW_PRIVATE_WEBHOOKS", "true")
		if err := ValidateWebhookURL(raw); err == nil {
			t.Fatal("production must reject private webhook even when OBSERVABILITY_ALLOW_PRIVATE_WEBHOOKS=true")
		}
	})
}

func TestValidateWebhookURLRejectsRemoteHTTPByDefault(t *testing.T) {
	if err := ValidateWebhookURLWithPolicy("http://hooks.example.com/services/TOKEN", false); err == nil {
		t.Fatal("remote webhook URL over HTTP must be rejected by default")
	}
}

func TestValidateWebhookURLRestrictsDiscordAndSlackHosts(t *testing.T) {
	if err := ValidateWebhookURLForTypeWithPolicy("https://example.com/webhook/token", "discord", false); err == nil {
		t.Fatal("discord channel must reject non-Discord webhook host")
	}
	if err := ValidateWebhookURLForTypeWithPolicy("https://example.com/webhook/token", "slack", false); err == nil {
		t.Fatal("slack channel must reject non-Slack webhook host")
	}
	if err := ValidateWebhookURLForTypeWithPolicy("https://discord.com/api/webhooks/id/token", "discord", false); err != nil {
		t.Fatalf("discord webhook host rejected: %v", err)
	}
	if err := ValidateWebhookURLForTypeWithPolicy("https://hooks.slack.com/services/T000/B000/XXX", "slack", false); err != nil {
		t.Fatalf("slack webhook host rejected: %v", err)
	}
	if err := ValidateWebhookURLForTypeWithPolicy("https://example.com/webhook/token", "generic", false); err != nil {
		t.Fatalf("generic webhook should allow arbitrary public HTTPS host: %v", err)
	}
}

func TestValidateSMTPChannelRequiresTLSForRemoteTargets(t *testing.T) {
	channel := store.NotificationChannel{
		Type:            "email",
		EmailRecipients: []string{"ops@example.com"},
		SMTPHost:        "smtp.example.com",
		SMTPPort:        587,
		SMTPFrom:        "autostream@example.com",
	}
	if err := ValidateSMTPChannelWithPolicy(channel, false); err == nil {
		t.Fatal("remote SMTP channel without TLS must be rejected")
	}
	if err := ValidateSMTPChannelWithPolicy(channel, true); err != nil {
		t.Fatalf("explicit private/dev SMTP allowance should preserve non-TLS local testing path: %v", err)
	}
	channel.SMTPTLS = true
	if err := ValidateSMTPChannelWithPolicy(channel, false); err != nil {
		t.Fatalf("remote SMTP channel with TLS rejected: %v", err)
	}
}

func TestValidateSMTPChannelIgnoresPrivateSMTPAllowanceInProduction(t *testing.T) {
	channel := store.NotificationChannel{
		Type:            "email",
		EmailRecipients: []string{"ops@example.com"},
		SMTPHost:        "127.0.0.1",
		SMTPPort:        587,
		SMTPTLS:         true,
		SMTPFrom:        "autostream@example.com",
	}

	t.Run("development explicit allowance", func(t *testing.T) {
		t.Setenv("OBSERVABILITY_ALLOW_PRIVATE_SMTP", "true")
		if err := ValidateSMTPChannel(channel); err != nil {
			t.Fatalf("development private SMTP allowance rejected: %v", err)
		}
	})

	t.Run("production ignores explicit allowance", func(t *testing.T) {
		t.Setenv("OBSERVABILITY_ENV", "production")
		t.Setenv("OBSERVABILITY_ALLOW_PRIVATE_SMTP", "true")
		if err := ValidateSMTPChannel(channel); err == nil {
			t.Fatal("production must reject private SMTP even when OBSERVABILITY_ALLOW_PRIVATE_SMTP=true")
		}
	})
}

func TestEmailNotifierSendsMaskedDelivery(t *testing.T) {
	var sentAddr, sentFrom string
	var sentTo []string
	notifier := EmailNotifier{
		Channel: store.NotificationChannel{
			Type:              "email",
			EmailRecipients:   []string{"ops@example.com"},
			SMTPHost:          "smtp.example.com",
			SMTPPort:          2525,
			SMTPFrom:          "autostream@example.com",
			SMTPUsername:      "autostream",
			SMTPPassword:      "raw-smtp-password",
			MaskedEmailTarget: "o***s@<EMAIL_DOMAIN>",
		},
		Send: func(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
			sentAddr = addr
			sentFrom = from
			sentTo = append([]string(nil), to...)
			if strings.Contains(string(msg), "raw-smtp-password") {
				t.Fatalf("SMTP password leaked into email message: %s", string(msg))
			}
			return nil
		},
	}
	results, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "inc-01", Rule: "encoder_down", Severity: "critical", Status: "open", SummaryJA: "Encoder process stopped.", ServiceID: "enc-01"})
	if err != nil {
		t.Fatal(err)
	}
	if sentAddr != "smtp.example.com:2525" || sentFrom != "autostream@example.com" || len(sentTo) != 1 || sentTo[0] != "ops@example.com" {
		t.Fatalf("unexpected smtp send args: addr=%q from=%q to=%#v", sentAddr, sentFrom, sentTo)
	}
	if len(results) != 1 || results[0].Status != "success" || results[0].Target != "o***s@<EMAIL_DOMAIN>" {
		t.Fatalf("unexpected result: %#v", results)
	}
}

func TestEmailNotifierRetriesTransientFailures(t *testing.T) {
	attempts := 0
	notifier := EmailNotifier{
		Channel: store.NotificationChannel{
			Type:              "email",
			EmailRecipients:   []string{"ops@example.com"},
			SMTPHost:          "smtp.example.com",
			SMTPPort:          587,
			SMTPFrom:          "autostream@example.com",
			MaskedEmailTarget: "o***s@<EMAIL_DOMAIN>",
		},
		RetryMax:       2,
		RetryBaseDelay: time.Millisecond,
		Sleep: func(ctx context.Context, delay time.Duration) error {
			return nil
		},
		Send: func(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
			attempts += 1
			if attempts == 1 {
				return errors.New("temporary smtp failure")
			}
			return nil
		},
	}
	results, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "inc-02", Rule: "gdrive_upload_failed", Severity: "error", Status: "open", SummaryJA: "Google Drive upload failed.", ServiceID: "enc-01"})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("expected retry after first failure, got attempts=%d", attempts)
	}
	if len(results) != 1 || results[0].Status != "success" || results[0].Target != "o***s@<EMAIL_DOMAIN>" {
		t.Fatalf("unexpected result: %#v", results)
	}
}

func TestEmailNotifierRejectsSMTPHostResolvingPrivateNetwork(t *testing.T) {
	original := smtpLookupIPAddr
	smtpLookupIPAddr = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		if host != "smtp.public-name.example" {
			t.Fatalf("unexpected host lookup: %s", host)
		}
		return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
	}
	defer func() { smtpLookupIPAddr = original }()

	notifier := EmailNotifier{
		Channel: store.NotificationChannel{
			Type:              "email",
			EmailRecipients:   []string{"ops@example.com"},
			SMTPHost:          "smtp.public-name.example",
			SMTPPort:          587,
			SMTPTLS:           true,
			SMTPFrom:          "autostream@example.com",
			MaskedEmailTarget: "o***s@<EMAIL_DOMAIN>",
		},
		RetryMax: -1,
	}
	results, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "inc-03", Rule: "smtp_private_target", Severity: "critical", Status: "open", SummaryJA: "SMTP private target.", ServiceID: "obs-01"})
	if err == nil {
		t.Fatal("expected SMTP delivery to reject private DNS target")
	}
	if len(results) != 1 || results[0].Status != "failure" || results[0].Target != "o***s@<EMAIL_DOMAIN>" || strings.Contains(results[0].Error, "169.254.169.254") {
		t.Fatalf("unexpected sanitized failure result: %#v", results)
	}
}

func TestWebhookNotifierRejectsHostResolvingPrivateNetwork(t *testing.T) {
	original := webhookLookupIPAddr
	webhookLookupIPAddr = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		if host != "webhook.public-name.example" {
			t.Fatalf("unexpected host lookup: %s", host)
		}
		return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
	}
	defer func() { webhookLookupIPAddr = original }()

	notifier := WebhookNotifier{
		Type:     "generic",
		URL:      "https://webhook.public-name.example/hook/secret-token",
		RetryMax: -1,
	}
	results, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "inc-04", Rule: "webhook_private_dns", Severity: "critical", Status: "open", SummaryJA: "Webhook private DNS target.", ServiceID: "obs-01"})
	if err == nil {
		t.Fatal("expected webhook delivery to reject private DNS target")
	}
	if len(results) != 1 || results[0].Status != "failure" || results[0].Target != "https://<WEBHOOK_HOST>/<WEBHOOK_PATH>" || strings.Contains(results[0].Error, "169.254.169.254") || strings.Contains(results[0].Error, "secret-token") {
		t.Fatalf("unexpected sanitized failure result: %#v", results)
	}
	if strings.Contains(err.Error(), "169.254.169.254") || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("secret leaked in returned error: %v", err)
	}
}

func TestValidateWebhookURLAllowsPrivateTargetOnlyWhenExplicit(t *testing.T) {
	if err := ValidateWebhookURLWithPolicy("http://127.0.0.1:8080/hook", true); err != nil {
		t.Fatalf("explicit private webhook allowance rejected: %v", err)
	}
	if err := ValidateWebhookURLWithPolicy("https://hooks.example.com/services/TOKEN", false); err != nil {
		t.Fatalf("public webhook rejected: %v", err)
	}
}
