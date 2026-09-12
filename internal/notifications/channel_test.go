package notifications

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/example/autostream-observability/internal/store"
)

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

func TestChannelNotifierAdminAuditBypassesIncidentFilters(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	st := store.NewMemoryStore()
	if _, err := st.CreateNotificationChannel(t.Context(), store.NotificationChannel{
		Name:            "critical incidents only",
		Type:            "generic",
		Enabled:         true,
		WebhookURL:      server.URL + "/hook/secret",
		SeverityFilter:  []string{"critical"},
		EventTypeFilter: []string{"incident.opened"},
	}); err != nil {
		t.Fatal(err)
	}
	notifier := ChannelNotifier{Store: st, Timeout: time.Second, AllowPrivate: true}
	incident := store.Incident{Rule: "oauth_accounts.update", Severity: "info", Status: "success", SummaryJA: "管理イベント: oauth_accounts.update", ServiceID: "observability"}
	if results, err := notifier.NotifyIncidentEvent(t.Context(), "incident.updated", incident); err != nil || len(results) != 0 {
		t.Fatalf("unexpected non-admin delivery: results=%#v err=%v", results, err)
	}
	results, err := notifier.NotifyIncidentEvent(t.Context(), "admin.audit", incident)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(results) != 1 || results[0].EventType != "admin.audit" {
		t.Fatalf("unexpected admin-audit delivery: calls=%d results=%#v", calls, results)
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

type recipientRecordingRelay struct {
	calls []string
	fail  map[string]error
}

func (r *recipientRecordingRelay) SendNotificationEmail(_ context.Context, recipients []string, _, _ string) error {
	if len(recipients) != 1 {
		return errors.New("expected exactly one recipient")
	}
	recipient := recipients[0]
	r.calls = append(r.calls, recipient)
	return r.fail[recipient]
}

func TestChannelNotifierUsesGlobalSMTPRelayForIncident(t *testing.T) {
	st := store.NewMemoryStore()
	_, err := st.CreateNotificationChannel(t.Context(), store.NotificationChannel{
		Name:            "global email",
		Type:            "email",
		Enabled:         true,
		UseGlobalSMTP:   true,
		EmailRecipients: []string{"ops@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	relay := &recordingEmailRelay{}
	notifier := ChannelNotifier{Store: st, EmailRelay: relay, Timeout: 10 * time.Millisecond, EmailTimeout: 500 * time.Millisecond}
	results, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "inc-channel", Rule: "encoder_down", Severity: "critical", Status: "open", SummaryJA: "Encoder stopped.", ServiceID: "enc-01"})
	if err != nil {
		t.Fatal(err)
	}
	if relay.attempts != 1 || len(results) != 1 || results[0].Status != "success" {
		t.Fatalf("global relay was not used: attempts=%d results=%#v", relay.attempts, results)
	}
	if !strings.Contains(relay.html, "<!doctype html>") || !strings.Contains(relay.html, "イベント") || !strings.Contains(relay.html, "encoder_down") {
		t.Fatalf("global relay did not receive the structured HTML alternative: %q", relay.html)
	}
	if !relay.hasDeadline || time.Until(relay.deadline) < 300*time.Millisecond {
		t.Fatalf("email relay inherited the webhook timeout: deadline=%v hasDeadline=%t", relay.deadline, relay.hasDeadline)
	}
}

func TestChannelNotifierRetriesOnlyFailedEmailRecipients(t *testing.T) {
	st := store.NewMemoryStore()
	channel, err := st.CreateNotificationChannel(t.Context(), store.NotificationChannel{
		Name:            "global email",
		Type:            "email",
		Enabled:         true,
		UseGlobalSMTP:   true,
		EmailRecipients: []string{"accepted@example.com", "failed@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	relay := &recipientRecordingRelay{fail: map[string]error{"failed@example.com": codedEmailRelayError("rate_limited")}}
	notifier := ChannelNotifier{Store: st, EmailRelay: relay}
	incident := store.Incident{ID: "inc-partial-email", Rule: "encoder_down", Severity: "critical", Status: "open"}
	results, err := notifier.NotifyIncidentOpened(t.Context(), incident)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || len(relay.calls) != 2 {
		t.Fatalf("email recipients were not delivered independently: results=%#v calls=%#v", results, relay.calls)
	}
	excluded := map[string]struct{}{}
	for _, result := range results {
		if result.Status == "success" {
			excluded[result.ChannelID] = struct{}{}
		}
		if strings.Contains(result.ChannelID, "@") {
			t.Fatalf("recipient address leaked through destination id: %q", result.ChannelID)
		}
	}
	if len(excluded) != 1 {
		t.Fatalf("expected one successful recipient destination: %#v", results)
	}
	relay.fail = map[string]error{}
	relay.calls = nil
	retry, err := notifier.NotifyIncidentEventExceptChannels(t.Context(), "incident.opened", incident, excluded)
	if err != nil {
		t.Fatal(err)
	}
	if len(retry) != 1 || len(relay.calls) != 1 || relay.calls[0] != "failed@example.com" || retry[0].Status != "success" {
		t.Fatalf("retry duplicated an already accepted recipient: retry=%#v calls=%#v", retry, relay.calls)
	}
	if !strings.HasPrefix(retry[0].ChannelID, channel.ID+"/recipient/") {
		t.Fatalf("retry destination is not scoped to the channel: %#v", retry[0])
	}
}
