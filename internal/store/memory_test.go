package store

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMemoryStoreDeduplicatesOpenIncidents(t *testing.T) {
	s := NewMemoryStore()
	incident := Incident{Rule: "encoder_process_exited", Severity: "critical", ServiceID: "enc-01", StreamID: "stream-01", SignalID: "sig-1"}
	first, created, err := s.UpsertIncident(t.Context(), incident)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("expected first incident to be created")
	}
	second, created, err := s.UpsertIncident(t.Context(), Incident{Rule: "encoder_process_exited", Severity: "critical", ServiceID: "enc-01", StreamID: "stream-01", SignalID: "sig-2"})
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("expected duplicate incident to update existing row")
	}
	if first.ID != second.ID || second.SignalID != "sig-2" {
		t.Fatalf("unexpected dedupe: first=%#v second=%#v", first, second)
	}
}

func TestMemoryStoreUpdatesIncidentStatus(t *testing.T) {
	s := NewMemoryStore()
	incident, _, err := s.UpsertIncident(t.Context(), Incident{Rule: "encoder_process_exited", Severity: "critical", ServiceID: "enc-01", SignalID: "sig-1"})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := s.UpdateIncidentStatus(t.Context(), incident.ID, "resolved")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != "resolved" || updated.ResolvedAt == nil {
		t.Fatalf("unexpected incident status: %#v", updated)
	}
	if _, err := s.UpdateIncidentStatus(t.Context(), incident.ID, "deleted"); err != ErrInvalidStatus {
		t.Fatalf("expected invalid status, got %v", err)
	}
}

func TestMemoryStoreNotificationDelivery(t *testing.T) {
	s := NewMemoryStore()
	delivery, err := s.SaveNotificationDelivery(t.Context(), NotificationDelivery{
		EventType: "incident.opened",
		Channel:   "generic",
		Target:    "https://example.com/webhook/private-token",
		Status:    "success",
		Error:     "Authorization Bearer raw-secret-token",
		Metadata: map[string]any{
			"safe":        "ok",
			"webhook_url": "https://discord.com/api/webhooks/id/upstream-secret-token",
			"nested": map[string]any{
				"target": "rtsp://user:password@camera.example.com/live",
			},
			"messages": []any{"ok", "Bearer nested-secret-token"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if delivery.ID == "" || delivery.CreatedAt.IsZero() {
		t.Fatalf("unexpected delivery: %#v", delivery)
	}
	body, err := json.Marshal(delivery)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"private-token", "raw-secret-token", "upstream-secret-token", "password@camera", "nested-secret-token", "discord.com/api/webhooks"} {
		if strings.Contains(string(body), raw) {
			t.Fatalf("raw delivery secret leaked in saved delivery: %s", body)
		}
	}
	if delivery.Target != "https://<WEBHOOK_HOST>/<WEBHOOK_PATH>" {
		t.Fatalf("unexpected masked delivery target: %q", delivery.Target)
	}
	if delivery.Error != "notification delivery error redacted" {
		t.Fatalf("unexpected sanitized delivery error: %q", delivery.Error)
	}
	deliveries, err := s.ListNotificationDeliveries(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 1 {
		t.Fatalf("unexpected deliveries: %#v", deliveries)
	}
	listBody, err := json.Marshal(deliveries)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"private-token", "raw-secret-token", "upstream-secret-token", "password@camera", "nested-secret-token", "discord.com/api/webhooks"} {
		if strings.Contains(string(listBody), raw) {
			t.Fatalf("raw delivery secret leaked in delivery list: %s", listBody)
		}
	}
}

func TestMemoryStoreMasksNotificationChannelWebhookPath(t *testing.T) {
	s := NewMemoryStore()
	channel, err := s.CreateNotificationChannel(t.Context(), NotificationChannel{
		Name:       "main",
		Type:       "generic",
		Enabled:    true,
		WebhookURL: "https://example.com/webhook/private-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	if channel.MaskedWebhookURL != "https://<WEBHOOK_HOST>/<WEBHOOK_PATH>" {
		t.Fatalf("unexpected masked URL: %q", channel.MaskedWebhookURL)
	}
	body, err := json.Marshal(channel)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "private-token") || strings.Contains(string(body), `"webhook_url"`) {
		t.Fatalf("raw webhook URL leaked in JSON: %s", body)
	}
}

func TestNotificationChannelJSONOmitsEmailOperationalSecrets(t *testing.T) {
	s := NewMemoryStore()
	channel, err := s.CreateNotificationChannel(t.Context(), NotificationChannel{
		Name:            "email ops",
		Type:            "email",
		Enabled:         true,
		EmailRecipients: []string{"ops@example.com"},
		SMTPHost:        "smtp.example.com",
		SMTPPort:        587,
		SMTPTLS:         true,
		SMTPFrom:        "autostream@example.com",
		SMTPUsername:    "autostream-user",
		SMTPPassword:    "raw-smtp-password",
		SeverityFilter:  []string{"critical"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(channel)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"ops@example.com",
		"smtp.example.com",
		"autostream@example.com",
		"autostream-user",
		"raw-smtp-password",
		`"email_recipients"`,
		`"smtp_host"`,
		`"smtp_from"`,
		`"smtp_username"`,
		`"smtp_password"`,
	} {
		if strings.Contains(string(body), raw) {
			t.Fatalf("raw email notification channel detail leaked in JSON: %s", body)
		}
	}
	for _, want := range []string{`"smtp_password_configured":true`, `"masked_email_target":"o***s@\u003cEMAIL_DOMAIN\u003e"`} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("expected public email channel marker %s in JSON: %s", want, body)
		}
	}
}

func TestMemoryStoreRemediationActions(t *testing.T) {
	s := NewMemoryStore()
	action, err := s.CreateRemediationAction(t.Context(), RemediationAction{IncidentID: "inc-1", Action: "retry_gdrive_upload", Mode: "suggest_only", SafeAuto: true})
	if err != nil {
		t.Fatal(err)
	}
	if action.ID == "" || action.Status != "suggested" {
		t.Fatalf("unexpected action: %#v", action)
	}
	action.Status = "executed"
	action.Result = "recorded_noop"
	updated, err := s.UpdateRemediationAction(t.Context(), action)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != "executed" {
		t.Fatalf("unexpected updated action: %#v", updated)
	}
	actions, err := s.ListRemediationActions(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 {
		t.Fatalf("unexpected actions: %#v", actions)
	}
}
