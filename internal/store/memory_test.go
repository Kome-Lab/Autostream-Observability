package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
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

func TestMemoryIncidentHistoryUsesStableCursor(t *testing.T) {
	st := NewMemoryStore()
	newest := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	st.incidents = map[string]Incident{
		"inc-c": {ID: "inc-c", Rule: "c", UpdatedAt: newest},
		"inc-b": {ID: "inc-b", Rule: "b", UpdatedAt: newest},
		"inc-a": {ID: "inc-a", Rule: "a", UpdatedAt: newest.Add(-time.Second)},
	}

	first, err := st.ListIncidentHistory(t.Context(), 2, time.Time{}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || first[0].ID != "inc-c" || first[1].ID != "inc-b" {
		t.Fatalf("unexpected first incident page: %#v", first)
	}
	second, err := st.ListIncidentHistory(t.Context(), 2, first[1].UpdatedAt, first[1].ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 || second[0].ID != "inc-a" {
		t.Fatalf("unexpected second incident page: %#v", second)
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

func TestMemoryStorePreservesResolvedIncidentWhenSameProblemRecurs(t *testing.T) {
	s := NewMemoryStore()
	first, created, err := s.UpsertIncident(t.Context(), Incident{Rule: "encoder_process_exited", Severity: "critical", ServiceID: "enc-01", StreamID: "stream-01", SignalID: "sig-1"})
	if err != nil || !created {
		t.Fatalf("create first incident: created=%v err=%v", created, err)
	}
	if _, err := s.UpdateIncidentStatus(t.Context(), first.ID, "resolved"); err != nil {
		t.Fatal(err)
	}
	second, created, err := s.UpsertIncident(t.Context(), Incident{Rule: "encoder_process_exited", Severity: "critical", ServiceID: "enc-01", StreamID: "stream-01", SignalID: "sig-2"})
	if err != nil || !created {
		t.Fatalf("create recurring incident: created=%v err=%v", created, err)
	}
	if second.ID == first.ID {
		t.Fatalf("recurrence reused terminal incident id %q", first.ID)
	}
	incidents, err := s.ListIncidents(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(incidents) != 2 {
		t.Fatalf("resolved incident history was overwritten: %#v", incidents)
	}
}

func TestMemoryStoreRejectsTerminalIncidentRollback(t *testing.T) {
	s := NewMemoryStore()
	incident, _, err := s.UpsertIncident(t.Context(), Incident{Rule: "encoder_process_exited", Severity: "critical", ServiceID: "enc-01", SignalID: "sig-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateIncidentStatus(t.Context(), incident.ID, "resolved"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateIncidentStatus(t.Context(), incident.ID, "acknowledged"); err != ErrInvalidTransition {
		t.Fatalf("terminal incident rollback error = %v, want %v", err, ErrInvalidTransition)
	}
}

func TestMemoryStoreAutoResolvesMatchingActiveIncident(t *testing.T) {
	s := NewMemoryStore()
	incident, _, err := s.UpsertIncident(t.Context(), Incident{Rule: "discord_audio_forward_failed", Severity: "error", ServiceID: "bot-01", StreamID: "stream-01", SignalID: "sig-failed"})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := s.ResolveActiveIncidents(t.Context(), []string{"discord_audio_forward_failed"}, "bot-01", "stream-01", "sig-recovered", "recent_forward_succeeded")
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 1 || resolved[0].ID != incident.ID || resolved[0].Status != "resolved" || resolved[0].ResolvedAt == nil {
		t.Fatalf("unexpected auto-resolved incidents: %#v", resolved)
	}
	if resolved[0].ResolvedBySignalID != "sig-recovered" || resolved[0].ResolutionReason != "recent_forward_succeeded" {
		t.Fatalf("recovery provenance was not retained: %#v", resolved[0])
	}
}

func TestMemoryStoreRepeatedTerminalStatusPreservesRecoveryProvenance(t *testing.T) {
	s := NewMemoryStore()
	incident, _, err := s.UpsertIncident(t.Context(), Incident{Rule: "discord_audio_forward_failed", Severity: "error", ServiceID: "bot-01", StreamID: "stream-01", SignalID: "sig-failed"})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := s.ResolveActiveIncidents(t.Context(), []string{incident.Rule}, incident.ServiceID, incident.StreamID, "sig-recovered", "recent_forward_succeeded")
	if err != nil || len(resolved) != 1 {
		t.Fatalf("auto resolve: resolved=%#v err=%v", resolved, err)
	}
	repeated, err := s.UpdateIncidentStatus(t.Context(), incident.ID, "resolved")
	if err != nil {
		t.Fatal(err)
	}
	if repeated.ResolvedBySignalID != "sig-recovered" || repeated.ResolutionReason != "recent_forward_succeeded" {
		t.Fatalf("idempotent terminal update overwrote recovery provenance: %#v", repeated)
	}
}

func TestMemoryStoreEscalatesActiveIncidentSeverityWithoutReplacingHistory(t *testing.T) {
	s := NewMemoryStore()
	first, created, err := s.UpsertIncident(t.Context(), Incident{Rule: "discord_audio_forward_failed", Severity: "warning", ServiceID: "bot-01", StreamID: "stream-01", SignalID: "sig-warning"})
	if err != nil || !created {
		t.Fatalf("create warning incident: created=%v err=%v", created, err)
	}
	escalated, created, err := s.UpsertIncident(t.Context(), Incident{Rule: first.Rule, Severity: "error", ServiceID: first.ServiceID, StreamID: first.StreamID, SignalID: "sig-error"})
	if err != nil || created {
		t.Fatalf("escalate active incident: created=%v err=%v", created, err)
	}
	if escalated.ID != first.ID || escalated.Severity != "error" || !escalated.SeverityChanged {
		t.Fatalf("active incident did not escalate in place: %#v", escalated)
	}
	downgraded, created, err := s.UpsertIncident(t.Context(), Incident{Rule: first.Rule, Severity: "warning", ServiceID: first.ServiceID, StreamID: first.StreamID, SignalID: "sig-warning-again"})
	if err != nil || created {
		t.Fatalf("repeat lower severity incident: created=%v err=%v", created, err)
	}
	if downgraded.Severity != "error" || downgraded.SeverityChanged {
		t.Fatalf("active incident severity was downgraded or spuriously marked changed: %#v", downgraded)
	}
}

func TestMemoryStoreListsMetricHistoryWithinRange(t *testing.T) {
	s := NewMemoryStore()
	now := time.Now().UTC()
	for index, at := range []time.Time{now.Add(-20 * time.Minute), now.Add(-10 * time.Minute), now.Add(-time.Minute)} {
		value := float64(index + 1)
		if _, err := s.SaveSignal(t.Context(), Signal{Type: "metric", Name: "worker.cpu_percent", ServiceID: "worker-01", ServiceType: "worker", Value: &value, Timestamp: at}); err != nil {
			t.Fatal(err)
		}
	}
	metrics, err := s.ListMetricSnapshots(t.Context(), MetricQuery{Since: now.Add(-15 * time.Minute), MaxPointsPerSeries: 360})
	if err != nil {
		t.Fatal(err)
	}
	if len(metrics) != 2 || metrics[0].UpdatedAt.Before(now.Add(-15*time.Minute)) {
		t.Fatalf("metric range was not applied: %#v", metrics)
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

func TestMemoryStorePreservesValidatedAdminAuditActionIdentifiers(t *testing.T) {
	s := NewMemoryStore()
	delivery, err := s.SaveNotificationDelivery(t.Context(), NotificationDelivery{
		EventType: "admin.audit",
		Channel:   "discord",
		Status:    "success",
		Metadata: map[string]any{
			"action":  "secrets.update",
			"rule":    "secrets.update",
			"summary": "シークレットを更新\n実行者: ops",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if delivery.Metadata["action"] != "secrets.update" || delivery.Metadata["rule"] != "secrets.update" {
		t.Fatalf("validated admin audit action was redacted: %#v", delivery.Metadata)
	}
	if delivery.Metadata["summary"] != "シークレットを更新\n実行者: ops" {
		t.Fatalf("safe admin audit summary was redacted: %#v", delivery.Metadata)
	}

	unsafe, err := s.SaveNotificationDelivery(t.Context(), NotificationDelivery{
		EventType: "admin.audit",
		Channel:   "discord",
		Status:    "success",
		Metadata: map[string]any{
			"action":  "raw.secret.token",
			"rule":    "secrets.ast_svc_raw_token",
			"summary": "<redacted> / opaque-value-that-must-not-survive",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if unsafe.Metadata["action"] != "<redacted>" || unsafe.Metadata["rule"] != "<redacted>" {
		t.Fatalf("invalid secret-like action identifier was retained: %#v", unsafe.Metadata)
	}
	if unsafe.Metadata["summary"] != "<redacted>" {
		t.Fatalf("compound redaction marker bypassed secret filtering: %#v", unsafe.Metadata)
	}
	unsafeBody, err := json.Marshal(unsafe)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"raw.secret.token", "ast_svc_raw_token", "opaque-value-that-must-not-survive"} {
		if strings.Contains(string(unsafeBody), raw) {
			t.Fatalf("secret-like admin audit metadata was retained: %s", unsafeBody)
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

func TestMemoryStoreInfersGlobalSMTPAndClearsLegacyConfigOnUpdate(t *testing.T) {
	s := NewMemoryStore()
	global, err := s.CreateNotificationChannel(t.Context(), NotificationChannel{
		Name:            "global email",
		Type:            "email",
		Enabled:         true,
		EmailRecipients: []string{"ops@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !global.UseGlobalSMTP || global.SMTPPort != 0 {
		t.Fatalf("email channel without legacy SMTP must use global settings: %#v", global)
	}

	legacy, err := s.CreateNotificationChannel(t.Context(), NotificationChannel{
		Name:            "legacy email",
		Type:            "email",
		Enabled:         true,
		EmailRecipients: []string{"legacy@example.com"},
		SMTPHost:        "smtp.example.com",
		SMTPPort:        587,
		SMTPTLS:         true,
		SMTPFrom:        "autostream@example.com",
		SMTPUsername:    "autostream",
		SMTPPassword:    "raw-smtp-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.UseGlobalSMTP {
		t.Fatalf("legacy SMTP channel unexpectedly switched to global: %#v", legacy)
	}
	updated, err := s.UpdateNotificationChannel(t.Context(), NotificationChannel{
		ID:               legacy.ID,
		Name:             legacy.Name,
		Type:             "email",
		Enabled:          true,
		UseGlobalSMTP:    true,
		UseGlobalSMTPSet: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !updated.UseGlobalSMTP || updated.SMTPHost != "" || updated.SMTPPort != 0 || updated.SMTPFrom != "" || updated.SMTPUsername != "" || updated.SMTPPassword != "" || updated.SMTPPasswordConfigured {
		t.Fatalf("global SMTP update retained legacy secrets: %#v", updated)
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
