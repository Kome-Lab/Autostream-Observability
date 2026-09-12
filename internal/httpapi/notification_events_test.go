package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/autostream-observability/internal/auth"
	"github.com/example/autostream-observability/internal/notifications"
	"github.com/example/autostream-observability/internal/store"
)

func TestCreateNotificationEventAcceptsExactControlPanelPayload(t *testing.T) {
	st := store.NewMemoryStore()
	notifier := &eventRecordingNotifier{}
	handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", st, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), notifier, nil)
	req := httptest.NewRequest(http.MethodPost, "/notification-events", bytes.NewBufferString(`{"event_type":"admin.audit","severity":"info","status":"success","action":"oauth_accounts.update","service_id":"control-panel","resource_type":"oauth_account","resource_id":"acct-01","actor_username":"ops","summary":"OAuth connected account updated","details":"OAuth account was updated successfully.","timestamp":"2026-07-18T01:32:00Z"}`))
	req.Header.Set("Authorization", "Bearer admin-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusAccepted {
		t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
	}
	if len(notifier.events) != 1 || notifier.events[0] != "admin.audit" {
		t.Fatalf("unexpected event notifier calls: %#v", notifier.events)
	}
	if len(notifier.incidents) != 1 {
		t.Fatalf("notification incident was not recorded: %#v", notifier.incidents)
	}
	notificationIncident := notifier.incidents[0]
	if notificationIncident.SummaryJA != "OAuth接続アカウントを更新\n対象: OAuth接続アカウント (acct-01)\n実行者: ops\n詳細: OAuth connected account updated" {
		t.Fatalf("admin audit summary is not readable: %q", notificationIncident.SummaryJA)
	}
	if notificationIncident.SourceSummary != "OAuth connected account updated / oauth_account acct-01 / actor=ops" {
		t.Fatalf("admin audit source summary was not preserved: %q", notificationIncident.SourceSummary)
	}
	if notificationIncident.ServiceID != "control-panel" || notificationIncident.NotificationDetails != "OAuth account was updated successfully." || notificationIncident.NotificationActor != "ops" {
		t.Fatalf("admin audit structured notification context was not preserved: %#v", notificationIncident)
	}
	if notificationIncident.UpdatedAt.Format(time.RFC3339) != "2026-07-18T01:32:00Z" {
		t.Fatalf("admin audit occurrence timestamp was lost: %s", notificationIncident.UpdatedAt)
	}
	deliveries, err := st.ListNotificationDeliveries(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 1 {
		t.Fatalf("expected one saved delivery, got %#v", deliveries)
	}
	delivery := deliveries[0]
	if delivery.EventType != "admin.audit" || delivery.IncidentID != "" || delivery.Status != "success" {
		t.Fatalf("unexpected saved delivery: %#v", delivery)
	}
	if delivery.Metadata["severity"] != "info" || delivery.Metadata["action"] != "oauth_accounts.update" || delivery.Metadata["rule"] != "oauth_accounts.update" || delivery.Metadata["summary"] != notificationIncident.SummaryJA || delivery.Metadata["occurred_at"] != "2026-07-18T01:32:00Z" {
		t.Fatalf("unexpected delivery metadata: %#v", delivery.Metadata)
	}
	if strings.Contains(res.Body.String(), "acct-01") || strings.Contains(res.Body.String(), "ops") {
		t.Fatalf("notification event response should only include sanitized delivery results: %s", res.Body.String())
	}
}

func TestCreateNotificationEventCoalescesDuplicateSemanticEventsAndKeepsLifecycleTransitions(t *testing.T) {
	st := store.NewMemoryStore()
	notifier := &eventRecordingNotifier{}
	handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", st, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), notifier, nil)

	request := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/notification-events", bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer admin-token")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		return res
	}

	duplicate := `{"event_type":"diagnostic.created","severity":"warning","status":"open","action":"worker_event_send_failed","service_id":"worker-stk-skylab-01","resource_type":"stream","resource_id":"stream-01","summary":"Worker event delivery failed","details":"The same event was retried."}`
	first := request(duplicate)
	if first.Code != http.StatusAccepted {
		t.Fatalf("first event status = %d body = %s", first.Code, first.Body.String())
	}
	second := request(duplicate)
	if second.Code != http.StatusAccepted {
		t.Fatalf("duplicate event status = %d body = %s", second.Code, second.Body.String())
	}
	if len(notifier.events) != 1 || notifier.events[0] != "diagnostic.created" {
		t.Fatalf("duplicate semantic event should not notify twice: %#v", notifier.events)
	}
	if !strings.Contains(second.Body.String(), `"status":"suppressed"`) {
		t.Fatalf("duplicate event should report coalescing: %s", second.Body.String())
	}

	resolved := request(`{"event_type":"incident.resolved","severity":"warning","status":"resolved","action":"worker_event_send_failed","service_id":"worker-stk-skylab-01","resource_type":"stream","resource_id":"stream-01","summary":"Worker event delivery recovered"}`)
	if resolved.Code != http.StatusAccepted {
		t.Fatalf("resolved transition status = %d body = %s", resolved.Code, resolved.Body.String())
	}
	if len(notifier.events) != 2 || notifier.events[1] != "incident.resolved" {
		t.Fatalf("distinct lifecycle transition must still notify: %#v", notifier.events)
	}

	deliveries, err := st.ListNotificationDeliveries(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 3 {
		t.Fatalf("expected delivered, coalesced-audit, and resolved records: %#v", deliveries)
	}
	var suppressed store.NotificationDelivery
	for _, delivery := range deliveries {
		if delivery.Status == "suppressed" {
			suppressed = delivery
			break
		}
	}
	if suppressed.EventType != "diagnostic.created" || suppressed.Metadata["suppression_reason"] != "duplicate_semantic_event" {
		t.Fatalf("duplicate coalescing must remain auditable: %#v", suppressed)
	}
}

func TestCreateNotificationEventRetriesPartialDeliveryWithoutSuppressingDiscordFailure(t *testing.T) {
	st := store.NewMemoryStore()
	emailRelay := &fakeEmailRelay{}
	if _, err := st.CreateNotificationChannel(t.Context(), store.NotificationChannel{
		Name:             "ops email",
		Type:             "email",
		Enabled:          true,
		UseGlobalSMTP:    true,
		UseGlobalSMTPSet: true,
		EmailRecipients:  []string{"ops@example.com"},
		SeverityFilter:   []string{"warning"},
		EventTypeFilter:  []string{"diagnostic.created"},
	}); err != nil {
		t.Fatal(err)
	}
	var discordCalls int
	discord := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		discordCalls++
		if discordCalls == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer discord.Close()
	if _, err := st.CreateNotificationChannel(t.Context(), store.NotificationChannel{
		Name:            "ops discord",
		Type:            "discord",
		Enabled:         true,
		WebhookURL:      discord.URL + "/api/webhooks/id/secret-token",
		SeverityFilter:  []string{"warning"},
		EventTypeFilter: []string{"diagnostic.created"},
	}); err != nil {
		t.Fatal(err)
	}
	notifier := notifications.ChannelNotifier{Store: st, EmailRelay: emailRelay, Timeout: time.Second, EmailTimeout: time.Second, RetryMax: 0, HTTP: discord.Client(), AllowPrivate: true}
	handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", st, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), notifier, nil)

	request := func() *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/notification-events", bytes.NewBufferString(`{"event_type":"diagnostic.created","severity":"warning","status":"open","action":"worker_event_send_failed","service_id":"worker-stk-skylab-01","resource_type":"stream","resource_id":"stream-01","summary":"Worker event delivery failed"}`))
		req.Header.Set("Authorization", "Bearer admin-token")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		return res
	}

	if first := request(); first.Code != http.StatusAccepted {
		t.Fatalf("first event status = %d body = %s", first.Code, first.Body.String())
	}
	second := request()
	if second.Code != http.StatusAccepted {
		t.Fatalf("retry event status = %d body = %s", second.Code, second.Body.String())
	}
	if strings.Contains(second.Body.String(), `"status":"suppressed"`) {
		t.Fatalf("failed Discord delivery was incorrectly coalesced: %s", second.Body.String())
	}
	if emailRelay.calls != 1 {
		t.Fatalf("successful email was retried %d times, want 1", emailRelay.calls)
	}
	if discordCalls != 2 {
		t.Fatalf("Discord attempts = %d, want 2", discordCalls)
	}

	deliveries, err := st.ListNotificationDeliveries(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 3 {
		t.Fatalf("expected one email and two Discord delivery records, got %#v", deliveries)
	}
	discordStatuses := map[string]int{}
	for _, delivery := range deliveries {
		if delivery.Channel == "discord" {
			discordStatuses[delivery.Status]++
		}
	}
	if discordStatuses["failure"] != 1 || discordStatuses["success"] != 1 {
		t.Fatalf("Discord must be retried after its partial failure: %#v", deliveries)
	}
}

func TestNotificationIncidentPreservesSafeResourceTypeAndValidatesTimestamp(t *testing.T) {
	for _, timestamp := range []string{"2026-07-18T10:32:00+09:00", "2026-07-18T01:32:00.123Z"} {
		incident, err := notificationIncidentFromRequest(notificationEventRequest{
			EventType:    "admin.audit",
			Severity:     "warning",
			Status:       "success",
			Action:       "secrets.update",
			ResourceType: "secret",
			ResourceID:   "DISCORD_BOT_TOKEN",
			Timestamp:    timestamp,
		}, "observability")
		if err != nil {
			t.Fatalf("valid timestamp %q was rejected: %v", timestamp, err)
		}
		if !strings.Contains(incident.SummaryJA, "対象: シークレット") {
			t.Fatalf("safe secret resource type was removed: %q", incident.SummaryJA)
		}
		if incident.ServiceID != "control-panel" {
			t.Fatalf("admin audit fallback service must identify the producer: %q", incident.ServiceID)
		}
		if incident.UpdatedAt.IsZero() {
			t.Fatalf("valid timestamp %q was lost", timestamp)
		}
	}
	legacySecretSummary := "管理イベント: secrets.update / success"
	incident, err := notificationIncidentFromRequest(notificationEventRequest{
		EventType: "admin.audit",
		Status:    "success",
		Action:    "secrets.update",
		Summary:   legacySecretSummary,
	}, "observability")
	if err != nil {
		t.Fatal(err)
	}
	if incident.SourceSummary != legacySecretSummary {
		t.Fatalf("validated legacy admin summary was not preserved: %q", incident.SourceSummary)
	}

	if _, err := notificationIncidentFromRequest(notificationEventRequest{
		EventType: "admin.audit",
		Status:    "success",
		Action:    "streams.start",
		Timestamp: "18 July 2026 10:32 JST",
	}, "observability"); err == nil {
		t.Fatal("invalid notification timestamp was accepted")
	}
}

func TestCreateNotificationEventRejectsInvalidTimestamp(t *testing.T) {
	st := store.NewMemoryStore()
	notifier := &eventRecordingNotifier{}
	handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", st, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), notifier, nil)
	req := httptest.NewRequest(http.MethodPost, "/notification-events", bytes.NewBufferString(`{"event_type":"admin.audit","severity":"info","status":"success","action":"streams.start","timestamp":"not-rfc3339"}`))
	req.Header.Set("Authorization", "Bearer admin-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "invalid_notification_event") {
		t.Fatalf("invalid timestamp status = %d body = %s", res.Code, res.Body.String())
	}
	if len(notifier.events) != 0 {
		t.Fatalf("invalid timestamp must not send a notification: %#v", notifier.events)
	}
}

func TestCreateNotificationEventValidatesKnownEventType(t *testing.T) {
	for _, eventType := range []string{
		"incident.opened",
		"incident.updated",
		"incident.resolved",
		"diagnostic.created",
		"remediation.pending_approval",
		"remediation.executed",
		"admin.audit",
	} {
		if !validNotificationEventType(eventType) {
			t.Fatalf("known event type rejected: %q", eventType)
		}
	}

	st := store.NewMemoryStore()
	notifier := &eventRecordingNotifier{}
	handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", st, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), notifier, nil)
	req := httptest.NewRequest(http.MethodPost, "/notification-events", bytes.NewBufferString(`{"event_type":"admin.audit.typo","severity":"info","status":"success","action":"oauth_accounts.update"}`))
	req.Header.Set("Authorization", "Bearer admin-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "invalid_notification_event") {
		t.Fatalf("unknown event type status = %d body = %s", res.Code, res.Body.String())
	}
	if len(notifier.events) != 0 {
		t.Fatalf("unknown event type should not notify: %#v", notifier.events)
	}
}

func TestCreateNotificationEventUsesStrictAuditActionIdentifier(t *testing.T) {
	valid := []string{
		"secrets.update",
		"users.reset_password",
		"nodes.configure_token.rotate",
		"nodes.registration_token.create",
		"nodes.runtime_token.rotate",
	}
	for _, action := range valid {
		t.Run("valid_"+strings.ReplaceAll(action, ".", "_"), func(t *testing.T) {
			st := store.NewMemoryStore()
			notifier := &eventRecordingNotifier{}
			handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", st, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), notifier, nil)
			body, err := json.Marshal(notificationEventRequest{EventType: "admin.audit", Severity: "info", Status: "success", Action: action})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/notification-events", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer admin-token")
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != http.StatusAccepted || len(notifier.events) != 1 {
				t.Fatalf("valid action %q status = %d body = %s events=%#v", action, res.Code, res.Body.String(), notifier.events)
			}
		})
	}

	invalid := []string{
		"raw-secret-token",
		"secrets..update",
		".secrets.update",
		"secrets.update.",
		strings.Repeat("a", 129),
	}
	for index, action := range invalid {
		t.Run("invalid_"+strconv.Itoa(index), func(t *testing.T) {
			st := store.NewMemoryStore()
			notifier := &eventRecordingNotifier{}
			handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", st, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), notifier, nil)
			body, err := json.Marshal(notificationEventRequest{EventType: "admin.audit", Severity: "info", Status: "success", Action: action})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/notification-events", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer admin-token")
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "invalid_notification_event") {
				t.Fatalf("invalid action status = %d body = %s", res.Code, res.Body.String())
			}
			if len(notifier.events) != 0 {
				t.Fatalf("invalid action should not notify: %#v", notifier.events)
			}
			if strings.Contains(res.Body.String(), action) {
				t.Fatalf("invalid action leaked in response: %s", res.Body.String())
			}
		})
	}
}

func TestCreateNotificationEventAdminAuditFansOutToAllEnabledChannelsAndSavesDeliveries(t *testing.T) {
	var callsMu sync.Mutex
	calls := map[string]int{}
	webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callsMu.Lock()
		calls[r.URL.Path]++
		callsMu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer webhookServer.Close()

	st := store.NewMemoryStore()
	channels := []store.NotificationChannel{
		{Name: "critical opened", Type: "generic", Enabled: true, WebhookURL: webhookServer.URL + "/critical-opened", SeverityFilter: []string{"critical"}, EventTypeFilter: []string{"incident.opened"}},
		{Name: "warning resolved", Type: "generic", Enabled: true, WebhookURL: webhookServer.URL + "/warning-resolved", SeverityFilter: []string{"warning"}, EventTypeFilter: []string{"incident.resolved"}},
		{Name: "disabled audit", Type: "generic", Enabled: false, WebhookURL: webhookServer.URL + "/disabled", SeverityFilter: []string{"info"}, EventTypeFilter: []string{"admin.audit"}},
	}
	for _, channel := range channels {
		if _, err := st.CreateNotificationChannel(t.Context(), channel); err != nil {
			t.Fatal(err)
		}
	}
	notifier := notifications.ChannelNotifier{Store: st, Timeout: time.Second, AllowPrivate: true}
	handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", st, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), notifier, nil)
	req := httptest.NewRequest(http.MethodPost, "/notification-events", bytes.NewBufferString(`{"event_type":"admin.audit","severity":"info","status":"success","action":"nodes.runtime_token.rotate","resource_type":"node","resource_id":"node-01","actor_username":"ops","summary":"Node runtime token rotated","timestamp":"2026-07-18T01:32:00Z"}`))
	req.Header.Set("Authorization", "Bearer admin-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusAccepted {
		t.Fatalf("status = %d body = %s", res.Code, res.Body.String())
	}

	callsMu.Lock()
	gotCalls := map[string]int{}
	for path, count := range calls {
		gotCalls[path] = count
	}
	callsMu.Unlock()
	if gotCalls["/critical-opened"] != 1 || gotCalls["/warning-resolved"] != 1 || gotCalls["/disabled"] != 0 {
		t.Fatalf("unexpected admin audit fanout: %#v", gotCalls)
	}
	deliveries, err := st.ListNotificationDeliveries(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 2 {
		t.Fatalf("expected two saved deliveries, got %#v", deliveries)
	}
	for _, delivery := range deliveries {
		if delivery.EventType != "admin.audit" || delivery.IncidentID != "" || delivery.Status != "success" || delivery.Metadata["rule"] != "nodes.runtime_token.rotate" {
			t.Fatalf("unexpected saved admin audit delivery: %#v", delivery)
		}
	}
}
