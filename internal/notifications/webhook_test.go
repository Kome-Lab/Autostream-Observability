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
	results, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "inc-1", Rule: "encoder_process_exited", Severity: "critical", Status: "open", SummaryJA: "Encoder process stopped. @everyone <@123>", ServiceID: "enc-01", StreamID: "stream-01"})
	if err != nil {
		t.Fatal(err)
	}
	result := results[0]
	if result.Status != "success" || strings.Contains(result.Target, "token") {
		t.Fatalf("unexpected result: %#v", result)
	}
	embeds, ok := got["embeds"].([]any)
	if !ok || len(embeds) != 1 {
		t.Fatalf("unexpected payload: %#v", got)
	}
	embed, ok := embeds[0].(map[string]any)
	if !ok || embed["title"] != "インシデント発生: encoder_process_exited" || !strings.Contains(embed["description"].(string), "Encoder process stopped") {
		t.Fatalf("Discord payload is missing its structured embed: %#v", got)
	}
	fields, ok := embed["fields"].([]any)
	if !ok || len(fields) < 4 {
		t.Fatalf("Discord embed is missing notification fields: %#v", embed)
	}
	if _, hasContent := got["content"]; hasContent {
		t.Fatalf("Discord payload must use an embed instead of a plain content message: %#v", got)
	}
	allowedMentions, ok := got["allowed_mentions"].(map[string]any)
	if !ok {
		t.Fatalf("Discord payload is missing allowed_mentions: %#v", got)
	}
	parse, ok := allowedMentions["parse"].([]any)
	if !ok || len(parse) != 0 {
		t.Fatalf("Discord payload must disable all automatic mentions: %#v", got)
	}
}

func TestSlackWebhookPayloadEscapesMentionsAndMarkup(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	notifier := WebhookNotifier{Type: "slack", URL: server.URL + "/services/id/token", Timeout: time.Second, AllowPrivate: true}
	_, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "inc-1", Rule: "auth.login", Severity: "warning", Status: "failure", SummaryJA: "A&B <!channel> <@U123>", ServiceID: "control-panel"})
	if err != nil {
		t.Fatal(err)
	}
	text, ok := got["text"].(string)
	if !ok || !strings.Contains(text, "A&amp;B &lt;!channel&gt; &lt;@U123&gt;") {
		t.Fatalf("Slack payload did not escape mentions and markup: %#v", got)
	}
	if strings.Contains(text, "<!channel>") || strings.Contains(text, "<@U123>") {
		t.Fatalf("Slack payload retained active mention syntax: %#v", got)
	}
	blocks, ok := got["blocks"].([]any)
	if !ok || len(blocks) < 3 {
		t.Fatalf("Slack payload is missing Block Kit content: %#v", got)
	}
	header, ok := blocks[0].(map[string]any)
	if !ok || header["type"] != "header" {
		t.Fatalf("Slack payload is missing its structured header: %#v", got)
	}
}

func TestAdminAuditNotificationUsesSpecificStructuredTitleAndContext(t *testing.T) {
	occurredAt := time.Date(2026, 7, 18, 1, 32, 0, 0, time.UTC)
	incident := store.Incident{
		Rule:      "secrets.update",
		Severity:  "warning",
		Status:    "success",
		SummaryJA: "シークレットを更新\n対象: secret\n実行者: ops",
		ServiceID: "observability",
		UpdatedAt: occurredAt,
	}
	payload := (WebhookNotifier{Type: "discord"}).payload("admin.audit", incident)
	embeds, ok := payload["embeds"].([]map[string]any)
	if !ok || len(embeds) != 1 {
		t.Fatalf("admin audit Discord payload is missing an embed: %#v", payload)
	}
	embed := embeds[0]
	if embed["title"] != "シークレットを更新" || embed["timestamp"] != occurredAt.Format(time.RFC3339) {
		t.Fatalf("admin audit embed title or timestamp is unclear: %#v", embed)
	}
	description, _ := embed["description"].(string)
	if !strings.Contains(description, "対象: secret") || !strings.Contains(description, "実行者: ops") {
		t.Fatalf("admin audit embed lost its operation context: %#v", embed)
	}
	if subject := formatEmailSubject("admin.audit", incident); subject != "[AutoStream] WARNING secrets.update | シークレットを更新" {
		t.Fatalf("admin audit email subject = %q", subject)
	}
	message := formatEmailMessage("admin.audit", incident, "autostream@example.jp", []string{"ops@example.jp"})
	if !strings.Contains(message, "Subject: [AutoStream] WARNING secrets.update | =?UTF-8?") {
		t.Fatalf("admin audit email subject lost its stable ASCII prefix or MIME encoding: %s", message)
	}
	text := formatIncidentText("admin.audit", incident)
	for _, want := range []string{"シークレットを更新", "重要度: 警告", "結果: 成功", "操作コード: secrets.update", "対象: secret", "実行者: ops", occurredAt.Format(time.RFC3339)} {
		if !strings.Contains(text, want) {
			t.Fatalf("structured admin audit text is missing %q: %s", want, text)
		}
	}
}

func TestNotificationActionLabelsCoverControlPanelAuditVocabulary(t *testing.T) {
	actions := []string{
		"api_tokens.create",
		"app.settings.test_email",
		"archive.artifact.share.create",
		"auth.change_password",
		"auth.oauth.provision_user",
		"integrations.drive_destination.update",
		"integrations.oauth_account.connect",
		"integrations.oauth_provider.update",
		"mfa.recovery_codes.regenerate",
		"passkeys.registration.start",
		"security.settings.update",
		"services.runtime_config.preview",
		"streams.discord_youtube_notify",
		"streams.retry_upload",
		"streams.worker_event_test",
		"users.email_welcome",
		"users.force_password_change",
		"users.oauth_link.delete",
		"workers.unassign",
	}
	for _, action := range actions {
		if label := NotificationActionLabel(action); label == action || label == "" {
			t.Fatalf("control-panel audit action %q has no readable label", action)
		}
	}
}

func TestDiscordEmbedStaysWithinTotalCharacterLimit(t *testing.T) {
	incident := store.Incident{
		Rule:      strings.Repeat("r", 5000),
		Severity:  "critical",
		Status:    "open",
		SummaryJA: strings.Repeat("詳", 10000),
		ServiceID: strings.Repeat("s", 5000),
		StreamID:  strings.Repeat("t", 5000),
	}
	payload := (WebhookNotifier{Type: "discord"}).payload("incident.opened", incident)
	embeds, ok := payload["embeds"].([]map[string]any)
	if !ok || len(embeds) != 1 {
		t.Fatalf("Discord payload is missing an embed: %#v", payload)
	}
	if total := discordEmbedCharacterCount(embeds[0]); total > 6000 {
		t.Fatalf("Discord embed exceeds the 6000-character total limit: %d", total)
	}
}

func discordEmbedCharacterCount(embed map[string]any) int {
	total := 0
	for _, key := range []string{"title", "description"} {
		if value, ok := embed[key].(string); ok {
			total += len([]rune(value))
		}
	}
	if footer, ok := embed["footer"].(map[string]any); ok {
		if value, ok := footer["text"].(string); ok {
			total += len([]rune(value))
		}
	}
	if fields, ok := embed["fields"].([]map[string]any); ok {
		for _, field := range fields {
			for _, key := range []string{"name", "value"} {
				if value, ok := field[key].(string); ok {
					total += len([]rune(value))
				}
			}
		}
	}
	return total
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
	if _, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "inc-1", Rule: "gdrive_upload_failed", Severity: "error", Status: "open", SummaryJA: "Google Drive upload failed. A&B <raw>", ServiceID: "enc-01"}); err != nil {
		t.Fatal(err)
	}
	if got["event_type"] != "incident.opened" || got["rule"] != "gdrive_upload_failed" || got["summary"] != "Google Drive upload failed. A&B <raw>" {
		t.Fatalf("unexpected payload: %#v", got)
	}
}

func TestGenericWebhookPreservesAdminAuditSummaryContract(t *testing.T) {
	incident := store.Incident{
		Rule:          "integrations.oauth_account.update",
		Severity:      "info",
		Status:        "success",
		SummaryJA:     "OAuth接続アカウントを更新\n対象: OAuth接続アカウント (acct-01)\n実行者: ops",
		SourceSummary: "管理イベント: integrations.oauth_account.update / success / oauth_account acct-01 / actor=ops",
		ServiceID:     "observability",
	}
	payload := (WebhookNotifier{Type: "generic"}).payload("admin.audit", incident)
	if payload["summary"] != incident.SourceSummary {
		t.Fatalf("generic webhook source summary contract changed: %#v", payload)
	}
	if _, exists := payload["display_summary"]; exists {
		t.Fatalf("generic webhook payload shape changed: %#v", payload)
	}
	if len(payload) != 8 {
		t.Fatalf("generic webhook field set changed: %#v", payload)
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

func TestNormalizeDiscordWebhookURLAliases(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "canonical", raw: "https://discord.com/api/webhooks/id/token", want: "https://discord.com/api/webhooks/id/token"},
		{name: "www", raw: "https://www.discord.com/api/webhooks/id/token", want: "https://discord.com/api/webhooks/id/token"},
		{name: "ptb", raw: "https://ptb.discord.com/api/webhooks/id/token?wait=true", want: "https://discord.com/api/webhooks/id/token?wait=true"},
		{name: "canary", raw: "https://canary.discord.com/api/webhooks/id/token", want: "https://discord.com/api/webhooks/id/token"},
		{name: "legacy", raw: "https://discordapp.com/api/webhooks/id/token", want: "https://discord.com/api/webhooks/id/token"},
		{name: "legacy www", raw: "https://www.discordapp.com/api/webhooks/id/token", want: "https://discord.com/api/webhooks/id/token"},
		{name: "legacy ptb", raw: "https://ptb.discordapp.com/api/webhooks/id/token", want: "https://discord.com/api/webhooks/id/token"},
		{name: "legacy canary", raw: "https://canary.discordapp.com/api/webhooks/id/token", want: "https://discord.com/api/webhooks/id/token"},
		{name: "explicit default port", raw: "https://ptb.discord.com:443/api/webhooks/id/token", want: "https://discord.com/api/webhooks/id/token"},
		{name: "versioned API path", raw: "https://canary.discord.com/api/v10/webhooks/id/token?thread_id=123", want: "https://discord.com/api/v10/webhooks/id/token?thread_id=123"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeWebhookURLForTypeWithPolicy(tt.raw, "discord", false)
			if err != nil {
				t.Fatalf("normalize Discord webhook URL: %v", err)
			}
			if got != tt.want {
				t.Fatalf("normalized URL = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeDiscordWebhookURLRejectsDeceptiveOrInvalidTargets(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "deceptive suffix", raw: "https://discord.com.evil.example/api/webhooks/id/token"},
		{name: "unapproved subdomain", raw: "https://evil.discord.com/api/webhooks/id/token"},
		{name: "legacy deceptive suffix", raw: "https://discordapp.com.evil.example/api/webhooks/id/token"},
		{name: "non default port", raw: "https://discord.com:444/api/webhooks/id/token"},
		{name: "wrong path", raw: "https://discord.com/channels/id/token"},
		{name: "missing token", raw: "https://discord.com/api/webhooks/id"},
		{name: "extra path segment", raw: "https://discord.com/api/webhooks/id/token/extra"},
		{name: "invalid API version", raw: "https://discord.com/api/latest/webhooks/id/token"},
		{name: "fragment", raw: "https://discord.com/api/webhooks/id/token#secret"},
		{name: "HTTP", raw: "http://discord.com/api/webhooks/id/token"},
		{name: "userinfo", raw: "https://user@discord.com/api/webhooks/id/token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NormalizeWebhookURLForTypeWithPolicy(tt.raw, "discord", false); err == nil {
				t.Fatalf("expected Discord webhook URL to be rejected: %s", tt.raw)
			}
		})
	}
}

func TestDiscordWebhookNotifierCanonicalizesAliasBeforeSend(t *testing.T) {
	var gotURL string
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotURL = req.URL.String()
		return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody, Header: make(http.Header)}, nil
	})}
	notifier := WebhookNotifier{
		Type: "discord",
		URL:  "https://ptb.discord.com/api/webhooks/id/token?wait=true",
		HTTP: client,
	}
	results, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "inc-01", Severity: "info"})
	if err != nil {
		t.Fatal(err)
	}
	if gotURL != "https://discord.com/api/webhooks/id/token?wait=true" {
		t.Fatalf("request URL = %q", gotURL)
	}
	if len(results) != 1 || results[0].Target != "https://discord.com/<WEBHOOK_PATH>" {
		t.Fatalf("unexpected delivery result: %#v", results)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
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

func TestValidateSMTPChannelRejectsPartialLegacyCredentials(t *testing.T) {
	base := store.NotificationChannel{
		Type:            "email",
		EmailRecipients: []string{"ops@example.com"},
		SMTPHost:        "smtp.example.com",
		SMTPPort:        587,
		SMTPTLS:         true,
		SMTPFrom:        "autostream@example.com",
	}
	withUsernameOnly := base
	withUsernameOnly.SMTPUsername = "autostream"
	if err := ValidateSMTPChannelWithPolicy(withUsernameOnly, false); err == nil {
		t.Fatal("legacy SMTP username without password must be rejected")
	}
	withPasswordOnly := base
	withPasswordOnly.SMTPPassword = "raw-smtp-password"
	if err := ValidateSMTPChannelWithPolicy(withPasswordOnly, false); err == nil {
		t.Fatal("legacy SMTP password without username must be rejected")
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

type recordingEmailRelay struct {
	recipients []string
	subject    string
	text       string
	attempts   int
	err        error
}

func (r *recordingEmailRelay) SendNotificationEmail(_ context.Context, recipients []string, subject, text string) error {
	r.attempts++
	r.recipients = append([]string(nil), recipients...)
	r.subject = subject
	r.text = text
	return r.err
}

type codedEmailRelayError string

func (e codedEmailRelayError) Error() string            { return string(e) }
func (e codedEmailRelayError) SafeDeliveryCode() string { return string(e) }

func TestEmailNotifierUsesGlobalSMTPRelay(t *testing.T) {
	relay := &recordingEmailRelay{}
	notifier := EmailNotifier{
		Channel: store.NotificationChannel{
			Type:              "email",
			UseGlobalSMTP:     true,
			EmailRecipients:   []string{"ops@example.com"},
			MaskedEmailTarget: "o***s@<EMAIL_DOMAIN>",
		},
		Relay: relay,
	}
	results, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "inc-global", Rule: "encoder_down", Severity: "critical", Status: "open", SummaryJA: "Encoder process stopped.", ServiceID: "enc-01"})
	if err != nil {
		t.Fatal(err)
	}
	if relay.attempts != 1 || len(relay.recipients) != 1 || relay.recipients[0] != "ops@example.com" || relay.subject != "[AutoStream] CRITICAL encoder_down | インシデント発生: encoder_down" || !strings.Contains(relay.text, "Encoder process stopped.") {
		t.Fatalf("unexpected global email relay call: %#v", relay)
	}
	if len(results) != 1 || results[0].Status != "success" || results[0].Target != "o***s@<EMAIL_DOMAIN>" {
		t.Fatalf("unexpected result: %#v", results)
	}
}

func TestEmailNotifierReturnsOnlySafeGlobalSMTPFailureCodeWithoutRetry(t *testing.T) {
	for _, code := range []string{"smtp_auth_failed", "rate_limited"} {
		t.Run(code, func(t *testing.T) {
			relay := &recordingEmailRelay{err: codedEmailRelayError(code)}
			notifier := EmailNotifier{
				Channel: store.NotificationChannel{
					Type:              "email",
					UseGlobalSMTP:     true,
					EmailRecipients:   []string{"ops@example.com"},
					MaskedEmailTarget: "o***s@<EMAIL_DOMAIN>",
				},
				Relay:          relay,
				RetryMax:       3,
				RetryBaseDelay: time.Millisecond,
				Sleep: func(context.Context, time.Duration) error {
					return nil
				},
			}
			results, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "inc-global-failure", Rule: "encoder_down", Severity: "critical", Status: "open", SummaryJA: "Encoder process stopped.", ServiceID: "enc-01"})
			if err == nil || relay.attempts != 1 {
				t.Fatalf("expected a single relay attempt, attempts=%d err=%v", relay.attempts, err)
			}
			if len(results) != 1 || results[0].Status != "failure" || results[0].Error != code || strings.Contains(results[0].Error, "example.com") {
				t.Fatalf("unexpected safe failure result: %#v", results)
			}
		})
	}
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
	notifier := ChannelNotifier{Store: st, EmailRelay: relay, Timeout: time.Second}
	results, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "inc-channel", Rule: "encoder_down", Severity: "critical", Status: "open", SummaryJA: "Encoder stopped.", ServiceID: "enc-01"})
	if err != nil {
		t.Fatal(err)
	}
	if relay.attempts != 1 || len(results) != 1 || results[0].Status != "success" {
		t.Fatalf("global relay was not used: attempts=%d results=%#v", relay.attempts, results)
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
