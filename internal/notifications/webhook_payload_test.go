package notifications

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/example/autostream-observability/internal/diagnostics"
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
	if !ok || embed["title"] != "インシデント発生: Encoder process 停止" || !strings.Contains(embed["description"].(string), "Encoder process stopped") {
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
	fields, ok := embed["fields"].([]map[string]any)
	if !ok {
		t.Fatalf("admin audit embed fields have an unexpected shape: %#v", embed)
	}
	context := map[string]string{}
	for _, field := range fields {
		name, _ := field["name"].(string)
		value, _ := field["value"].(string)
		context[name] = value
	}
	if context["対象"] != "secret" || context["実行者"] != "ops" || context["サービス"] != "observability" {
		t.Fatalf("admin audit embed lost its structured operation context: %#v", embed)
	}
	if subject := formatEmailSubject("admin.audit", incident); subject != "[AutoStream] WARNING secrets.update | シークレットを更新" {
		t.Fatalf("admin audit email subject = %q", subject)
	}
	text := formatIncidentEmailText("admin.audit", incident)
	for _, want := range []string{"シークレットを更新", "重要度: 警告", "結果: 成功", "操作コード: シークレットを更新 (secrets.update)", "対象: secret", "実行者: ops", occurredAt.Format(time.RFC3339)} {
		if !strings.Contains(text, want) {
			t.Fatalf("structured admin audit text is missing %q: %s", want, text)
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
	if got["schema_version"] != float64(2) || got["title"] != "インシデント発生: Google Drive upload 失敗" || got["service_id"] != "enc-01" {
		t.Fatalf("generic webhook lost structured identity: %#v", got)
	}
	if got["details"] != "" || got["target"] != "" || got["actor"] != "" {
		t.Fatalf("generic webhook details are not normalized: %#v", got)
	}
}

func TestGenericWebhookCarriesDiagnosticDetailsWithoutRepeatingSummary(t *testing.T) {
	incident := store.Incident{
		ID:        "inc-1",
		Rule:      "encoder_process_exited",
		Severity:  "critical",
		Status:    "open",
		SummaryJA: "Encoder process stopped.",
		ServiceID: "enc-01",
		Report: diagnostics.Report{
			LikelyCause:        "FFmpeg exited unexpectedly",
			RecommendedActions: []string{"check encoder logs", "restart encoder"},
		},
	}
	payload := (WebhookNotifier{Type: "generic"}).payload("incident.opened", incident)
	if payload["summary"] != incident.SummaryJA {
		t.Fatalf("generic summary changed: %#v", payload)
	}
	details, ok := payload["details"].(string)
	if !ok || !strings.Contains(details, "原因候補: FFmpeg exited unexpectedly") {
		t.Fatalf("generic diagnostic details are incomplete: %#v", payload)
	}
	if strings.Contains(details, incident.SummaryJA) || strings.Contains(details, "check encoder logs") {
		t.Fatalf("generic details repeat summary or structured actions: %q", details)
	}
	actions, ok := payload["recommended_actions"].([]string)
	if !ok || len(actions) != 2 || actions[0] != "check encoder logs" {
		t.Fatalf("generic actions are not structured once: %#v", payload)
	}
}

func TestNotificationPresentationDoesNotRepeatActionsOrEvidence(t *testing.T) {
	incident := store.Incident{
		Rule:      "encoder_process_exited",
		Severity:  "critical",
		Status:    "open",
		SummaryJA: "Encoder process stopped.",
		ServiceID: "enc-01",
		Report: diagnostics.Report{
			LikelyCause:        "FFmpeg exited unexpectedly",
			RecommendedActions: []string{"check encoder logs"},
			Evidence:           []string{"signal_id=sig-01"},
		},
	}
	text := formatIncidentText("incident.opened", incident)
	if strings.Count(text, "check encoder logs") != 1 || strings.Count(text, "signal_id=sig-01") != 1 {
		t.Fatalf("plain notification repeated structured content: %s", text)
	}
	payload := (WebhookNotifier{Type: "generic"}).payload("incident.opened", incident)
	details, _ := payload["details"].(string)
	if strings.Contains(details, "check encoder logs") || strings.Contains(details, "signal_id=sig-01") {
		t.Fatalf("generic details duplicate structured lists: %#v", payload)
	}
}

func TestGenericWebhookPreservesAdminAuditSummaryContract(t *testing.T) {
	incident := store.Incident{
		Rule:                     "integrations.oauth_account.update",
		Severity:                 "info",
		Status:                   "success",
		SummaryJA:                "OAuth接続アカウントを更新\n対象: OAuth接続アカウント (acct-01)\n実行者: ops",
		SourceSummary:            "管理イベント: integrations.oauth_account.update / success / oauth_account acct-01 / actor=ops",
		ServiceID:                "observability",
		NotificationResourceType: "oauth_account",
		NotificationResourceID:   "acct-01",
		NotificationActor:        "ops",
		NotificationDetails:      "OAuth connected account updated",
	}
	payload := (WebhookNotifier{Type: "generic"}).payload("admin.audit", incident)
	if payload["summary"] != incident.NotificationDetails {
		t.Fatalf("generic webhook did not use the concise canonical summary: %#v", payload)
	}
	if payload["schema_version"] != 2 || payload["service_id"] != "observability" || payload["target"] != "OAuth接続アカウント (acct-01)" || payload["actor"] != "ops" {
		t.Fatalf("generic webhook structured context changed: %#v", payload)
	}
	if payload["details"] != "" {
		t.Fatalf("generic webhook repeated the canonical admin summary: %#v", payload)
	}
	if len(payload) != 15 {
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
