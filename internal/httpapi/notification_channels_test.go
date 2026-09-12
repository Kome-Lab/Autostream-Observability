package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/example/autostream-observability/internal/auth"
	"github.com/example/autostream-observability/internal/store"
)

func TestNotificationChannelCRUDDoesNotExposeWebhookURL(t *testing.T) {
	handler := newTestServer(store.NewMemoryStore())
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"discord main","type":"discord","enabled":true,"webhook_url":"https://discord.com/api/webhooks/id/secret-token","severity_filter":["critical"],"event_type_filter":["incident.opened"]}`))
	createReq.Header.Set("Authorization", "Bearer service-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusCreated {
		t.Fatalf("create status = %d body = %s", createRes.Code, createRes.Body.String())
	}
	if strings.Contains(createRes.Body.String(), "secret-token") || strings.Contains(createRes.Body.String(), `"webhook_url"`) {
		t.Fatalf("webhook URL leaked in create response: %s", createRes.Body.String())
	}
	if strings.Contains(createRes.Body.String(), `"smtp_tls"`) || strings.Contains(createRes.Body.String(), `"smtp_password"`) {
		t.Fatalf("SMTP fields leaked into webhook channel response: %s", createRes.Body.String())
	}
	var created store.NotificationChannel
	if err := json.NewDecoder(createRes.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	listReq := httptest.NewRequest(http.MethodGet, "/notification-channels", nil)
	listReq.Header.Set("Authorization", "Bearer service-token")
	listRes := httptest.NewRecorder()
	handler.ServeHTTP(listRes, listReq)
	if listRes.Code != http.StatusOK || strings.Contains(listRes.Body.String(), "secret-token") {
		t.Fatalf("list status = %d body = %s", listRes.Code, listRes.Body.String())
	}
	getReq := httptest.NewRequest(http.MethodGet, "/notification-channels/"+created.ID, nil)
	getReq.Header.Set("Authorization", "Bearer service-token")
	getRes := httptest.NewRecorder()
	handler.ServeHTTP(getRes, getReq)
	if getRes.Code != http.StatusOK || strings.Contains(getRes.Body.String(), "secret-token") || strings.Contains(getRes.Body.String(), `"webhook_url"`) {
		t.Fatalf("get status = %d body = %s", getRes.Code, getRes.Body.String())
	}
	updateReq := httptest.NewRequest(http.MethodPut, "/notification-channels/"+created.ID, bytes.NewBufferString(`{"name":"discord updated","type":"discord","enabled":false,"webhook_url":"https://discord.com/api/webhooks/id/new-secret-token"}`))
	updateReq.Header.Set("Authorization", "Bearer service-token")
	updateRes := httptest.NewRecorder()
	handler.ServeHTTP(updateRes, updateReq)
	if updateRes.Code != http.StatusOK || !strings.Contains(updateRes.Body.String(), "discord updated") {
		t.Fatalf("update status = %d body = %s", updateRes.Code, updateRes.Body.String())
	}
	if strings.Contains(updateRes.Body.String(), "new-secret-token") || strings.Contains(updateRes.Body.String(), `"webhook_url"`) {
		t.Fatalf("webhook URL leaked in update response: %s", updateRes.Body.String())
	}
	if strings.Contains(updateRes.Body.String(), `"smtp_tls"`) || strings.Contains(updateRes.Body.String(), `"smtp_password"`) {
		t.Fatalf("SMTP fields leaked into webhook channel update response: %s", updateRes.Body.String())
	}
	deleteReq := httptest.NewRequest(http.MethodDelete, "/notification-channels/"+created.ID, nil)
	deleteReq.Header.Set("Authorization", "Bearer service-token")
	deleteRes := httptest.NewRecorder()
	handler.ServeHTTP(deleteRes, deleteReq)
	if deleteRes.Code != http.StatusOK {
		t.Fatalf("delete status = %d body = %s", deleteRes.Code, deleteRes.Body.String())
	}
}

func TestNotificationChannelCanonicalizesDiscordAliasesBeforePersistence(t *testing.T) {
	st := store.NewMemoryStore()
	handler := newTestServer(st)
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"discord ptb","type":"discord","enabled":true,"webhook_url":"https://ptb.discord.com/api/webhooks/id/secret-token?wait=true"}`))
	createReq.Header.Set("Authorization", "Bearer service-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusCreated {
		t.Fatalf("create status = %d body = %s", createRes.Code, createRes.Body.String())
	}
	var created store.NotificationChannel
	if err := json.NewDecoder(createRes.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	stored, err := st.GetNotificationChannel(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.WebhookURL != "https://discord.com/api/webhooks/id/secret-token?wait=true" {
		t.Fatalf("stored create URL = %q", stored.WebhookURL)
	}

	updateReq := httptest.NewRequest(http.MethodPut, "/notification-channels/"+created.ID, bytes.NewBufferString(`{"name":"discord legacy canary","type":"discord","enabled":true,"webhook_url":"https://canary.discordapp.com/api/webhooks/id/new-secret-token"}`))
	updateReq.Header.Set("Authorization", "Bearer service-token")
	updateRes := httptest.NewRecorder()
	handler.ServeHTTP(updateRes, updateReq)
	if updateRes.Code != http.StatusOK {
		t.Fatalf("update status = %d body = %s", updateRes.Code, updateRes.Body.String())
	}
	stored, err = st.GetNotificationChannel(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.WebhookURL != "https://discord.com/api/webhooks/id/new-secret-token" {
		t.Fatalf("stored update URL = %q", stored.WebhookURL)
	}
}

func TestSlackNotificationChannelCRUDDoesNotExposeWebhookURL(t *testing.T) {
	handler := newTestServer(store.NewMemoryStore())
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"slack ops","type":"slack","enabled":true,"webhook_url":"https://hooks.slack.com/services/T000/B000/secret-token","severity_filter":["critical","error"],"event_type_filter":["incident.opened"]}`))
	createReq.Header.Set("Authorization", "Bearer service-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusCreated {
		t.Fatalf("create slack channel status=%d body=%s", createRes.Code, createRes.Body.String())
	}
	for _, leaked := range []string{"secret-token", "hooks.slack.com/services", `"webhook_url"`} {
		if strings.Contains(createRes.Body.String(), leaked) {
			t.Fatalf("slack webhook detail leaked in create response: %s", createRes.Body.String())
		}
	}
	var created store.NotificationChannel
	if err := json.NewDecoder(createRes.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.Type != "slack" || created.MaskedWebhookURL != "https://hooks.slack.com/<WEBHOOK_PATH>" {
		t.Fatalf("slack public channel markers missing: %#v", created)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/notification-channels", nil)
	listReq.Header.Set("Authorization", "Bearer service-token")
	listRes := httptest.NewRecorder()
	handler.ServeHTTP(listRes, listReq)
	if listRes.Code != http.StatusOK {
		t.Fatalf("list slack channels status=%d body=%s", listRes.Code, listRes.Body.String())
	}
	for _, leaked := range []string{"secret-token", "hooks.slack.com/services", `"webhook_url"`} {
		if strings.Contains(listRes.Body.String(), leaked) {
			t.Fatalf("slack webhook detail leaked in list response: %s", listRes.Body.String())
		}
	}
	if !strings.Contains(listRes.Body.String(), `"masked_webhook_url":"https://hooks.slack.com/\u003cWEBHOOK_PATH\u003e"`) {
		t.Fatalf("slack masked webhook URL was not preserved: %s", listRes.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/notification-channels/"+created.ID, nil)
	getReq.Header.Set("Authorization", "Bearer service-token")
	getRes := httptest.NewRecorder()
	handler.ServeHTTP(getRes, getReq)
	if getRes.Code != http.StatusOK {
		t.Fatalf("get slack channel status=%d body=%s", getRes.Code, getRes.Body.String())
	}
	for _, leaked := range []string{"secret-token", "hooks.slack.com/services", `"webhook_url"`} {
		if strings.Contains(getRes.Body.String(), leaked) {
			t.Fatalf("slack webhook detail leaked in get response: %s", getRes.Body.String())
		}
	}
}

func TestSlackNotificationChannelRejectsNonSlackWebhookHost(t *testing.T) {
	handler := newTestServer(store.NewMemoryStore())
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"slack wrong host","type":"slack","enabled":true,"webhook_url":"https://example.com/services/T000/B000/secret-token"}`))
	createReq.Header.Set("Authorization", "Bearer service-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusBadRequest || !strings.Contains(createRes.Body.String(), "invalid_webhook_url") {
		t.Fatalf("expected invalid_webhook_url, status=%d body=%s", createRes.Code, createRes.Body.String())
	}
	if strings.Contains(createRes.Body.String(), "secret-token") || strings.Contains(createRes.Body.String(), "example.com/services") {
		t.Fatalf("slack webhook detail leaked in validation error: %s", createRes.Body.String())
	}
}

func TestEmailNotificationChannelCRUDUsesGlobalSMTPReferenceAndMasksRecipients(t *testing.T) {
	handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", store.NewMemoryStore(), auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), &fakeNotifier{}, nil)
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"email ops","type":"email","enabled":true,"uses_global_smtp":true,"email_recipients":["ops@example.com"],"severity_filter":["critical"],"event_type_filter":["incident.opened"]}`))
	createReq.Header.Set("Authorization", "Bearer admin-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusCreated {
		t.Fatalf("create email channel status=%d body=%s", createRes.Code, createRes.Body.String())
	}
	for _, raw := range []string{"ops@example.com", `"email_recipients"`} {
		if strings.Contains(createRes.Body.String(), raw) {
			t.Fatalf("email channel raw detail leaked in create response: %s", createRes.Body.String())
		}
	}
	var created store.NotificationChannel
	if err := json.NewDecoder(createRes.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if !created.UseGlobalSMTP || created.MaskedEmailTarget == "" {
		t.Fatalf("email channel status fields missing: %#v", created)
	}
	listReq := httptest.NewRequest(http.MethodGet, "/notification-channels", nil)
	listReq.Header.Set("Authorization", "Bearer admin-token")
	listRes := httptest.NewRecorder()
	handler.ServeHTTP(listRes, listReq)
	if listRes.Code != http.StatusOK {
		t.Fatalf("list response status=%d body=%s", listRes.Code, listRes.Body.String())
	}
	for _, raw := range []string{"ops@example.com", `"email_recipients"`} {
		if strings.Contains(listRes.Body.String(), raw) {
			t.Fatalf("email channel raw detail leaked in list response: %s", listRes.Body.String())
		}
	}
	getReq := httptest.NewRequest(http.MethodGet, "/notification-channels/"+created.ID, nil)
	getReq.Header.Set("Authorization", "Bearer admin-token")
	getRes := httptest.NewRecorder()
	handler.ServeHTTP(getRes, getReq)
	if getRes.Code != http.StatusOK {
		t.Fatalf("get response status=%d body=%s", getRes.Code, getRes.Body.String())
	}
	for _, raw := range []string{"ops@example.com", `"email_recipients"`} {
		if strings.Contains(getRes.Body.String(), raw) {
			t.Fatalf("email channel raw detail leaked in get response: %s", getRes.Body.String())
		}
	}
}

func TestGlobalSMTPEmailChannelCreateAndUpdate(t *testing.T) {
	mem := store.NewMemoryStore()
	handler := NewServerWithStoreAuthzNotifierExecutorAndEmailRelay("observability", mem, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), &fakeNotifier{}, nil, &fakeEmailRelay{})
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"global email","type":"email","enabled":true,"uses_global_smtp":true,"email_recipients":["ops@example.com"],"severity_filter":["critical"]}`))
	createReq.Header.Set("Authorization", "Bearer admin-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusCreated {
		t.Fatalf("global email create status=%d body=%s", createRes.Code, createRes.Body.String())
	}
	var created store.NotificationChannel
	if err := json.NewDecoder(createRes.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if !created.UseGlobalSMTP || created.ID == "" {
		t.Fatalf("global SMTP marker missing from create response: %#v", created)
	}

	updateReq := httptest.NewRequest(http.MethodPut, "/notification-channels/"+created.ID, bytes.NewBufferString(`{"name":"global email renamed","type":"email","enabled":true,"uses_global_smtp":true}`))
	updateReq.Header.Set("Authorization", "Bearer admin-token")
	updateRes := httptest.NewRecorder()
	handler.ServeHTTP(updateRes, updateReq)
	if updateRes.Code != http.StatusOK {
		t.Fatalf("global email update status=%d body=%s", updateRes.Code, updateRes.Body.String())
	}
	stored, err := mem.GetNotificationChannel(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.UseGlobalSMTP || len(stored.EmailRecipients) != 1 || stored.EmailRecipients[0] != "ops@example.com" {
		t.Fatalf("update did not preserve omitted recipients: %#v", stored)
	}
}

func TestGlobalSMTPEmailChannelRejectsEmptyRecipients(t *testing.T) {
	mem := store.NewMemoryStore()
	handler := NewServerWithStoreAuthzNotifierExecutorAndEmailRelay("observability", mem, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), &fakeNotifier{}, nil, &fakeEmailRelay{})
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"global email","type":"email","enabled":true,"uses_global_smtp":true,"email_recipients":[]}`))
	createReq.Header.Set("Authorization", "Bearer admin-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusBadRequest || !strings.Contains(createRes.Body.String(), "invalid_notification_channel") {
		t.Fatalf("empty recipients must be rejected, status=%d body=%s", createRes.Code, createRes.Body.String())
	}
}

func TestGlobalSMTPEmailChannelRejectsMixedLegacySMTPFields(t *testing.T) {
	mem := store.NewMemoryStore()
	handler := NewServerWithStoreAuthzNotifierExecutorAndEmailRelay("observability", mem, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), &fakeNotifier{}, nil, &fakeEmailRelay{})
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"mixed email","type":"email","enabled":true,"uses_global_smtp":true,"email_recipients":["ops@example.com"],"smtp_host":"smtp.example.com"}`))
	createReq.Header.Set("Authorization", "Bearer admin-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusBadRequest || !strings.Contains(createRes.Body.String(), "bad_request") {
		t.Fatalf("removed SMTP fields must be rejected as unknown input, status=%d body=%s", createRes.Code, createRes.Body.String())
	}
}

func TestNotificationChannelRejectsGlobalSMTPForNonEmailTypes(t *testing.T) {
	mem := store.NewMemoryStore()
	handler := NewServerWithStoreAuthzNotifierExecutorAndEmailRelay("observability", mem, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), &fakeNotifier{}, nil, &fakeEmailRelay{})

	for _, tt := range []struct {
		channelType string
		webhookURL  string
	}{
		{channelType: "generic", webhookURL: "https://example.com/hook/token"},
		{channelType: "discord", webhookURL: "https://discord.com/api/webhooks/id/token"},
		{channelType: "slack", webhookURL: "https://hooks.slack.com/services/id/token"},
	} {
		t.Run("create_"+tt.channelType, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{
				"name":             tt.channelType + " invalid global SMTP",
				"type":             tt.channelType,
				"enabled":          true,
				"uses_global_smtp": true,
				"webhook_url":      tt.webhookURL,
			})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer admin-token")
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "invalid_notification_channel") {
				t.Fatalf("non-email global SMTP create must fail, status=%d body=%s", res.Code, res.Body.String())
			}
		})
	}

	generic, err := mem.CreateNotificationChannel(t.Context(), store.NotificationChannel{
		Name: "generic", Type: "generic", Enabled: true, WebhookURL: "https://example.com/hook/token",
	})
	if err != nil {
		t.Fatal(err)
	}
	explicitReq := httptest.NewRequest(http.MethodPut, "/notification-channels/"+generic.ID, bytes.NewBufferString(`{"name":"generic","type":"generic","enabled":true,"uses_global_smtp":true}`))
	explicitReq.Header.Set("Authorization", "Bearer admin-token")
	explicitRes := httptest.NewRecorder()
	handler.ServeHTTP(explicitRes, explicitReq)
	if explicitRes.Code != http.StatusBadRequest || !strings.Contains(explicitRes.Body.String(), "invalid_notification_channel") {
		t.Fatalf("explicit non-email global SMTP update must fail, status=%d body=%s", explicitRes.Code, explicitRes.Body.String())
	}

	globalEmail, err := mem.CreateNotificationChannel(t.Context(), store.NotificationChannel{
		Name: "global email", Type: "email", Enabled: true, UseGlobalSMTP: true, UseGlobalSMTPSet: true, EmailRecipients: []string{"ops@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	inheritedReq := httptest.NewRequest(http.MethodPut, "/notification-channels/"+globalEmail.ID, bytes.NewBufferString(`{"name":"generic conversion","type":"generic","enabled":true,"webhook_url":"https://example.com/hook/token"}`))
	inheritedReq.Header.Set("Authorization", "Bearer admin-token")
	inheritedRes := httptest.NewRecorder()
	handler.ServeHTTP(inheritedRes, inheritedReq)
	if inheritedRes.Code != http.StatusBadRequest || !strings.Contains(inheritedRes.Body.String(), "invalid_notification_channel") {
		t.Fatalf("effective non-email global SMTP update must fail, status=%d body=%s", inheritedRes.Code, inheritedRes.Body.String())
	}
}

func TestPublicNotificationChannelProjectionOmitsInternalSecrets(t *testing.T) {
	channel := store.NotificationChannel{
		ID:                "chn-secret",
		Name:              "ops email",
		Type:              "email",
		Enabled:           true,
		WebhookURL:        "https://discord.com/api/webhooks/id/raw-webhook-token",
		MaskedWebhookURL:  "https://<WEBHOOK_HOST>/<WEBHOOK_PATH>",
		EmailRecipients:   []string{"ops@example.com"},
		UseGlobalSMTP:     true,
		UseGlobalSMTPSet:  true,
		MaskedEmailTarget: "o***s@<EMAIL_DOMAIN>",
		SeverityFilter:    []string{"critical"},
		EventTypeFilter:   []string{"incident.opened"},
	}
	body, err := json.Marshal(publicNotificationChannel(channel))
	if err != nil {
		t.Fatal(err)
	}
	raw := string(body)
	for _, leaked := range []string{
		"raw-webhook-token",
		"ops@example.com",
		"email_recipients",
	} {
		if strings.Contains(raw, leaked) {
			t.Fatalf("public notification channel projection leaked %q: %s", leaked, raw)
		}
	}
	if strings.Contains(raw, `"webhook_url"`) {
		t.Fatalf("public notification channel projection leaked raw webhook field: %s", raw)
	}
	for _, want := range []string{`"uses_global_smtp":true`, `"masked_email_target":"o***s@\u003cEMAIL_DOMAIN\u003e"`, `"severity_filter":["critical"]`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("public notification channel projection missing %s: %s", want, raw)
		}
	}
}

func TestEmailNotificationChannelRejectsRemovedDirectSMTPFields(t *testing.T) {
	handler := NewServerWithStoreAuthzNotifierAndExecutor("observability", store.NewMemoryStore(), auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), &fakeNotifier{}, nil)
	removed := map[string]string{
		"smtp_host":     `"smtp.example.com"`,
		"smtp_port":     `587`,
		"smtp_tls":      `true`,
		"smtp_from":     `"autostream@example.com"`,
		"smtp_username": `"autostream"`,
		"smtp_password": `"raw-smtp-password"`,
	}
	for name, value := range removed {
		t.Run(name, func(t *testing.T) {
			body := `{"name":"email ops","type":"email","enabled":true,"uses_global_smtp":true,"email_recipients":["ops@example.com"],"` + name + `":` + value + `}`

			req := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(body))
			req.Header.Set("Authorization", "Bearer admin-token")
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "bad_request") {
				t.Fatalf("removed direct SMTP field %q accepted: status=%d body=%s", name, res.Code, res.Body.String())
			}
			if strings.Contains(res.Body.String(), "raw-smtp-password") || strings.Contains(res.Body.String(), "smtp.example.com") {
				t.Fatalf("removed SMTP detail leaked in error response: %s", res.Body.String())
			}
		})
	}
}

func TestNotificationChannelTestDoesNotExposeWebhookURL(t *testing.T) {
	t.Setenv("OBSERVABILITY_ALLOW_PRIVATE_WEBHOOKS", "true")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "secret-token", http.StatusForbidden)
	}))
	defer upstream.Close()

	handler := newTestServer(store.NewMemoryStore())
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"generic main","type":"generic","enabled":true,"webhook_url":"`+upstream.URL+`/hook/secret-token"}`))
	createReq.Header.Set("Authorization", "Bearer service-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusCreated {
		t.Fatalf("create status = %d body = %s", createRes.Code, createRes.Body.String())
	}
	var created store.NotificationChannel
	if err := json.NewDecoder(createRes.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	testReq := httptest.NewRequest(http.MethodPost, "/notification-channels/"+created.ID+"/test", nil)
	testReq.Header.Set("Authorization", "Bearer service-token")
	testRes := httptest.NewRecorder()
	handler.ServeHTTP(testRes, testReq)
	if testRes.Code != http.StatusAccepted {
		t.Fatalf("test status = %d body = %s", testRes.Code, testRes.Body.String())
	}
	body := testRes.Body.String()
	if strings.Contains(body, "secret-token") || strings.Contains(body, `"webhook_url"`) {
		t.Fatalf("webhook URL leaked in test response: %s", body)
	}
}

func TestEmailNotificationChannelTestDoesNotExposeRecipientDetails(t *testing.T) {
	st := store.NewMemoryStore()
	channel, err := st.CreateNotificationChannel(t.Context(), store.NotificationChannel{
		Name:              "ops email",
		Type:              "email",
		Enabled:           true,
		EmailRecipients:   []string{"ops@example.com"},
		MaskedEmailTarget: "o***s@<EMAIL_DOMAIN>",
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := newTestServer(st)
	testReq := httptest.NewRequest(http.MethodPost, "/notification-channels/"+channel.ID+"/test", nil)
	testReq.Header.Set("Authorization", "Bearer service-token")
	testRes := httptest.NewRecorder()
	handler.ServeHTTP(testRes, testReq)
	if testRes.Code != http.StatusAccepted {
		t.Fatalf("test status = %d body = %s", testRes.Code, testRes.Body.String())
	}
	body := testRes.Body.String()
	for _, raw := range []string{"ops@example.com", `"email_recipients"`} {
		if strings.Contains(body, raw) {
			t.Fatalf("email notification test response leaked SMTP detail %q: %s", raw, body)
		}
	}
	if !strings.Contains(body, `o***s@\u003cEMAIL_DOMAIN\u003e`) || !strings.Contains(body, "email notification delivery failed") {
		t.Fatalf("email notification test response should include masked target and sanitized error: %s", body)
	}
}

func TestGlobalSMTPNotificationChannelTestUsesRelay(t *testing.T) {
	st := store.NewMemoryStore()
	channel, err := st.CreateNotificationChannel(t.Context(), store.NotificationChannel{
		Name: "global email", Type: "email", Enabled: true, UseGlobalSMTP: true, EmailRecipients: []string{"ops@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	relay := &fakeEmailRelay{}
	handler := NewServerWithStoreAuthzNotifierExecutorAndEmailRelay("observability", st, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), &fakeNotifier{}, nil, relay)
	testReq := httptest.NewRequest(http.MethodPost, "/notification-channels/"+channel.ID+"/test", nil)
	testReq.Header.Set("Authorization", "Bearer admin-token")
	testRes := httptest.NewRecorder()
	handler.ServeHTTP(testRes, testReq)
	if testRes.Code != http.StatusAccepted || relay.calls != 1 || !strings.Contains(testRes.Body.String(), `"status":"success"`) {
		t.Fatalf("global relay test failed: calls=%d status=%d body=%s", relay.calls, testRes.Code, testRes.Body.String())
	}
	deliveries, err := st.ListNotificationDeliveries(t.Context())
	if err != nil || len(deliveries) != 1 || deliveries[0].Status != "success" || deliveries[0].Channel != "email" {
		t.Fatalf("successful channel test was not saved to delivery history: deliveries=%#v err=%v", deliveries, err)
	}
}

func TestGlobalSMTPNotificationChannelTestReturnsSafeFailureCodes(t *testing.T) {
	for _, code := range []string{"smtp_not_configured", "rate_limited"} {
		t.Run(code, func(t *testing.T) {
			st := store.NewMemoryStore()
			channel, err := st.CreateNotificationChannel(t.Context(), store.NotificationChannel{
				Name: "global email", Type: "email", Enabled: true, UseGlobalSMTP: true, EmailRecipients: []string{"ops@example.com"},
			})
			if err != nil {
				t.Fatal(err)
			}
			relay := &fakeEmailRelay{err: fakeSafeEmailError(code)}
			handler := NewServerWithStoreAuthzNotifierExecutorAndEmailRelay("observability", st, auth.NewVerifierFromRawTokens("ingest-token"), auth.NewVerifierFromRawTokens("admin-token"), &fakeNotifier{}, nil, relay)
			testReq := httptest.NewRequest(http.MethodPost, "/notification-channels/"+channel.ID+"/test", nil)
			testReq.Header.Set("Authorization", "Bearer admin-token")
			testRes := httptest.NewRecorder()
			handler.ServeHTTP(testRes, testReq)
			body := testRes.Body.String()
			if testRes.Code != http.StatusAccepted || relay.calls != 1 || !strings.Contains(body, `"status":"failure"`) || !strings.Contains(body, `"error":"`+code+`"`) || strings.Contains(body, "ops@example.com") {
				t.Fatalf("unexpected safe global relay failure: calls=%d status=%d body=%s", relay.calls, testRes.Code, body)
			}
			deliveries, err := st.ListNotificationDeliveries(t.Context())
			if err != nil || len(deliveries) != 1 || deliveries[0].Status != "failure" || deliveries[0].Error != code || deliveries[0].Channel != "email" {
				t.Fatalf("failed channel test was not safely saved to delivery history: deliveries=%#v err=%v", deliveries, err)
			}
		})
	}
}

func TestNotificationChannelRejectsNonHTTPWebhookURL(t *testing.T) {
	handler := newTestServer(store.NewMemoryStore())
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"bad","type":"generic","enabled":true,"webhook_url":"ftp://example.com/hook/secret-token"}`))
	createReq.Header.Set("Authorization", "Bearer service-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusBadRequest {
		t.Fatalf("create status = %d body = %s", createRes.Code, createRes.Body.String())
	}
	if strings.Contains(createRes.Body.String(), "secret-token") {
		t.Fatalf("webhook URL leaked in error response: %s", createRes.Body.String())
	}
}

func TestNotificationChannelRejectsPrivateWebhookURLByDefault(t *testing.T) {
	handler := newTestServer(store.NewMemoryStore())
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"metadata","type":"generic","enabled":true,"webhook_url":"http://169.254.169.254/latest/meta-data"}`))
	createReq.Header.Set("Authorization", "Bearer service-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusBadRequest || !strings.Contains(createRes.Body.String(), "invalid_webhook_url") {
		t.Fatalf("create status = %d body = %s", createRes.Code, createRes.Body.String())
	}
	if strings.Contains(createRes.Body.String(), "169.254.169.254") {
		t.Fatalf("private target leaked in error response: %s", createRes.Body.String())
	}
}

func TestNotificationChannelRejectsPrivateWebhookURLInProductionEvenWhenEnvAllows(t *testing.T) {
	t.Setenv("OBSERVABILITY_ENV", "production")
	t.Setenv("OBSERVABILITY_ALLOW_PRIVATE_WEBHOOKS", "true")

	handler := newTestServer(store.NewMemoryStore())
	createReq := httptest.NewRequest(http.MethodPost, "/notification-channels", bytes.NewBufferString(`{"name":"local","type":"generic","enabled":true,"webhook_url":"http://127.0.0.1:8080/hook"}`))
	createReq.Header.Set("Authorization", "Bearer service-token")
	createRes := httptest.NewRecorder()
	handler.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusBadRequest || !strings.Contains(createRes.Body.String(), "invalid_webhook_url") {
		t.Fatalf("create status = %d body = %s", createRes.Code, createRes.Body.String())
	}
	if strings.Contains(createRes.Body.String(), "127.0.0.1") {
		t.Fatalf("private target leaked in error response: %s", createRes.Body.String())
	}
}
