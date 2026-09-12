package notifications

import (
	"html"
	"strings"
	"unicode/utf8"

	"github.com/example/autostream-observability/internal/store"
)

const maxNotificationEmailTextBytes = 16 * 1024

func formatEmailSubject(eventType string, incident store.Incident) string {
	severity := strings.ToUpper(strings.TrimSpace(incident.Severity))
	if severity == "" {
		severity = "INFO"
	}
	legacy := strings.TrimSpace("[AutoStream] " + severity + " " + strings.TrimSpace(incident.Rule))
	title := notificationTitle(eventType, incident)
	subject := legacy
	if title != "" && title != strings.TrimSpace(incident.Rule) {
		subject += " | " + title
	}
	return truncateNotificationText(strings.Join(strings.Fields(strings.ReplaceAll(strings.ReplaceAll(subject, "\r", " "), "\n", " ")), " "), 200)
}

func formatIncidentEmailText(eventType string, incident store.Incident) string {
	return truncateEmailBytes(formatIncidentText(eventType, incident), maxNotificationEmailTextBytes)
}

func formatIncidentHTML(eventType string, incident store.Incident) string {
	title := truncateNotificationText(notificationTitle(eventType, incident), 256)
	content := buildNotificationContent(eventType, incident)
	summary := truncateNotificationText(joinNotificationDetails(content.Summary, content.Diagnosis), 12000)
	if summary == "" {
		summary = "詳細情報はありません。"
	}

	var rows strings.Builder
	for _, field := range emailNotificationFields(eventType, incident) {
		rows.WriteString(`<tr><th scope="row" style="padding:10px 12px;text-align:left;vertical-align:top;width:34%;border-bottom:1px solid #e4e7ec;color:#475467;font-size:13px;font-weight:600;">`)
		rows.WriteString(html.EscapeString(field.Name))
		rows.WriteString(`</th><td style="padding:10px 12px;vertical-align:top;border-bottom:1px solid #e4e7ec;color:#101828;font-size:14px;word-break:break-word;">`)
		rows.WriteString(formatEmailHTMLText(truncateNotificationText(field.Value, 2048)))
		rows.WriteString(`</td></tr>`)
	}
	var detailSections strings.Builder
	if len(content.Actions) > 0 {
		detailSections.WriteString(notificationHTMLSection("推奨対応", "• "+strings.Join(content.Actions, "\n• ")))
	}
	if len(content.Evidence) > 0 {
		detailSections.WriteString(notificationHTMLSection("根拠", "• "+strings.Join(content.Evidence, "\n• ")))
	}

	return `<!doctype html><html lang="ja"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>` +
		`<body style="margin:0;padding:0;background:#f2f4f7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#101828;">` +
		`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f2f4f7;"><tr><td align="center" style="padding:24px 12px;">` +
		`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:640px;background:#ffffff;border:1px solid #e4e7ec;border-radius:12px;overflow:hidden;">` +
		`<tr><td style="height:6px;background:` + notificationEmailAccent(incident.Severity) + `;font-size:0;line-height:0;">&nbsp;</td></tr>` +
		`<tr><td style="padding:22px 24px 14px;"><div style="color:#667085;font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;">AutoStream Notification</div>` +
		`<h1 style="margin:8px 0 0;font-size:22px;line-height:1.35;color:#101828;">` + html.EscapeString(title) + `</h1></td></tr>` +
		`<tr><td style="padding:0 24px 18px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e4e7ec;border-radius:8px;border-collapse:separate;border-spacing:0;overflow:hidden;">` + rows.String() + `</table></td></tr>` +
		`<tr><td style="padding:0 24px 24px;"><div style="margin-bottom:8px;color:#475467;font-size:13px;font-weight:700;">概要</div>` +
		`<div style="padding:14px 16px;background:#f9fafb;border-radius:8px;color:#344054;font-size:14px;line-height:1.65;word-break:break-word;">` + formatEmailHTMLText(summary) + `</div></td></tr>` + detailSections.String() +
		`<tr><td style="padding:14px 24px;background:#f9fafb;border-top:1px solid #e4e7ec;color:#667085;font-size:12px;">AutoStream Control Panel から送信された通知です。</td></tr>` +
		`</table></td></tr></table></body></html>`
}

func notificationHTMLSection(title, value string) string {
	return `<tr><td style="padding:0 24px 24px;"><div style="margin-bottom:8px;color:#475467;font-size:13px;font-weight:700;">` + html.EscapeString(title) + `</div>` +
		`<div style="padding:14px 16px;background:#f9fafb;border-radius:8px;color:#344054;font-size:14px;line-height:1.65;word-break:break-word;">` + formatEmailHTMLText(value) + `</div></td></tr>`
}

func emailNotificationFields(eventType string, incident store.Incident) []notificationMessageField {
	eventType = normalizedEventType(eventType)
	eventValue := notificationEventLabel(eventType) + " (" + eventType + ")"
	actionCode := strings.TrimSpace(incident.Rule)
	actionValue := notificationRuleValue(eventType, actionCode)
	if actionValue == "" {
		actionValue = "—"
	}
	resource := notificationTargetValue(incident)
	if resource == "" {
		switch {
		case strings.TrimSpace(incident.StreamID) != "":
			resource = "配信枠: " + strings.TrimSpace(incident.StreamID)
		case strings.TrimSpace(incident.ServiceID) != "":
			resource = "サービス: " + strings.TrimSpace(incident.ServiceID)
		case strings.TrimSpace(incident.ID) != "":
			resource = "インシデント: " + strings.TrimSpace(incident.ID)
		default:
			resource = "—"
		}
	}
	actor := notificationActorValue(incident)
	if actor == "" {
		actor = "—"
	}
	timestamp := notificationTimestamp(incident)
	if timestamp == "" {
		timestamp = "—"
	}
	return []notificationMessageField{
		{Name: "イベント", Value: eventValue},
		{Name: "操作 / ルール", Value: actionValue},
		{Name: "対象", Value: resource},
		{Name: "実行者", Value: actor},
		{Name: "結果", Value: notificationStatusLabel(incident.Status)},
		{Name: "重要度", Value: notificationSeverityLabel(incident.Severity)},
		{Name: "日時", Value: timestamp},
	}
}

func formatEmailHTMLText(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	return strings.ReplaceAll(html.EscapeString(value), "\n", "<br>")
}

func notificationEmailAccent(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "error":
		return "#d92d20"
	case "warning":
		return "#f79009"
	case "info":
		return "#1570ef"
	default:
		return "#667085"
	}
}

func truncateEmailBytes(value string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(value) <= maxBytes {
		return value
	}
	suffix := "…"
	limit := maxBytes - len(suffix)
	if limit <= 0 {
		return suffix[:maxBytes]
	}
	used := 0
	for _, value := range value {
		size := utf8.RuneLen(value)
		if size < 1 || used+size > limit {
			break
		}
		used += size
	}
	return strings.TrimSpace(value[:used]) + suffix
}
