package notifications

import (
	"strings"

	"github.com/example/autostream-observability/internal/store"
)

func (n WebhookNotifier) payload(eventType string, incident store.Incident) map[string]any {
	text := formatIncidentText(eventType, incident)
	switch normalizedType(n.Type) {
	case "discord":
		embed := map[string]any{
			"title":  truncateNotificationText(notificationTitle(eventType, incident), 256),
			"color":  notificationColor(incident.Severity),
			"fields": discordNotificationFields(eventType, incident),
			"footer": map[string]any{"text": "AutoStream • " + eventType},
		}
		if description := notificationDescription(eventType, incident); description != "" {
			embed["description"] = truncateNotificationText(description, 3000)
		}
		if timestamp := notificationTimestamp(incident); timestamp != "" {
			embed["timestamp"] = timestamp
		}
		return map[string]any{
			"embeds": []map[string]any{embed},
			"allowed_mentions": map[string]any{
				"parse": []string{},
			},
		}
	case "slack":
		return map[string]any{
			"text":   escapeSlackText(text),
			"blocks": slackNotificationBlocks(eventType, incident),
		}
	default:
		content := buildNotificationContent(eventType, incident)
		// Keep the original summary fields for existing consumers, while also
		// exposing the same structured context used by Discord, Slack, and email.
		// This prevents generic webhook receivers from having to parse Japanese
		// free-form text or accidentally displaying the receiver (observability)
		// as the source service.
		payload := map[string]any{
			"schema_version": 2,
			"event_type":     eventType,
			"event_label":    notificationEventLabel(eventType),
			"title":          notificationTitle(eventType, incident),
			"severity":       incident.Severity,
			"status":         incident.Status,
			"incident_id":    incident.ID,
			"rule":           incident.Rule,
			"service_id":     incident.ServiceID,
			"stream_id":      incident.StreamID,
			"target":         notificationTargetValue(incident),
			"actor":          notificationActorValue(incident),
			"summary":        content.Summary,
			"details":        truncateNotificationText(content.Diagnosis, 6000),
			"occurred_at":    notificationTimestamp(incident),
		}
		if len(content.Actions) > 0 {
			payload["recommended_actions"] = content.Actions
		}
		if len(content.Evidence) > 0 {
			payload["evidence"] = content.Evidence
		}
		return payload
	}
}

func escapeSlackText(value string) string {
	return strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
	).Replace(value)
}

func discordNotificationFields(eventType string, incident store.Incident) []map[string]any {
	fields := notificationMessageFields(eventType, incident)
	out := make([]map[string]any, 0, len(fields))
	for _, field := range fields {
		out = append(out, map[string]any{
			"name":   field.Name,
			"value":  truncateNotificationText(field.Value, 480),
			"inline": true,
		})
	}
	content := buildNotificationContent(eventType, incident)
	if len(content.Actions) > 0 {
		out = append(out, map[string]any{"name": "推奨対応", "value": truncateNotificationText("• "+strings.Join(content.Actions, "\n• "), 1000), "inline": false})
	}
	if len(content.Evidence) > 0 {
		out = append(out, map[string]any{"name": "根拠", "value": truncateNotificationText("• "+strings.Join(content.Evidence, "\n• "), 1000), "inline": false})
	}
	return out
}

func slackNotificationBlocks(eventType string, incident store.Incident) []map[string]any {
	blocks := []map[string]any{
		{
			"type": "header",
			"text": map[string]any{
				"type": "plain_text",
				"text": truncateNotificationText(notificationTitle(eventType, incident), 150),
			},
		},
	}
	if description := notificationDescription(eventType, incident); description != "" {
		blocks = append(blocks, map[string]any{
			"type": "section",
			"text": map[string]any{
				"type": "plain_text",
				"text": truncateNotificationText(description, 3000),
			},
		})
	}
	content := buildNotificationContent(eventType, incident)
	if len(content.Actions) > 0 {
		blocks = append(blocks, map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": "*推奨対応*\n• " + escapeSlackText(strings.Join(content.Actions, "\n• "))}})
	}
	if len(content.Evidence) > 0 {
		blocks = append(blocks, map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": "*根拠*\n• " + escapeSlackText(strings.Join(content.Evidence, "\n• "))}})
	}
	fields := make([]map[string]any, 0, len(notificationMessageFields(eventType, incident)))
	for _, field := range notificationMessageFields(eventType, incident) {
		fields = append(fields, map[string]any{
			"type": "mrkdwn",
			"text": "*" + field.Name + "*\n" + escapeSlackText(truncateNotificationText(field.Value, 1900)),
		})
	}
	if len(fields) > 0 {
		blocks = append(blocks, map[string]any{"type": "section", "fields": fields})
	}
	contextText := "`" + escapeSlackText(eventType) + "`"
	if timestamp := notificationTimestamp(incident); timestamp != "" {
		contextText += " • " + escapeSlackText(timestamp)
	}
	blocks = append(blocks, map[string]any{
		"type": "context",
		"elements": []map[string]any{{
			"type": "mrkdwn",
			"text": contextText,
		}},
	})
	return blocks
}
