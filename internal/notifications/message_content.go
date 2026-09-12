package notifications

import (
	"strings"
	"time"

	"github.com/example/autostream-observability/internal/store"
)

func formatIncidentText(eventType string, incident store.Incident) string {
	content := buildNotificationContent(eventType, incident)
	parts := []string{notificationTitle(eventType, incident), ""}
	for _, field := range notificationMessageFields(eventType, incident) {
		parts = append(parts, field.Name+": "+field.Value)
	}
	if timestamp := notificationTimestamp(incident); timestamp != "" {
		parts = append(parts, "日時: "+timestamp)
	}
	if description := joinNotificationDetails(content.Summary, content.Diagnosis); description != "" {
		parts = append(parts, "", "詳細", description)
	}
	if len(content.Actions) > 0 {
		parts = append(parts, "", "推奨対応", "- "+strings.Join(content.Actions, "\n- "))
	}
	if len(content.Evidence) > 0 {
		parts = append(parts, "", "根拠", "- "+strings.Join(content.Evidence, "\n- "))
	}
	return strings.Join(parts, "\n")
}

func notificationContextValue(summary string, keys ...string) string {
	for _, line := range strings.Split(strings.ReplaceAll(summary, "\r\n", "\n"), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(parts) != 2 {
			continue
		}
		for _, key := range keys {
			if strings.EqualFold(strings.TrimSpace(parts[0]), key) {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

type notificationMessageField struct {
	Name  string
	Value string
}

func notificationTitle(eventType string, incident store.Incident) string {
	if normalizedEventType(eventType) == "admin.audit" {
		return NotificationActionLabel(incident.Rule)
	}
	label := notificationEventLabel(eventType)
	if rule := strings.TrimSpace(incident.Rule); rule != "" {
		return label + ": " + notificationRuleLabel(rule)
	}
	return label
}

func notificationMessageFields(eventType string, incident store.Incident) []notificationMessageField {
	fields := []notificationMessageField{
		{Name: "重要度", Value: notificationSeverityLabel(incident.Severity)},
		{Name: "結果", Value: notificationStatusLabel(incident.Status)},
	}
	if rule := strings.TrimSpace(incident.Rule); rule != "" {
		name := "ルール"
		if normalizedEventType(eventType) == "admin.audit" {
			name = "操作コード"
		}
		fields = append(fields, notificationMessageField{Name: name, Value: notificationRuleValue(eventType, rule)})
	}
	if target := notificationTargetValue(incident); target != "" {
		fields = append(fields, notificationMessageField{Name: "対象", Value: target})
	}
	if serviceID := strings.TrimSpace(incident.ServiceID); serviceID != "" {
		fields = append(fields, notificationMessageField{Name: "サービス", Value: serviceID})
	}
	if streamID := strings.TrimSpace(incident.StreamID); streamID != "" && !notificationTargetIsStream(incident, streamID) {
		fields = append(fields, notificationMessageField{Name: "配信枠", Value: streamID})
	}
	if actor := notificationActorValue(incident); actor != "" {
		fields = append(fields, notificationMessageField{Name: "実行者", Value: actor})
	}
	return fields
}

func notificationDescription(eventType string, incident store.Incident) string {
	content := buildNotificationContent(eventType, incident)
	return joinNotificationDetails(content.Summary, content.Diagnosis)
}

type notificationContent struct {
	Summary   string
	Diagnosis string
	Actions   []string
	Evidence  []string
}

func buildNotificationContent(eventType string, incident store.Incident) notificationContent {
	content := notificationContent{
		Actions:  compactNotificationList(incident.Report.RecommendedActions),
		Evidence: compactNotificationList(incident.Report.Evidence),
	}
	if normalizedEventType(eventType) == "admin.audit" {
		content.Summary = strings.TrimSpace(incident.NotificationDetails)
		if content.Summary == "" {
			content.Summary = legacyNotificationDetails(incident.SummaryJA, notificationTitle(eventType, incident))
		}
		if content.Summary == "" {
			content.Summary = legacyNotificationDetails(incident.SourceSummary, notificationTitle(eventType, incident))
		}
		return content
	}
	description := strings.TrimSpace(incident.SummaryJA)
	title := strings.TrimSpace(notificationTitle(eventType, incident))
	if description == title {
		description = ""
	}
	if strings.HasPrefix(description, title+"\n") {
		description = strings.TrimSpace(strings.TrimPrefix(description, title+"\n"))
	}
	content.Summary = description
	content.Diagnosis = incidentReportDetails(incident)
	return content
}

func notificationAdditionalDetails(eventType string, incident store.Incident) string {
	if normalizedEventType(eventType) == "admin.audit" {
		return ""
	}
	return buildNotificationContent(eventType, incident).Diagnosis
}

func notificationRuleValue(eventType, rule string) string {
	rule = strings.TrimSpace(rule)
	if rule == "" {
		return ""
	}
	var label string
	if normalizedEventType(eventType) == "admin.audit" {
		label = NotificationActionLabel(rule)
	} else {
		label = notificationRuleLabel(rule)
	}
	if label == "" || label == rule {
		return rule
	}
	return label + " (" + rule + ")"
}

func notificationTargetValue(incident store.Incident) string {
	resourceType := strings.TrimSpace(incident.NotificationResourceType)
	resourceID := strings.TrimSpace(incident.NotificationResourceID)
	if resourceType == "" || resourceID == "" {
		description := strings.TrimSpace(incident.NotificationDetails)
		if description == "" {
			description = incident.SummaryJA
		}
		if resourceType == "" {
			resourceType = notificationContextValue(description, "対象種別", "resource_type")
		}
		if resourceID == "" {
			resourceID = notificationContextValue(description, "resource_id")
		}
	}
	if resourceType == "" {
		if target := notificationContextValue(incident.SummaryJA, "対象"); target != "" {
			return target
		}
		return ""
	}
	label := NotificationResourceLabel(resourceType)
	if resourceID == "" {
		return label
	}
	return label + " (" + resourceID + ")"
}

func notificationTargetIsStream(incident store.Incident, streamID string) bool {
	return strings.EqualFold(strings.TrimSpace(incident.NotificationResourceType), "stream") && strings.TrimSpace(incident.NotificationResourceID) == strings.TrimSpace(streamID)
}

func notificationActorValue(incident store.Incident) string {
	if actor := strings.TrimSpace(incident.NotificationActor); actor != "" {
		return actor
	}
	description := strings.TrimSpace(incident.NotificationDetails)
	if description == "" {
		description = incident.SummaryJA
	}
	return notificationContextValue(description, "実行者", "actor")
}

func legacyNotificationDetails(summary, title string) string {
	var details []string
	for _, line := range strings.Split(strings.ReplaceAll(summary, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == strings.TrimSpace(title) {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(line, "対象:") || strings.HasPrefix(line, "実行者:") || strings.HasPrefix(lower, "resource") || strings.HasPrefix(lower, "actor") {
			continue
		}
		if strings.HasPrefix(line, "詳細:") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "詳細:"))
		}
		if line != "" {
			details = append(details, line)
		}
	}
	return strings.Join(details, "\n")
}

func incidentReportDetails(incident store.Incident) string {
	var details []string
	if summary := strings.TrimSpace(incident.Report.Summary); summary != "" && summary != strings.TrimSpace(incident.SummaryJA) {
		details = append(details, "診断: "+summary)
	}
	if cause := strings.TrimSpace(incident.Report.LikelyCause); cause != "" {
		details = append(details, "原因候補: "+cause)
	}
	if impact := strings.TrimSpace(incident.Report.Impact); impact != "" {
		details = append(details, "影響: "+impact)
	}
	return strings.Join(details, "\n")
}

func compactNotificationList(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
		if len(out) == 6 {
			break
		}
	}
	return out
}

func joinNotificationDetails(parts ...string) string {
	var out []string
	seen := map[string]struct{}{}
	for _, part := range parts {
		for _, line := range strings.Split(strings.ReplaceAll(part, "\r\n", "\n"), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if _, ok := seen[line]; ok {
				continue
			}
			seen[line] = struct{}{}
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

func notificationTimestamp(incident store.Incident) string {
	if !incident.UpdatedAt.IsZero() {
		return incident.UpdatedAt.UTC().Format(time.RFC3339)
	}
	if !incident.OpenedAt.IsZero() {
		return incident.OpenedAt.UTC().Format(time.RFC3339)
	}
	return ""
}

func notificationColor(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "error":
		return 0xd92d20
	case "warning":
		return 0xf79009
	case "info":
		return 0x1570ef
	default:
		return 0x667085
	}
}

func truncateNotificationText(value string, maxRunes int) string {
	value = strings.TrimSpace(value)
	if maxRunes <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= maxRunes {
		return value
	}
	if maxRunes == 1 {
		return "…"
	}
	return string(runes[:maxRunes-1]) + "…"
}
