package httpapi

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/example/autostream-observability/internal/notifications"
	"github.com/example/autostream-observability/internal/store"
)

var notificationActionPattern = regexp.MustCompile(`^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*$`)

var notificationResourceTypePattern = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

type notificationEventRequest struct {
	EventType     string `json:"event_type"`
	Severity      string `json:"severity"`
	Status        string `json:"status"`
	Action        string `json:"action"`
	ServiceID     string `json:"service_id"`
	ResourceType  string `json:"resource_type"`
	ResourceID    string `json:"resource_id"`
	ActorUsername string `json:"actor_username"`
	Summary       string `json:"summary"`
	Details       string `json:"details"`
	Timestamp     string `json:"timestamp"`
}

func (s *Server) createNotificationEvent(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeNotificationsManage) {
		return
	}
	var body notificationEventRequest
	if err := decodeJSONBody(w, r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "bad_request"})
		return
	}
	eventType := strings.TrimSpace(body.EventType)
	if eventType == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "event_type_required"})
		return
	}
	if !validNotificationEventType(eventType) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_notification_event"})
		return
	}
	incident, err := notificationIncidentFromRequest(body, s.serviceType)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_notification_event"})
		return
	}
	results := s.deliverNotificationEvent(r, eventType, incident)
	writeJSON(w, http.StatusAccepted, results)
}

func notificationIncidentFromRequest(body notificationEventRequest, fallbackService string) (store.Incident, error) {
	action := strings.TrimSpace(body.Action)
	if !validNotificationAction(action) {
		return store.Incident{}, errors.New("action is required")
	}
	resourceType := safeNotificationResourceType(body.ResourceType)
	resourceID := safeNotificationField(body.ResourceID, 160)
	actor := safeNotificationField(body.ActorUsername, 80)
	serviceID := safeNotificationField(body.ServiceID, 160)
	if serviceID == "" && !strings.EqualFold(strings.TrimSpace(fallbackService), "observability") {
		serviceID = safeNotificationField(fallbackService, 160)
	}
	// A missing service_id describes the producer, not the Observability
	// process that happens to receive the request. Never attribute an event to
	// the receiver merely because it was delivered through this endpoint.
	if serviceID == "" || strings.EqualFold(serviceID, "observability") {
		serviceID = "control-panel"
	}
	status := safeNotificationStatus(body.Status)
	severity := safeNotificationSeverity(body.Severity)
	callerSummary := safeNotificationField(body.Summary, 240)
	details := safeNotificationField(body.Details, 3000)
	sourceSummary := callerSummary
	legacySummary := "管理イベント: " + action + " / " + status
	if sourceSummary == "" {
		sourceSummary = legacySummary
	}
	legacyResourceType := safeNotificationField(body.ResourceType, 80)
	if legacyResourceType != "" {
		sourceSummary += " / " + legacyResourceType
		if resourceID != "" {
			sourceSummary += " " + resourceID
		}
	}
	if actor != "" {
		sourceSummary += " / actor=" + actor
	}
	summary := sourceSummary
	if strings.TrimSpace(body.EventType) == "admin.audit" {
		actionLabel := notifications.NotificationActionLabel(action)
		parts := []string{actionLabel}
		if resourceType != "" {
			target := notifications.NotificationResourceLabel(resourceType)
			if resourceID != "" {
				target += " (" + resourceID + ")"
			}
			parts = append(parts, "対象: "+target)
		}
		if actor != "" {
			parts = append(parts, "実行者: "+actor)
		}
		if callerSummary != "" && callerSummary != legacySummary && callerSummary != parts[0] {
			parts = append(parts, "詳細: "+callerSummary)
		}
		summary = strings.Join(parts, "\n")
	}
	var occurredAt time.Time
	if timestamp := strings.TrimSpace(body.Timestamp); timestamp != "" {
		parsed, err := time.Parse(time.RFC3339, timestamp)
		if err != nil {
			return store.Incident{}, errors.New("timestamp must be RFC3339")
		}
		occurredAt = parsed.UTC()
	}
	return store.Incident{
		Rule:                     action,
		Severity:                 severity,
		Status:                   status,
		SummaryJA:                summary,
		SourceSummary:            sourceSummary,
		ServiceID:                serviceID,
		NotificationResourceType: resourceType,
		NotificationResourceID:   resourceID,
		NotificationActor:        actor,
		NotificationDetails:      details,
		UpdatedAt:                occurredAt,
	}, nil
}

func validNotificationEventType(value string) bool {
	switch value {
	case "incident.opened", "incident.updated", "incident.resolved", "diagnostic.created", "remediation.pending_approval", "remediation.executed", "admin.audit":
		return true
	default:
		return false
	}
}

func validNotificationAction(value string) bool {
	return value != "" && len(value) <= 128 && notificationActionPattern.MatchString(value)
}

func safeNotificationField(value string, maxLen int) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = strings.Map(func(char rune) rune {
		switch char {
		case '\n', '\r', '\t':
			return char
		default:
			if char < 0x20 || (char >= 0x7f && char <= 0x9f) {
				return -1
			}
			return char
		}
	}, value)
	value = strings.TrimSpace(value)
	if safeEvidenceValue(value) == "<redacted>" {
		return ""
	}
	if maxLen > 0 {
		runes := []rune(value)
		if len(runes) > maxLen {
			return string(runes[:maxLen])
		}
	}
	return value
}

func safeNotificationResourceType(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 80 || !notificationResourceTypePattern.MatchString(value) {
		return ""
	}
	return value
}

func safeNotificationSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical", "error", "warning", "info":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "info"
	}
}

func safeNotificationStatus(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || safeEvidenceValue(value) == "<redacted>" {
		return "recorded"
	}
	if len(value) > 64 {
		return value[:64]
	}
	return value
}
