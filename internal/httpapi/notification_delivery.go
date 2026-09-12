package httpapi

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/example/autostream-observability/internal/control"
	"github.com/example/autostream-observability/internal/notifications"
	"github.com/example/autostream-observability/internal/store"
)

type envEmailRelay struct{}

func (envEmailRelay) SendNotificationEmail(ctx context.Context, recipients []string, subject, text string) error {
	return control.FromEnv().SendNotificationEmail(ctx, recipients, subject, text)
}

func (envEmailRelay) SendNotificationEmailHTML(ctx context.Context, recipients []string, subject, text, html string) error {
	return control.FromEnv().SendNotificationEmailHTML(ctx, recipients, subject, text, html)
}

func (s *Server) listNotificationDeliveries(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeNotificationsRead) {
		return
	}
	deliveries, err := s.store.ListNotificationDeliveries(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "list_notification_deliveries_failed"})
		return
	}
	writeJSON(w, http.StatusOK, deliveries)
}

func (s *Server) notifyIncidentEvent(r *http.Request, eventType string, incident store.Incident) {
	_ = s.deliverNotificationEvent(r, eventType, incident)
}

func (s *Server) deliverNotificationEvent(r *http.Request, eventType string, incident store.Incident) []notifications.DeliveryResult {
	if s.notifier == nil {
		return nil
	}
	reservation := s.notificationDedupe.reserve(eventType, incident, time.Now().UTC())
	if !reservation.allowed {
		if reservation.recordSuppression {
			s.saveSuppressedNotificationDelivery(r, eventType, incident, reservation.suppressionCount)
		}
		return []notifications.DeliveryResult{{
			EventType: eventType,
			Channel:   "dedupe",
			Target:    "<NOTIFICATION_DEDUPLICATED>",
			Status:    "suppressed",
		}}
	}
	// Notification delivery must not be canceled just because the originating
	// HTTP client used a shorter request timeout. Keep request values, detach
	// cancellation, and retain a hard deadline so a stuck provider cannot keep
	// the handler alive indefinitely.
	deliveryContext, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), notificationFanoutTimeout)
	defer cancel()
	var results []notifications.DeliveryResult
	var err error
	if selectiveNotifier, ok := s.notifier.(notifications.ChannelSelectiveIncidentEventNotifier); ok && len(reservation.successfulChannelIDs) > 0 {
		results, err = selectiveNotifier.NotifyIncidentEventExceptChannels(deliveryContext, eventType, incident, reservation.successfulChannelIDs)
	} else {
		results, err = notifications.NotifyIncidentEvent(deliveryContext, s.notifier, eventType, incident)
	}
	if err != nil && len(results) == 0 {
		results = []notifications.DeliveryResult{{EventType: eventType, Channel: "generic", Target: "<WEBHOOK_URL>", Status: "failure", Error: notifications.SanitizeDeliveryError(err)}}
	}
	s.notificationDedupe.complete(reservation, results)
	s.saveNotificationDeliveryResults(deliveryContext, eventType, incident, results)
	return results
}

func notificationDeliverySucceeded(results []notifications.DeliveryResult) bool {
	// Keep a semantic event eligible for another fan-out until every selected
	// destination accepts it. In particular, a successful email must not cause
	// a failed Discord delivery to be suppressed by the short dedupe window.
	if len(results) == 0 {
		return false
	}
	for _, result := range results {
		status := strings.TrimSpace(result.Status)
		if strings.TrimSpace(result.Error) != "" || (status != "" && !strings.EqualFold(status, "success")) {
			return false
		}
	}
	return true
}

func (s *Server) saveSuppressedNotificationDelivery(r *http.Request, eventType string, incident store.Incident, suppressionCount int) {
	if s.store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), notificationFanoutTimeout)
	defer cancel()
	metadata := notificationDeliveryMetadata(eventType, incident)
	metadata["suppression_reason"] = "duplicate_semantic_event"
	metadata["suppression_count_at_record"] = suppressionCount
	metadata["coalescing_active"] = true
	if _, err := s.store.SaveNotificationDelivery(ctx, store.NotificationDelivery{
		EventType:  eventType,
		Channel:    "dedupe",
		Target:     "<NOTIFICATION_DEDUPLICATED>",
		IncidentID: incident.ID,
		Status:     "suppressed",
		Metadata:   metadata,
	}); err != nil {
		logger := s.logger
		if logger == nil {
			logger = log.Default()
		}
		logger.Printf("notification coalescing audit save failed: event_type=%q", eventType)
	}
}

func (s *Server) saveNotificationDeliveryResults(ctx context.Context, eventType string, incident store.Incident, results []notifications.DeliveryResult) {
	for _, result := range results {
		status := result.Status
		if status == "" {
			status = "success"
		}
		errorText := notifications.SanitizeChannelDeliveryError(result.Channel, errors.New(result.Error))
		if result.Error == "" {
			errorText = ""
		}
		if errorText != "" {
			status = "failure"
		}
		if result.EventType == "" {
			result.EventType = eventType
		}
		metadata := notificationDeliveryMetadata(result.EventType, incident)
		_, err := s.store.SaveNotificationDelivery(ctx, store.NotificationDelivery{
			EventType:  result.EventType,
			Channel:    result.Channel,
			Target:     result.Target,
			IncidentID: incident.ID,
			Status:     status,
			Error:      errorText,
			Metadata:   metadata,
		})
		if err != nil {
			logger := s.logger
			if logger == nil {
				logger = log.Default()
			}
			logger.Printf("notification delivery history save failed: event_type=%q channel=%q status=%q", result.EventType, result.Channel, status)
		}
	}
}

func notificationDeliveryMetadata(eventType string, incident store.Incident) map[string]any {
	metadata := map[string]any{
		"severity": incident.Severity,
		"rule":     incident.Rule,
		"summary":  incident.SummaryJA,
	}
	if incident.ServiceID != "" {
		metadata["service_id"] = incident.ServiceID
	}
	if incident.StreamID != "" {
		metadata["stream_id"] = incident.StreamID
	}
	if incident.NotificationResourceType != "" {
		metadata["resource_type"] = incident.NotificationResourceType
	}
	if incident.NotificationResourceID != "" {
		metadata["resource_id"] = incident.NotificationResourceID
	}
	if eventType == "admin.audit" {
		metadata["action"] = incident.Rule
	}
	if !incident.UpdatedAt.IsZero() {
		metadata["occurred_at"] = incident.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return metadata
}
