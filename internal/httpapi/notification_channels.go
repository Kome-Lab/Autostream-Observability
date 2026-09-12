package httpapi

import (
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/example/autostream-observability/internal/notifications"
	"github.com/example/autostream-observability/internal/store"
)

type notificationChannelRequest struct {
	Name            string   `json:"name"`
	Type            string   `json:"type"`
	Enabled         bool     `json:"enabled"`
	UseGlobalSMTP   *bool    `json:"uses_global_smtp"`
	WebhookURL      string   `json:"webhook_url"`
	EmailRecipients []string `json:"email_recipients"`
	SeverityFilter  []string `json:"severity_filter"`
	EventTypeFilter []string `json:"event_type_filter"`
}

func (s *Server) listNotificationChannels(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeNotificationsRead) {
		return
	}
	channels, err := s.store.ListNotificationChannels(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "list_notification_channels_failed"})
		return
	}
	writeJSON(w, http.StatusOK, publicNotificationChannels(channels))
}

func (s *Server) createNotificationChannel(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeNotificationsManage) {
		return
	}
	var body notificationChannelRequest
	if err := decodeJSONBody(w, r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "bad_request"})
		return
	}
	channel := notificationChannelFromRequest(body)
	if channel.Name == "" || !validNotificationChannelConfig(channel) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_notification_channel"})
		return
	}
	if channel.Type != "email" {
		normalizedURL, err := notifications.NormalizeWebhookURLForType(channel.WebhookURL, channel.Type)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_webhook_url"})
			return
		}
		channel.WebhookURL = normalizedURL
	}
	created, err := s.store.CreateNotificationChannel(r.Context(), channel)
	if errors.Is(err, store.ErrSecretKeyRequired) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"code": "secret_encryption_key_required"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "create_notification_channel_failed"})
		return
	}
	writeJSON(w, http.StatusCreated, publicNotificationChannel(created))
}

func (s *Server) getNotificationChannel(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeNotificationsRead) {
		return
	}
	channel, err := s.store.GetNotificationChannel(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"code": "not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "get_notification_channel_failed"})
		return
	}
	writeJSON(w, http.StatusOK, publicNotificationChannel(channel))
}

func (s *Server) updateNotificationChannel(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeNotificationsManage) {
		return
	}
	var body notificationChannelRequest
	if err := decodeJSONBody(w, r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "bad_request"})
		return
	}
	channel := notificationChannelFromRequest(body)
	channel.ID = r.PathValue("id")
	effective := channel
	if existing, err := s.store.GetNotificationChannel(r.Context(), channel.ID); errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"code": "not_found"})
		return
	} else if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "get_notification_channel_failed"})
		return
	} else {
		effective = effectiveNotificationChannel(existing, channel)
	}
	if effective.Name == "" || !validNotificationChannelConfig(effective) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_notification_channel"})
		return
	}
	if effective.Type != "email" && effective.WebhookURL != "" {
		normalizedURL, err := notifications.NormalizeWebhookURLForType(effective.WebhookURL, effective.Type)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_webhook_url"})
			return
		}
		channel.WebhookURL = normalizedURL
	}
	updated, err := s.store.UpdateNotificationChannel(r.Context(), channel)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"code": "not_found"})
		return
	}
	if errors.Is(err, store.ErrSecretKeyRequired) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"code": "secret_encryption_key_required"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "update_notification_channel_failed"})
		return
	}
	writeJSON(w, http.StatusOK, publicNotificationChannel(updated))
}

func (s *Server) deleteNotificationChannel(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeNotificationsManage) {
		return
	}
	if err := s.store.DeleteNotificationChannel(r.Context(), r.PathValue("id")); errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"code": "not_found"})
		return
	} else if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "delete_notification_channel_failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) testNotificationChannel(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeNotificationsManage) {
		return
	}
	channel, err := s.store.GetNotificationChannel(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"code": "not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "get_notification_channel_failed"})
		return
	}
	testIncident := store.Incident{ID: "test", Rule: "notification_test", Severity: "info", Status: "open", SummaryJA: "Notification channel test.", ServiceID: s.serviceType}
	timeout := notificationWebhookTimeout
	if channel.Type == "email" {
		timeout = notificationEmailTimeout
	}
	notifier := notifications.NotifierForChannelWithRelay(channel, timeout, 0, time.Second, nil, false, s.emailRelay)
	results, _ := notifier.NotifyIncidentEvent(r.Context(), "incident.opened", testIncident)
	for i := range results {
		results[i].Target = notificationChannelTarget(channel)
	}
	s.saveNotificationDeliveryResults(r.Context(), "incident.opened", testIncident, results)
	writeJSON(w, http.StatusAccepted, results)
}

func notificationChannelFromRequest(body notificationChannelRequest) store.NotificationChannel {
	channelType := strings.ToLower(strings.TrimSpace(body.Type))
	channel := store.NotificationChannel{
		Name:             strings.TrimSpace(body.Name),
		Type:             channelType,
		Enabled:          body.Enabled,
		UseGlobalSMTPSet: body.UseGlobalSMTP != nil,
		WebhookURL:       strings.TrimSpace(body.WebhookURL),
		EmailRecipients:  cleanStringSlice(body.EmailRecipients),
		SeverityFilter:   body.SeverityFilter,
		EventTypeFilter:  body.EventTypeFilter,
	}
	if body.UseGlobalSMTP != nil {
		channel.UseGlobalSMTP = *body.UseGlobalSMTP
	}
	return channel
}

func effectiveNotificationChannel(existing, incoming store.NotificationChannel) store.NotificationChannel {
	effective := existing
	if incoming.Name != "" {
		effective.Name = incoming.Name
	}
	if incoming.Type != "" {
		effective.Type = incoming.Type
	}
	effective.Enabled = incoming.Enabled
	if incoming.UseGlobalSMTPSet {
		effective.UseGlobalSMTP = incoming.UseGlobalSMTP
		effective.UseGlobalSMTPSet = true
	}
	if incoming.WebhookURL != "" {
		effective.WebhookURL = incoming.WebhookURL
	}
	if incoming.EmailRecipients != nil {
		effective.EmailRecipients = append([]string(nil), incoming.EmailRecipients...)
	}
	if incoming.SeverityFilter != nil {
		effective.SeverityFilter = append([]string(nil), incoming.SeverityFilter...)
	}
	if incoming.EventTypeFilter != nil {
		effective.EventTypeFilter = append([]string(nil), incoming.EventTypeFilter...)
	}
	return effective
}

type publicNotificationChannelResponse struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Type              string   `json:"type"`
	Enabled           bool     `json:"enabled"`
	UseGlobalSMTP     bool     `json:"uses_global_smtp"`
	MaskedWebhookURL  string   `json:"masked_webhook_url,omitempty"`
	MaskedEmailTarget string   `json:"masked_email_target,omitempty"`
	SeverityFilter    []string `json:"severity_filter,omitempty"`
	EventTypeFilter   []string `json:"event_type_filter,omitempty"`
	CreatedAt         string   `json:"created_at,omitempty"`
	UpdatedAt         string   `json:"updated_at,omitempty"`
}

func publicNotificationChannels(channels []store.NotificationChannel) []publicNotificationChannelResponse {
	out := make([]publicNotificationChannelResponse, 0, len(channels))
	for _, channel := range channels {
		out = append(out, publicNotificationChannel(channel))
	}
	return out
}

func publicNotificationChannel(channel store.NotificationChannel) publicNotificationChannelResponse {
	response := publicNotificationChannelResponse{
		ID:                channel.ID,
		Name:              channel.Name,
		Type:              channel.Type,
		Enabled:           channel.Enabled,
		UseGlobalSMTP:     channel.UseGlobalSMTP,
		MaskedWebhookURL:  channel.MaskedWebhookURL,
		MaskedEmailTarget: channel.MaskedEmailTarget,
		SeverityFilter:    append([]string(nil), channel.SeverityFilter...),
		EventTypeFilter:   append([]string(nil), channel.EventTypeFilter...),
	}
	if !channel.CreatedAt.IsZero() {
		response.CreatedAt = channel.CreatedAt.UTC().Format(time.RFC3339)
	}
	if !channel.UpdatedAt.IsZero() {
		response.UpdatedAt = channel.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return response
}

func validNotificationChannelConfig(channel store.NotificationChannel) bool {
	if channel.UseGlobalSMTP && channel.Type != "email" {
		return false
	}
	if channel.Type == "email" {
		if !channel.UseGlobalSMTPSet || !channel.UseGlobalSMTP || len(channel.EmailRecipients) == 0 || !safeEmailRecipients(channel.EmailRecipients) {
			return false
		}
		return true
	}
	return channel.WebhookURL != ""
}

func safeEmailRecipients(recipients []string) bool {
	if len(recipients) == 0 || len(recipients) > 20 {
		return false
	}
	seen := make(map[string]struct{}, len(recipients))
	for _, recipient := range recipients {
		recipient = strings.TrimSpace(recipient)
		if len(recipient) > 320 || !safeEmailHeaderValue(recipient) {
			return false
		}
		address, err := mail.ParseAddress(recipient)
		if err != nil || address.Address != recipient {
			return false
		}
		key := strings.ToLower(recipient)
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

func safeEmailHeaderValue(value string) bool {
	return !strings.ContainsAny(value, "\r\n")
}

func notificationChannelTarget(channel store.NotificationChannel) string {
	if channel.Type == "email" {
		if channel.MaskedEmailTarget != "" {
			return channel.MaskedEmailTarget
		}
		return "<EMAIL>"
	}
	if channel.MaskedWebhookURL != "" {
		return channel.MaskedWebhookURL
	}
	return "<WEBHOOK_URL>"
}

func cleanStringSlice(values []string) []string {
	if values == nil {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}
