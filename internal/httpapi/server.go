package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/example/autostream-observability/internal/auth"
	"github.com/example/autostream-observability/internal/control"
	"github.com/example/autostream-observability/internal/detection"
	"github.com/example/autostream-observability/internal/diagnostics"
	"github.com/example/autostream-observability/internal/notifications"
	"github.com/example/autostream-observability/internal/remediation"
	"github.com/example/autostream-observability/internal/store"
)

type Status struct {
	ServiceType string    `json:"service_type"`
	ServiceID   string    `json:"service_id"`
	Status      string    `json:"status"`
	CheckedAt   time.Time `json:"checked_at"`
}

var standaloneSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bAIza[0-9A-Za-z_-]{35}\b`),
	regexp.MustCompile(`\beyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\b`),
	regexp.MustCompile(`\bmfa\.[0-9A-Za-z_-]{60,}\b`),
	regexp.MustCompile(`\b[MN][0-9A-Za-z]{23}\.[0-9A-Za-z_-]{6}\.[0-9A-Za-z_-]{27}\b`),
}

type Server struct {
	serviceType string
	store       store.Store
	ingestAuth  auth.Verifier
	adminAuth   auth.Verifier
	notifier    notifications.Notifier
	executor    controlExecutor
	rateLimiter *rateLimiter
}

const maxJSONBodyBytes = 64 << 10

const (
	adminScopeRead                = "observability.read"
	adminScopeIngest              = "observability.ingest"
	adminScopeIncidentsUpdate     = "incidents.update"
	adminScopeNotificationsRead   = "notifications.read"
	adminScopeNotificationsManage = "notifications.manage"
	adminScopeRemediationRead     = "remediation.read"
	adminScopeRemediationApprove  = "remediation.approve"
	adminScopeRemediationExecute  = "remediation.execute"
)

type controlExecutor interface {
	ExecuteRemediation(ctx context.Context, req control.RemediationRequest) error
}

type envControlExecutor struct{}

func (envControlExecutor) ExecuteRemediation(ctx context.Context, req control.RemediationRequest) error {
	return control.FromEnv().ExecuteRemediation(ctx, req)
}

type IngestResponse struct {
	Signal    store.Signal     `json:"signal"`
	Incidents []store.Incident `json:"incidents"`
}

type DiagnosticReportView struct {
	IncidentID string             `json:"incident_id"`
	Rule       string             `json:"rule"`
	Severity   string             `json:"severity"`
	Status     string             `json:"status"`
	ServiceID  string             `json:"service_id"`
	StreamID   string             `json:"stream_id,omitempty"`
	Report     diagnostics.Report `json:"diagnostic_report"`
	UpdatedAt  time.Time          `json:"updated_at"`
}

type notificationChannelRequest struct {
	Name            string   `json:"name"`
	Type            string   `json:"type"`
	Enabled         bool     `json:"enabled"`
	WebhookURL      string   `json:"webhook_url"`
	EmailRecipients []string `json:"email_recipients"`
	SMTPHost        string   `json:"smtp_host"`
	SMTPPort        int      `json:"smtp_port"`
	SMTPTLS         *bool    `json:"smtp_tls"`
	SMTPFrom        string   `json:"smtp_from"`
	SMTPUsername    string   `json:"smtp_username"`
	SMTPPassword    string   `json:"smtp_password"`
	SeverityFilter  []string `json:"severity_filter"`
	EventTypeFilter []string `json:"event_type_filter"`
}

func NewServer(serviceType string) http.Handler {
	return NewServerWithStore(serviceType, store.NewMemoryStore())
}

func NewServerWithStore(serviceType string, st store.Store) http.Handler {
	return NewServerWithStoreAuthz(serviceType, st, auth.Verifier{}, auth.Verifier{})
}

func NewServerWithStoreAndAuth(serviceType string, st store.Store, verifier auth.Verifier) http.Handler {
	return NewServerWithStoreAuthAndNotifier(serviceType, st, verifier, notifications.ChannelNotifier{Store: st, Fallback: notifications.FromEnv(), Timeout: 5 * time.Second})
}

func NewServerWithStoreAuthAndNotifier(serviceType string, st store.Store, verifier auth.Verifier, notifier notifications.Notifier) http.Handler {
	return NewServerWithStoreAuthNotifierAndExecutor(serviceType, st, verifier, notifier, envControlExecutor{})
}

func NewServerWithStoreAuthNotifierAndExecutor(serviceType string, st store.Store, verifier auth.Verifier, notifier notifications.Notifier, executor controlExecutor) http.Handler {
	return NewServerWithStoreAuthzNotifierAndExecutor(serviceType, st, verifier, verifier, notifier, executor)
}

func NewServerWithStoreAuthz(serviceType string, st store.Store, ingestVerifier, adminVerifier auth.Verifier) http.Handler {
	return NewServerWithStoreAuthzNotifierAndExecutor(serviceType, st, ingestVerifier, adminVerifier, notifications.ChannelNotifier{Store: st, Fallback: notifications.FromEnv(), Timeout: 5 * time.Second}, envControlExecutor{})
}

func NewServerWithStoreAuthzNotifierAndExecutor(serviceType string, st store.Store, ingestVerifier, adminVerifier auth.Verifier, notifier notifications.Notifier, executor controlExecutor) http.Handler {
	if st == nil {
		st = store.NewMemoryStore()
	}
	s := &Server{serviceType: serviceType, store: st, ingestAuth: ingestVerifier, adminAuth: adminVerifier, notifier: notifier, executor: executor, rateLimiter: rateLimiterFromEnv(st)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /status", s.status)
	mux.HandleFunc("POST /heartbeat", s.heartbeat)
	mux.HandleFunc("POST /signals", s.ingestSignal)
	mux.HandleFunc("GET /signals", s.listSignals)
	mux.HandleFunc("GET /metrics", s.listMetrics)
	mux.HandleFunc("GET /diagnostics", s.listDiagnostics)
	mux.HandleFunc("GET /incidents", s.listIncidents)
	mux.HandleFunc("GET /incidents/{id}", s.getIncident)
	mux.HandleFunc("POST /incidents/{id}/acknowledge", s.acknowledgeIncident)
	mux.HandleFunc("POST /incidents/{id}/resolve", s.resolveIncident)
	mux.HandleFunc("GET /notification-deliveries", s.listNotificationDeliveries)
	mux.HandleFunc("GET /notification-channels", s.listNotificationChannels)
	mux.HandleFunc("POST /notification-channels", s.createNotificationChannel)
	mux.HandleFunc("GET /notification-channels/{id}", s.getNotificationChannel)
	mux.HandleFunc("PUT /notification-channels/{id}", s.updateNotificationChannel)
	mux.HandleFunc("DELETE /notification-channels/{id}", s.deleteNotificationChannel)
	mux.HandleFunc("POST /notification-channels/{id}/test", s.testNotificationChannel)
	mux.HandleFunc("GET /remediation-actions", s.listRemediationActions)
	mux.HandleFunc("GET /remediation-actions/{id}/dispatch-context", s.getRemediationDispatchContext)
	mux.HandleFunc("POST /remediation-actions/{id}/approve", s.approveRemediationAction)
	mux.HandleFunc("POST /remediation-actions/{id}/execute", s.executeRemediationAction)
	return securityHeaders(s.rateLimitSensitive(mux))
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, Status{ServiceType: s.serviceType, ServiceID: os.Getenv("SERVICE_ID"), Status: "ready", CheckedAt: time.Now().UTC()})
}

func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request) {
	if !s.ingestAuthorized(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"code": "invalid_service_token"})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func (s *Server) ingestSignal(w http.ResponseWriter, r *http.Request) {
	tokenSubject, ok := s.ingestAuth.VerifyRequestSubject(r)
	if !ok {
		authenticated, authorized := s.adminAuth.AuthorizeRequest(r, adminScopeIngest)
		if !authenticated {
			authenticated, authorized = nodeRuntimeVerifier().AuthorizeRequest(r, adminScopeIngest)
		}
		if !authenticated {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"code": "invalid_service_token"})
			return
		}
		if !authorized {
			writeJSON(w, http.StatusForbidden, map[string]string{"code": "admin_scope_required"})
			return
		}
	}
	var signal store.Signal
	if err := decodeJSONBody(w, r, &signal); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "bad_request"})
		return
	}
	if signal.Type == "" || signal.Name == "" || signal.ServiceID == "" || signal.ServiceType == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_signal"})
		return
	}
	if tokenSubject.ServiceID != "" && (tokenSubject.ServiceID != signal.ServiceID || tokenSubject.ServiceType != signal.ServiceType) {
		writeJSON(w, http.StatusForbidden, map[string]string{"code": "service_identity_mismatch"})
		return
	}
	if err := validateSignalTopLevelFields(signal); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_signal_identifier"})
		return
	}
	if err := validateSignalAttributes(signal.Attributes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_signal_attributes"})
		return
	}
	signal.Attributes = safeSignalAttributes(signal.Attributes)
	saved, err := s.store.SaveSignal(r.Context(), signal)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "save_signal_failed"})
		return
	}
	createdIncidents, err := s.evaluateAndStoreIncidents(r, saved)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "incident_evaluation_failed"})
		return
	}
	writeJSON(w, http.StatusAccepted, IngestResponse{Signal: safeSignal(saved), Incidents: createdIncidents})
}

func (s *Server) listSignals(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeRead) {
		return
	}
	signals, err := s.store.ListSignals(r.Context(), parseLimit(r, 200))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "list_signals_failed"})
		return
	}
	writeJSON(w, http.StatusOK, safeSignals(signals))
}

func (s *Server) listMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeRead) {
		return
	}
	signals, err := s.store.ListSignals(r.Context(), parseLimit(r, 500))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "list_metrics_failed"})
		return
	}
	writeJSON(w, http.StatusOK, metricSnapshots(signals))
}

func (s *Server) listDiagnostics(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeRead) {
		return
	}
	incidents, err := s.store.ListIncidents(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "list_diagnostics_failed"})
		return
	}
	out := make([]DiagnosticReportView, 0, len(incidents))
	for _, incident := range incidents {
		out = append(out, DiagnosticReportView{
			IncidentID: incident.ID,
			Rule:       incident.Rule,
			Severity:   incident.Severity,
			Status:     incident.Status,
			ServiceID:  incident.ServiceID,
			StreamID:   incident.StreamID,
			Report:     incident.Report,
			UpdatedAt:  incident.UpdatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listIncidents(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeRead) {
		return
	}
	incidents, err := s.store.ListIncidents(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "list_incidents_failed"})
		return
	}
	writeJSON(w, http.StatusOK, incidents)
}

func (s *Server) getIncident(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeRead) {
		return
	}
	incident, err := s.store.GetIncident(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"code": "not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "get_incident_failed"})
		return
	}
	writeJSON(w, http.StatusOK, incident)
}

func (s *Server) acknowledgeIncident(w http.ResponseWriter, r *http.Request) {
	s.updateIncidentStatus(w, r, "acknowledged")
}

func (s *Server) resolveIncident(w http.ResponseWriter, r *http.Request) {
	s.updateIncidentStatus(w, r, "resolved")
}

func (s *Server) updateIncidentStatus(w http.ResponseWriter, r *http.Request, status string) {
	if !s.authorizeAdmin(w, r, adminScopeIncidentsUpdate) {
		return
	}
	incident, err := s.store.UpdateIncidentStatus(r.Context(), r.PathValue("id"), status)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"code": "not_found"})
		return
	}
	if errors.Is(err, store.ErrInvalidStatus) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_incident_status"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "update_incident_failed"})
		return
	}
	eventType := "incident.updated"
	if status == "resolved" {
		eventType = "incident.resolved"
	}
	s.notifyIncidentEvent(r, eventType, incident)
	writeJSON(w, http.StatusOK, incident)
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
	if channel.Type == "email" {
		if err := notifications.ValidateSMTPChannel(channel); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_smtp_channel"})
			return
		}
	} else if notifications.ValidateWebhookURLForType(channel.WebhookURL, channel.Type) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_webhook_url"})
		return
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
	if effective.Type == "email" {
		if err := notifications.ValidateSMTPChannel(effective); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_smtp_channel"})
			return
		}
	} else if effective.WebhookURL != "" {
		if err := notifications.ValidateWebhookURLForType(effective.WebhookURL, effective.Type); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_webhook_url"})
			return
		}
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
	notifier := notifications.NotifierForChannel(channel, 5*time.Second, 0, time.Second, nil, false)
	results, _ := notifier.NotifyIncidentEvent(r.Context(), "incident.opened", store.Incident{ID: "test", Rule: "notification_test", Severity: "info", Status: "open", SummaryJA: "Notification channel test.", ServiceID: s.serviceType})
	for i := range results {
		results[i].Target = notificationChannelTarget(channel)
	}
	writeJSON(w, http.StatusAccepted, results)
}

func notificationChannelFromRequest(body notificationChannelRequest) store.NotificationChannel {
	channelType := strings.ToLower(strings.TrimSpace(body.Type))
	smtpTLS := false
	if channelType == "email" {
		smtpTLS = true
	}
	if body.SMTPTLS != nil {
		smtpTLS = *body.SMTPTLS
	}
	return store.NotificationChannel{
		Name:            strings.TrimSpace(body.Name),
		Type:            channelType,
		Enabled:         body.Enabled,
		WebhookURL:      strings.TrimSpace(body.WebhookURL),
		EmailRecipients: cleanStringSlice(body.EmailRecipients),
		SMTPHost:        strings.TrimSpace(body.SMTPHost),
		SMTPPort:        body.SMTPPort,
		SMTPTLS:         smtpTLS,
		SMTPFrom:        strings.TrimSpace(body.SMTPFrom),
		SMTPUsername:    strings.TrimSpace(body.SMTPUsername),
		SMTPPassword:    strings.TrimSpace(body.SMTPPassword),
		SeverityFilter:  body.SeverityFilter,
		EventTypeFilter: body.EventTypeFilter,
	}
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
	if incoming.WebhookURL != "" {
		effective.WebhookURL = incoming.WebhookURL
	}
	if incoming.EmailRecipients != nil {
		effective.EmailRecipients = append([]string(nil), incoming.EmailRecipients...)
	}
	if incoming.SMTPHost != "" {
		effective.SMTPHost = incoming.SMTPHost
	}
	if incoming.SMTPPort != 0 {
		effective.SMTPPort = incoming.SMTPPort
	}
	if incoming.SMTPTLS != existing.SMTPTLS {
		effective.SMTPTLS = incoming.SMTPTLS
	}
	if incoming.SMTPFrom != "" {
		effective.SMTPFrom = incoming.SMTPFrom
	}
	if incoming.SMTPUsername != "" {
		effective.SMTPUsername = incoming.SMTPUsername
	}
	if incoming.SMTPPassword != "" {
		effective.SMTPPassword = incoming.SMTPPassword
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
	ID                     string   `json:"id"`
	Name                   string   `json:"name"`
	Type                   string   `json:"type"`
	Enabled                bool     `json:"enabled"`
	MaskedWebhookURL       string   `json:"masked_webhook_url,omitempty"`
	SMTPPasswordConfigured bool     `json:"smtp_password_configured,omitempty"`
	MaskedEmailTarget      string   `json:"masked_email_target,omitempty"`
	SeverityFilter         []string `json:"severity_filter,omitempty"`
	EventTypeFilter        []string `json:"event_type_filter,omitempty"`
	CreatedAt              string   `json:"created_at,omitempty"`
	UpdatedAt              string   `json:"updated_at,omitempty"`
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
		ID:                     channel.ID,
		Name:                   channel.Name,
		Type:                   channel.Type,
		Enabled:                channel.Enabled,
		MaskedWebhookURL:       channel.MaskedWebhookURL,
		SMTPPasswordConfigured: channel.SMTPPasswordConfigured,
		MaskedEmailTarget:      channel.MaskedEmailTarget,
		SeverityFilter:         append([]string(nil), channel.SeverityFilter...),
		EventTypeFilter:        append([]string(nil), channel.EventTypeFilter...),
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
	if channel.Type == "email" {
		return len(channel.EmailRecipients) > 0 &&
			channel.SMTPHost != "" &&
			channel.SMTPFrom != "" &&
			safeEmailHeaderValue(channel.SMTPFrom) &&
			safeEmailHeaderValue(channel.SMTPUsername) &&
			safeEmailRecipients(channel.EmailRecipients)
	}
	return channel.WebhookURL != ""
}

func safeEmailRecipients(recipients []string) bool {
	for _, recipient := range recipients {
		if !safeEmailHeaderValue(recipient) {
			return false
		}
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
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func (s *Server) listRemediationActions(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeRemediationRead) {
		return
	}
	actions, err := s.store.ListRemediationActions(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "list_remediation_actions_failed"})
		return
	}
	writeJSON(w, http.StatusOK, actions)
}

type remediationDispatchContextResponse struct {
	ActionID       string `json:"action_id"`
	Action         string `json:"action"`
	ActionStatus   string `json:"action_status"`
	IncidentID     string `json:"incident_id"`
	IncidentStatus string `json:"incident_status"`
	StreamID       string `json:"stream_id"`
	Executable     bool   `json:"executable"`
}

func (s *Server) getRemediationDispatchContext(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeRemediationRead) {
		return
	}
	action, err := s.store.GetRemediationAction(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"code": "not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "get_remediation_action_failed"})
		return
	}
	incident, err := s.store.GetIncident(r.Context(), action.IncidentID)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusConflict, map[string]string{"code": "incident_context_missing"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "get_incident_failed"})
		return
	}
	if strings.TrimSpace(incident.StreamID) == "" {
		writeJSON(w, http.StatusConflict, map[string]string{"code": "stream_context_missing"})
		return
	}
	if remediation.IsTerminalStatus(action.Status) {
		writeJSON(w, http.StatusConflict, map[string]string{"code": "remediation_action_terminal"})
		return
	}
	if !remediationActionDispatchExecutable(action) {
		writeJSON(w, http.StatusConflict, map[string]string{"code": "remediation_action_not_executable"})
		return
	}
	writeJSON(w, http.StatusOK, remediationDispatchContextResponse{
		ActionID:       action.ID,
		Action:         action.Action,
		ActionStatus:   action.Status,
		IncidentID:     incident.ID,
		IncidentStatus: incident.Status,
		StreamID:       incident.StreamID,
		Executable:     true,
	})
}

func remediationActionDispatchExecutable(action store.RemediationAction) bool {
	if remediation.IsTerminalStatus(action.Status) || remediation.IsDangerous(action.Action) || !requiresControlPanelDispatch(action.Action) {
		return false
	}
	mode := remediation.NormalizeMode(action.Mode)
	if mode == remediation.ModeDisabled || mode == remediation.ModeSuggestOnly {
		return false
	}
	if mode == remediation.ModeManualApproval && action.Status != "approved" {
		return false
	}
	if action.RequiresApproval && action.Status != "approved" {
		return false
	}
	return action.SafeAuto || action.RequiresApproval
}

func (s *Server) approveRemediationAction(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeRemediationApprove) {
		return
	}
	action, err := s.store.GetRemediationAction(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"code": "not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "get_remediation_action_failed"})
		return
	}
	action = remediation.Approve(action)
	action, err = s.store.UpdateRemediationAction(r.Context(), action)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "approve_remediation_action_failed"})
		return
	}
	writeJSON(w, http.StatusOK, action)
}

func (s *Server) executeRemediationAction(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, adminScopeRemediationExecute) {
		return
	}
	action, err := s.store.GetRemediationAction(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"code": "not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "get_remediation_action_failed"})
		return
	}
	if remediation.IsTerminalStatus(action.Status) {
		action.Result = "remediation action is already terminal"
		writeJSON(w, http.StatusConflict, action)
		return
	}
	action = remediation.Execute(action)
	if action.Status == "executed" && requiresControlPanelDispatch(action.Action) {
		incident, err := s.store.GetIncident(r.Context(), action.IncidentID)
		if err != nil {
			action.Status = "blocked"
			action.Result = "incident context is required for control panel dispatch"
			action.ExecutedAt = nil
		} else if strings.TrimSpace(incident.StreamID) == "" {
			action.Status = "blocked"
			action.Result = "stream_id is required for control panel dispatch"
			action.ExecutedAt = nil
		} else if s.executor == nil {
			action.Status = "blocked"
			action.Result = "control panel dispatch is not configured"
			action.ExecutedAt = nil
		} else if err := s.executor.ExecuteRemediation(r.Context(), control.RemediationRequest{ActionID: action.ID, Action: action.Action, IncidentID: action.IncidentID, StreamID: incident.StreamID}); err != nil {
			action.Status = "blocked"
			action.Result = "control panel dispatch failed"
			action.ExecutedAt = nil
		} else {
			action.Result = "control_panel_dispatch_executed"
			if action.ExecutedAt == nil {
				now := time.Now().UTC()
				action.ExecutedAt = &now
			}
		}
	}
	action, err = s.store.UpdateRemediationAction(r.Context(), action)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "execute_remediation_action_failed"})
		return
	}
	if action.Status == "executed" {
		if incident, incidentErr := s.store.GetIncident(r.Context(), action.IncidentID); incidentErr == nil {
			s.notifyIncidentEvent(r, "remediation.executed", incident)
		}
	}
	status := http.StatusOK
	if action.Status == "blocked" {
		status = http.StatusForbidden
	}
	writeJSON(w, status, action)
}

func requiresControlPanelDispatch(action string) bool {
	switch action {
	case "retry_gdrive_upload", "retry_package_remux":
		return true
	default:
		return false
	}
}

func (s *Server) evaluateAndStoreIncidents(r *http.Request, signal store.Signal) ([]store.Incident, error) {
	value := 0.0
	if signal.Value != nil {
		value = *signal.Value
	}
	streamLive := signal.Attributes["stream_live"] == true || signal.Status == "live"
	detected := detection.Evaluate(detection.Signal{
		Type:       signal.Type,
		Name:       signal.Name,
		Value:      value,
		StreamID:   signal.StreamID,
		StreamLive: streamLive,
		Status:     signal.Status,
		Attributes: signal.Attributes,
	})
	out := make([]store.Incident, 0, len(detected))
	for _, detectedIncident := range detected {
		evidence := []string{
			"signal_id=" + signal.ID,
			"signal_name=" + signal.Name,
			"service_id=" + signal.ServiceID,
		}
		if signal.StreamID != "" {
			evidence = append(evidence, "stream_id="+signal.StreamID)
		}
		evidence = append(evidence, safeAttributeEvidence(signal.Attributes)...)
		incident := store.Incident{
			Rule:      detectedIncident.Rule,
			Severity:  detectedIncident.Severity,
			Status:    "open",
			SummaryJA: detectedIncident.SummaryJA,
			ServiceID: signal.ServiceID,
			StreamID:  signal.StreamID,
			SignalID:  signal.ID,
			Report:    diagnostics.JapaneseReport(detectedIncident.Rule, evidence),
		}
		stored, created, err := s.store.UpsertIncident(r.Context(), incident)
		if err != nil {
			return nil, err
		}
		if created {
			s.notifyIncidentEvent(r, "incident.opened", stored)
			s.notifyIncidentEvent(r, "diagnostic.created", stored)
			if err := s.createRemediationActions(r, stored); err != nil {
				return nil, err
			}
		}
		out = append(out, stored)
	}
	return out, nil
}

func safeAttributeEvidence(attributes map[string]any) []string {
	if len(attributes) == 0 {
		return nil
	}
	allowed := []string{
		"failure_phase", "error_class", "dry_run", "upload_dry_run", "upload_attempts", "file_count", "remux_duration_ms",
		"discord.audio_forwarded_total", "discord.audio_forward_errors_total", "discord.audio_last_forward_age_sec", "discord.audio_last_packet_age_sec",
		"discord.worker_event_publish_failures_total",
	}
	out := make([]string, 0, len(allowed))
	for _, key := range allowed {
		value, ok := attributes[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case string:
			if safeValue := safeEvidenceValue(typed); safeValue != "" {
				out = append(out, key+"="+safeValue)
			}
		case bool:
			if typed {
				out = append(out, key+"=true")
			} else {
				out = append(out, key+"=false")
			}
		case float64:
			out = append(out, key+"="+strconv.FormatFloat(typed, 'f', -1, 64))
		case int:
			out = append(out, key+"="+strconv.Itoa(typed))
		}
	}
	return out
}

func safeEvidenceValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	lower := strings.ToLower(value)
	for _, prefix := range []string{"ghp_", "gho_", "github_pat_", "xoxb-", "xoxp-", "xoxa-", "xoxr-", "ast_svc_", "ast_ingest_v1."} {
		if strings.HasPrefix(lower, prefix) {
			return "<redacted>"
		}
	}
	for _, pattern := range standaloneSecretPatterns {
		if pattern.MatchString(value) {
			return "<redacted>"
		}
	}
	sensitivePatterns := []string{
		"://",
		"token=",
		"access_token",
		"refresh_token",
		"authorization",
		"bearer ",
		"password",
		"passwd",
		"secret",
		"webhook",
		"discord.com/api/webhooks",
		"hooks.slack.com/services",
		"private_key",
		"credential",
	}
	for _, pattern := range sensitivePatterns {
		if strings.Contains(lower, pattern) {
			return "<redacted>"
		}
	}
	if len(value) > 120 {
		return value[:120] + "..."
	}
	return value
}

func validateSignalTopLevelFields(signal store.Signal) error {
	fields := map[string]string{
		"type":         signal.Type,
		"name":         signal.Name,
		"service_id":   signal.ServiceID,
		"service_type": signal.ServiceType,
		"stream_id":    signal.StreamID,
		"status":       signal.Status,
	}
	for field, value := range fields {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if len(value) > 255 || safeEvidenceValue(value) == "<redacted>" {
			return fmt.Errorf("unsafe signal %s", field)
		}
	}
	return nil
}

func validateSignalAttributes(attributes map[string]any) error {
	for key, value := range attributes {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if secretAttributeKey(key) {
			return fmt.Errorf("unsafe signal attribute %s", key)
		}
		if err := validateSignalAttributeValue(value); err != nil {
			return fmt.Errorf("unsafe signal attribute %s", key)
		}
	}
	return nil
}

func validateSignalAttributeValue(value any) error {
	switch typed := value.(type) {
	case string:
		if safeEvidenceValue(typed) == "<redacted>" {
			return errors.New("unsafe signal attribute value")
		}
	case []any:
		for _, item := range typed {
			if err := validateSignalAttributeValue(item); err != nil {
				return err
			}
		}
	case map[string]any:
		return validateSignalAttributes(typed)
	}
	return nil
}

func safeSignal(signal store.Signal) store.Signal {
	signal.Attributes = safeSignalAttributes(signal.Attributes)
	return signal
}

func safeSignals(signals []store.Signal) []store.Signal {
	out := make([]store.Signal, 0, len(signals))
	for _, signal := range signals {
		out = append(out, safeSignal(signal))
	}
	return out
}

func safeSignalAttributes(attributes map[string]any) map[string]any {
	if attributes == nil {
		return map[string]any{}
	}
	out := map[string]any{}
	for key, value := range attributes {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if secretAttributeKey(key) {
			out[key] = "<redacted>"
			continue
		}
		out[key] = safeSignalAttributeValue(value)
	}
	return out
}

func safeSignalAttributeValue(value any) any {
	switch typed := value.(type) {
	case string:
		return safeEvidenceValue(typed)
	case bool:
		return typed
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return typed
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, safeSignalAttributeValue(item))
		}
		return out
	case map[string]any:
		return safeSignalAttributes(typed)
	default:
		return nil
	}
}

func secretAttributeKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	for _, token := range []string{"webhook_url", "token", "secret", "password", "passwd", "private_key", "credential", "authorization", "stream_key", "refresh_token", "access_token", "client_secret", "api_key", "apikey"} {
		if strings.Contains(normalized, token) {
			return true
		}
	}
	return false
}

func (s *Server) createRemediationActions(r *http.Request, incident store.Incident) error {
	for _, action := range remediation.BuildActions(incident, remediation.ModeFromEnv()) {
		created, err := s.store.CreateRemediationAction(r.Context(), action)
		if err != nil {
			return err
		}
		if created.Status == "pending_approval" {
			s.notifyIncidentEvent(r, "remediation.pending_approval", incident)
		}
	}
	return nil
}

func (s *Server) notifyIncidentEvent(r *http.Request, eventType string, incident store.Incident) {
	if s.notifier == nil {
		return
	}
	results, err := notifications.NotifyIncidentEvent(r.Context(), s.notifier, eventType, incident)
	if err != nil && len(results) == 0 {
		results = []notifications.DeliveryResult{{EventType: eventType, Channel: "generic", Target: "<WEBHOOK_URL>", Status: "failure", Error: notifications.SanitizeDeliveryError(err)}}
	}
	for _, result := range results {
		status := result.Status
		if status == "" {
			status = "success"
		}
		errorText := notifications.SanitizeDeliveryError(errors.New(result.Error))
		if result.Error == "" {
			errorText = ""
		}
		if errorText != "" {
			status = "failure"
		}
		if result.EventType == "" {
			result.EventType = eventType
		}
		_, _ = s.store.SaveNotificationDelivery(r.Context(), store.NotificationDelivery{
			EventType:  result.EventType,
			Channel:    result.Channel,
			Target:     result.Target,
			IncidentID: incident.ID,
			Status:     status,
			Error:      errorText,
			Metadata: map[string]any{
				"severity": incident.Severity,
				"rule":     incident.Rule,
			},
		})
	}
}

func metricSnapshots(signals []store.Signal) []store.MetricSnapshot {
	seen := map[string]bool{}
	out := make([]store.MetricSnapshot, 0, len(signals))
	for _, signal := range signals {
		key := signal.ServiceID + "\x00" + signal.StreamID + "\x00" + signal.Name
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, store.MetricSnapshot{
			Name:        signal.Name,
			ServiceID:   signal.ServiceID,
			ServiceType: signal.ServiceType,
			StreamID:    signal.StreamID,
			Status:      signal.Status,
			Value:       signal.Value,
			Attributes:  safeSignalAttributes(signal.Attributes),
			UpdatedAt:   signal.CreatedAt,
		})
	}
	return out
}

func parseLimit(r *http.Request, fallback int) int {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return fallback
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit <= 0 {
		return fallback
	}
	if limit > 1000 {
		return 1000
	}
	return limit
}

func (s *Server) authorizeAdmin(w http.ResponseWriter, r *http.Request, scope string) bool {
	authenticated, authorized := s.adminAuth.AuthorizeRequest(r, scope)
	if !authenticated {
		authenticated, authorized = nodeRuntimeVerifier().AuthorizeRequest(r, scope)
	}
	if !authenticated {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"code": "invalid_service_token"})
		return false
	}
	if !authorized {
		writeJSON(w, http.StatusForbidden, map[string]string{"code": "missing_admin_scope"})
		return false
	}
	return true
}

func (s *Server) ingestAuthorized(r *http.Request) bool {
	return s.ingestAuth.VerifyRequest(r) || nodeRuntimeVerifier().VerifyRequest(r)
}

func nodeRuntimeVerifier() auth.Verifier {
	return auth.WithRawTokenScopes(auth.Verifier{}, control.NodeRuntimeTokenFromEnv(), "*")
}

type rateLimiter struct {
	mu         sync.Mutex
	burst      int
	window     time.Duration
	maxBuckets int
	hits       map[string][]time.Time
	now        func() time.Time
	shared     rateLimitStore
	requireDB  bool
}

type rateLimitStore interface {
	AllowRateLimit(ctx context.Context, bucketKey string, window time.Duration, burst int, now time.Time) (bool, error)
}

func rateLimiterFromEnv(st store.Store) *rateLimiter {
	burst := envInt("OBSERVABILITY_RATE_LIMIT_BURST", 120)
	windowSec := envInt("OBSERVABILITY_RATE_LIMIT_WINDOW_SEC", 60)
	maxBuckets := envInt("OBSERVABILITY_RATE_LIMIT_MAX_BUCKETS", 10000)
	if burst <= 0 || windowSec <= 0 {
		return nil
	}
	if maxBuckets <= 0 {
		maxBuckets = 10000
	}
	limiter := &rateLimiter{
		burst:      burst,
		window:     time.Duration(windowSec) * time.Second,
		maxBuckets: maxBuckets,
		hits:       map[string][]time.Time{},
		now:        time.Now,
	}
	backend := strings.ToLower(strings.TrimSpace(os.Getenv("OBSERVABILITY_RATE_LIMIT_BACKEND")))
	if backend == "store" || backend == "mariadb" || backend == "shared" {
		shared, ok := st.(rateLimitStore)
		if !ok {
			limiter.requireDB = true
			return limiter
		}
		limiter.shared = shared
		return limiter
	}
	if backend == "" {
		if shared, ok := st.(store.MariaDBStore); ok {
			limiter.shared = shared
		}
	}
	return limiter
}

func (s *Server) rateLimitSensitive(next http.Handler) http.Handler {
	if s.rateLimiter == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isRateLimitedEndpoint(r) {
			allowed, err := s.rateLimiter.allow(r.Context(), rateLimitKey(r))
			if err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"code": "rate_limit_unavailable"})
				return
			}
			if !allowed {
				writeJSON(w, http.StatusTooManyRequests, map[string]string{"code": "rate_limited"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isRateLimitedEndpoint(r *http.Request) bool {
	path := r.URL.Path
	switch r.Method {
	case http.MethodGet:
		if path == "/signals" || path == "/metrics" || path == "/diagnostics" || path == "/incidents" || path == "/notification-deliveries" || path == "/notification-channels" || path == "/remediation-actions" {
			return true
		}
		if strings.HasPrefix(path, "/incidents/") || strings.HasPrefix(path, "/notification-channels/") || strings.HasPrefix(path, "/remediation-actions/") {
			return true
		}
	case http.MethodPost:
		if path == "/heartbeat" || path == "/signals" || path == "/notification-channels" {
			return true
		}
		if strings.HasPrefix(path, "/incidents/") && (strings.HasSuffix(path, "/acknowledge") || strings.HasSuffix(path, "/resolve")) {
			return true
		}
		if strings.HasPrefix(path, "/notification-channels/") && strings.HasSuffix(path, "/test") {
			return true
		}
		if strings.HasPrefix(path, "/remediation-actions/") && (strings.HasSuffix(path, "/approve") || strings.HasSuffix(path, "/execute")) {
			return true
		}
	case http.MethodPut, http.MethodDelete:
		if strings.HasPrefix(path, "/notification-channels/") {
			return true
		}
	}
	return false
}

func rateLimitKey(r *http.Request) string {
	return r.Method + "\x00" + rateLimitPath(r) + "\x00" + clientIP(r)
}

func rateLimitPath(r *http.Request) string {
	path := r.URL.Path
	if r.Method == http.MethodGet && strings.HasPrefix(path, "/incidents/") {
		return "/incidents/{id}"
	}
	if r.Method == http.MethodGet && strings.HasPrefix(path, "/notification-channels/") {
		return "/notification-channels/{id}"
	}
	if r.Method == http.MethodGet && strings.HasPrefix(path, "/remediation-actions/") && strings.HasSuffix(path, "/dispatch-context") {
		return "/remediation-actions/{id}/dispatch-context"
	}
	if strings.HasPrefix(path, "/incidents/") && strings.HasSuffix(path, "/acknowledge") {
		return "/incidents/{id}/acknowledge"
	}
	if strings.HasPrefix(path, "/incidents/") && strings.HasSuffix(path, "/resolve") {
		return "/incidents/{id}/resolve"
	}
	if strings.HasPrefix(path, "/notification-channels/") && strings.HasSuffix(path, "/test") {
		return "/notification-channels/{id}/test"
	}
	if (r.Method == http.MethodPut || r.Method == http.MethodDelete) && strings.HasPrefix(path, "/notification-channels/") {
		return "/notification-channels/{id}"
	}
	if strings.HasPrefix(path, "/remediation-actions/") && strings.HasSuffix(path, "/approve") {
		return "/remediation-actions/{id}/approve"
	}
	if strings.HasPrefix(path, "/remediation-actions/") && strings.HasSuffix(path, "/execute") {
		return "/remediation-actions/{id}/execute"
	}
	return path
}

func clientIP(r *http.Request) string {
	remote := remoteHost(r.RemoteAddr)
	forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if forwarded != "" && trustedProxy(remote) {
		current, err := netip.ParseAddr(remote)
		if err != nil {
			return remote
		}
		current = current.Unmap()
		hops := strings.Split(forwarded, ",")
		for i := len(hops) - 1; i >= 0; i-- {
			hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
			if err != nil {
				return remote
			}
			if !trustedProxy(current.String()) {
				return current.String()
			}
			current = hop.Unmap()
		}
		return current.String()
	}
	if remote != "" {
		return remote
	}
	if raw := strings.TrimSpace(r.RemoteAddr); raw != "" {
		return raw
	}
	return "unknown"
}

func remoteHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil && host != "" {
		return host
	}
	if idx := strings.LastIndex(remoteAddr, ":"); idx > 0 && !strings.Contains(remoteAddr[idx+1:], ":") {
		return remoteAddr[:idx]
	}
	return strings.Trim(remoteAddr, "[]")
}

func trustedProxy(host string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	raw := strings.TrimSpace(os.Getenv("OBSERVABILITY_TRUSTED_PROXIES"))
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("AUTOSTREAM_TRUSTED_PROXIES"))
	}
	if raw == "" {
		return false
	}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(item); err == nil {
			if prefix.Contains(addr) {
				return true
			}
			continue
		}
		if trustedAddr, err := netip.ParseAddr(item); err == nil && trustedAddr.Unmap() == addr {
			return true
		}
	}
	return false
}

func (l *rateLimiter) allow(ctx context.Context, key string) (bool, error) {
	now := l.now().UTC()
	if l.requireDB {
		return false, errors.New("shared rate limit store unavailable")
	}
	if l.shared != nil {
		return l.shared.AllowRateLimit(ctx, key, l.window, l.burst, now)
	}
	return l.allowMemory(key, now), nil
}

func (l *rateLimiter) allowMemory(key string, now time.Time) bool {
	cutoff := now.Add(-l.window)
	l.mu.Lock()
	defer l.mu.Unlock()

	for candidate, candidateHits := range l.hits {
		kept := candidateHits[:0]
		for _, hit := range candidateHits {
			if hit.After(cutoff) {
				kept = append(kept, hit)
			}
		}
		if len(kept) == 0 {
			delete(l.hits, candidate)
			continue
		}
		l.hits[candidate] = kept
	}

	hits := l.hits[key]
	kept := hits[:0]
	for _, hit := range hits {
		if hit.After(cutoff) {
			kept = append(kept, hit)
		}
	}
	if len(kept) >= l.burst {
		l.hits[key] = kept
		return false
	}
	if len(kept) == 0 && l.maxBuckets > 0 && len(l.hits) >= l.maxBuckets {
		return false
	}
	kept = append(kept, now)
	l.hits[key] = kept
	return true
}

func envInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain a single JSON object")
	}
	return nil
}
