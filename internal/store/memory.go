package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/example/autostream-observability/internal/diagnostics"
)

type MemoryStore struct {
	mu              sync.Mutex
	signals         []Signal
	incidents       map[string]Incident
	activeIncidents map[string]string
	deliveries      []NotificationDelivery
	channels        map[string]NotificationChannel
	remediations    map[string]RemediationAction
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{incidents: map[string]Incident{}, activeIncidents: map[string]string{}, channels: map[string]NotificationChannel{}, remediations: map[string]RemediationAction{}}
}

func (s *MemoryStore) SaveSignal(ctx context.Context, signal Signal) (Signal, error) {
	if err := ctx.Err(); err != nil {
		return Signal{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if signal.ID == "" {
		signal.ID = newID("sig")
	}
	if signal.Timestamp.IsZero() {
		signal.Timestamp = now
	}
	signal.CreatedAt = now
	if signal.Attributes == nil {
		signal.Attributes = map[string]any{}
	}
	s.signals = append(s.signals, signal)
	return signal, nil
}

func (s *MemoryStore) LatestMetricValue(ctx context.Context, name, serviceID, streamID string) (float64, bool, error) {
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for index := len(s.signals) - 1; index >= 0; index-- {
		signal := s.signals[index]
		if signal.Name == name && signal.ServiceID == serviceID && signal.StreamID == streamID && signal.Value != nil {
			return *signal.Value, true, nil
		}
	}
	return 0, false, nil
}

func (s *MemoryStore) ListSignals(ctx context.Context, limit int) ([]Signal, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]Signal(nil), s.signals...)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemoryStore) GetSignal(ctx context.Context, id string) (Signal, error) {
	if err := ctx.Err(); err != nil {
		return Signal{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return Signal{}, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, signal := range s.signals {
		if signal.ID == id {
			return signal, nil
		}
	}
	return Signal{}, ErrNotFound
}

func (s *MemoryStore) UpsertIncident(ctx context.Context, incident Incident) (Incident, bool, error) {
	if err := ctx.Err(); err != nil {
		return Incident{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	key := incidentKey(incident)
	if activeID, ok := s.activeIncidents[key]; ok {
		existing, exists := s.incidents[activeID]
		if !exists || isTerminalIncidentStatus(existing.Status) {
			delete(s.activeIncidents, key)
		} else {
			existing.SeverityChanged = isMoreSevereIncidentSeverity(incident.Severity, existing.Severity)
			if existing.SeverityChanged {
				existing.Severity = incident.Severity
			}
			existing.SignalID = incident.SignalID
			existing.SummaryJA = incident.SummaryJA
			existing.Report = incident.Report
			existing.UpdatedAt = now
			existing.LastSeenAt = now
			existing.OccurrenceCount++
			persisted := existing
			persisted.SeverityChanged = false
			persisted.StatusChanged = false
			s.incidents[existing.ID] = persisted
			return existing, false, nil
		}
	}
	if incident.ID == "" {
		incident.ID = newID("inc")
	}
	if incident.Status == "" {
		incident.Status = "open"
	}
	incident.OpenedAt = now
	incident.UpdatedAt = now
	incident.LastSeenAt = now
	incident.OccurrenceCount = 1
	s.incidents[incident.ID] = incident
	s.activeIncidents[key] = incident.ID
	return incident, true, nil
}

func (s *MemoryStore) ListIncidents(ctx context.Context) ([]Incident, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Incident, 0, len(s.incidents))
	for _, incident := range s.incidents {
		out = append(out, incident)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UpdatedAt.Equal(out[j].UpdatedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].UpdatedAt.After(out[j].UpdatedAt)
	})
	return out, nil
}

func (s *MemoryStore) ListIncidentHistory(ctx context.Context, limit int, before time.Time, beforeID, status string) ([]Incident, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Incident, 0, len(s.incidents))
	for _, incident := range s.incidents {
		if status != "" && incident.Status != status {
			continue
		}
		if !before.IsZero() && (incident.UpdatedAt.After(before) || (incident.UpdatedAt.Equal(before) && incident.ID >= beforeID)) {
			continue
		}
		out = append(out, incident)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UpdatedAt.Equal(out[j].UpdatedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].UpdatedAt.After(out[j].UpdatedAt)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemoryStore) GetIncident(ctx context.Context, id string) (Incident, error) {
	if err := ctx.Err(); err != nil {
		return Incident{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if incident, ok := s.incidents[id]; ok {
		return incident, nil
	}
	return Incident{}, ErrNotFound
}

func (s *MemoryStore) UpdateIncidentStatus(ctx context.Context, id, status string) (Incident, error) {
	if err := ctx.Err(); err != nil {
		return Incident{}, err
	}
	if !validIncidentStatus(status) {
		return Incident{}, ErrInvalidStatus
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	incident, ok := s.incidents[id]
	if ok {
		if incident.Status == status {
			incident.StatusChanged = false
			return incident, nil
		}
		if !canTransitionIncidentStatus(incident.Status, status) {
			return Incident{}, ErrInvalidTransition
		}
		now := time.Now().UTC()
		incident.Status = status
		incident.StatusChanged = true
		incident.UpdatedAt = now
		if isTerminalIncidentStatus(status) {
			incident.ResolvedAt = &now
			incident.ResolutionReason = "manual"
			delete(s.activeIncidents, incidentKey(incident))
		} else {
			incident.ResolvedAt = nil
			incident.ResolvedBySignalID = ""
			incident.ResolutionReason = ""
		}
		persisted := incident
		persisted.SeverityChanged = false
		persisted.StatusChanged = false
		s.incidents[id] = persisted
		return incident, nil
	}
	return Incident{}, ErrNotFound
}

func (s *MemoryStore) ResolveActiveIncidents(ctx context.Context, rules []string, serviceID, streamID, signalID, reason string) ([]Incident, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	resolved := make([]Incident, 0, len(rules))
	for _, rule := range uniqueNonEmptyStrings(rules) {
		key := incidentKey(Incident{Rule: rule, ServiceID: serviceID, StreamID: streamID})
		id, ok := s.activeIncidents[key]
		if !ok {
			continue
		}
		incident, ok := s.incidents[id]
		if !ok || isTerminalIncidentStatus(incident.Status) {
			delete(s.activeIncidents, key)
			continue
		}
		incident.Status = "resolved"
		incident.StatusChanged = true
		incident.UpdatedAt = now
		incident.ResolvedAt = &now
		incident.ResolvedBySignalID = strings.TrimSpace(signalID)
		incident.ResolutionReason = strings.TrimSpace(reason)
		persisted := incident
		persisted.SeverityChanged = false
		persisted.StatusChanged = false
		s.incidents[id] = persisted
		delete(s.activeIncidents, key)
		resolved = append(resolved, incident)
	}
	return resolved, nil
}

func isMoreSevereIncidentSeverity(candidate, current string) bool {
	return incidentSeverityRank(candidate) > incidentSeverityRank(current)
}

func incidentSeverityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "info":
		return 1
	case "warning":
		return 2
	case "error":
		return 3
	case "critical":
		return 4
	default:
		return 0
	}
}

func (s *MemoryStore) UpdateIncidentDiagnostic(ctx context.Context, id, expectedSignalID string, report diagnostics.Report) (Incident, bool, error) {
	if err := ctx.Err(); err != nil {
		return Incident{}, false, err
	}
	id = strings.TrimSpace(id)
	expectedSignalID = strings.TrimSpace(expectedSignalID)
	if id == "" || expectedSignalID == "" {
		return Incident{}, false, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	incident, ok := s.incidents[id]
	if ok {
		if incident.SignalID != expectedSignalID {
			return incident, false, nil
		}
		incident.Report = report
		incident.UpdatedAt = time.Now().UTC()
		s.incidents[id] = incident
		return incident, true, nil
	}
	return Incident{}, false, ErrNotFound
}

func (s *MemoryStore) SaveNotificationDelivery(ctx context.Context, delivery NotificationDelivery) (NotificationDelivery, error) {
	if err := ctx.Err(); err != nil {
		return NotificationDelivery{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if delivery.ID == "" {
		delivery.ID = newID("ntf")
	}
	if delivery.CreatedAt.IsZero() {
		delivery.CreatedAt = time.Now().UTC()
	}
	if delivery.Metadata == nil {
		delivery.Metadata = map[string]any{}
	}
	delivery = sanitizeNotificationDelivery(delivery)
	s.deliveries = append(s.deliveries, delivery)
	return delivery, nil
}

func (s *MemoryStore) ListNotificationDeliveries(ctx context.Context) ([]NotificationDelivery, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]NotificationDelivery(nil), s.deliveries...)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) ListNotificationChannels(ctx context.Context) ([]NotificationChannel, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]NotificationChannel, 0, len(s.channels))
	for _, channel := range s.channels {
		out = append(out, publicChannel(channel))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *MemoryStore) CreateNotificationChannel(ctx context.Context, channel NotificationChannel) (NotificationChannel, error) {
	if err := ctx.Err(); err != nil {
		return NotificationChannel{}, err
	}
	now := time.Now().UTC()
	if channel.ID == "" {
		channel.ID = newID("ntc")
	}
	channel.Type = normalizeChannelType(channel.Type)
	channel = normalizeNotificationChannelSecrets(channel)
	channel.CreatedAt = now
	channel.UpdatedAt = now
	s.mu.Lock()
	s.channels[channel.ID] = channel
	s.mu.Unlock()
	return publicChannel(channel), nil
}

func (s *MemoryStore) GetNotificationChannel(ctx context.Context, id string) (NotificationChannel, error) {
	if err := ctx.Err(); err != nil {
		return NotificationChannel{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	channel, ok := s.channels[id]
	if !ok {
		return NotificationChannel{}, ErrNotFound
	}
	return publicChannel(channel), nil
}

func (s *MemoryStore) UpdateNotificationChannel(ctx context.Context, channel NotificationChannel) (NotificationChannel, error) {
	if err := ctx.Err(); err != nil {
		return NotificationChannel{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.channels[channel.ID]
	if !ok {
		return NotificationChannel{}, ErrNotFound
	}
	if channel.Name != "" {
		existing.Name = channel.Name
	}
	if channel.Type != "" {
		existing.Type = normalizeChannelType(channel.Type)
	}
	existing.Enabled = channel.Enabled
	if channel.UseGlobalSMTPSet {
		existing.UseGlobalSMTP = channel.UseGlobalSMTP
		existing.UseGlobalSMTPSet = true
		if channel.UseGlobalSMTP {
			clearLegacySMTPConfiguration(&existing)
		}
	}
	if channel.WebhookURL != "" {
		existing.WebhookURL = channel.WebhookURL
	}
	if channel.EmailRecipients != nil {
		existing.EmailRecipients = append([]string(nil), channel.EmailRecipients...)
	}
	if channel.SMTPHost != "" {
		existing.SMTPHost = channel.SMTPHost
	}
	if channel.SMTPPort != 0 {
		existing.SMTPPort = channel.SMTPPort
	}
	existing.SMTPTLS = channel.SMTPTLS
	if channel.SMTPFrom != "" {
		existing.SMTPFrom = channel.SMTPFrom
	}
	if channel.SMTPUsername != "" {
		existing.SMTPUsername = channel.SMTPUsername
	}
	if channel.SMTPPassword != "" {
		existing.SMTPPassword = channel.SMTPPassword
	}
	if channel.SeverityFilter != nil {
		existing.SeverityFilter = append([]string(nil), channel.SeverityFilter...)
	}
	if channel.EventTypeFilter != nil {
		existing.EventTypeFilter = append([]string(nil), channel.EventTypeFilter...)
	}
	existing = normalizeNotificationChannelSecrets(existing)
	existing.UpdatedAt = time.Now().UTC()
	s.channels[channel.ID] = existing
	return publicChannel(existing), nil
}

func (s *MemoryStore) DeleteNotificationChannel(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.channels[id]; !ok {
		return ErrNotFound
	}
	delete(s.channels, id)
	return nil
}

func (s *MemoryStore) CreateRemediationAction(ctx context.Context, action RemediationAction) (RemediationAction, error) {
	if err := ctx.Err(); err != nil {
		return RemediationAction{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if action.ID == "" {
		action.ID = newID("rem")
	}
	if action.Status == "" {
		action.Status = "suggested"
	}
	action.CreatedAt = now
	action.UpdatedAt = now
	s.remediations[action.ID] = action
	return action, nil
}

func publicChannel(channel NotificationChannel) NotificationChannel {
	channel = normalizeNotificationChannelSecrets(channel)
	return channel
}

func normalizeChannelType(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "discord", "slack":
		return normalized
	case "email":
		return "email"
	default:
		return "generic"
	}
}

func normalizeNotificationChannelSecrets(channel NotificationChannel) NotificationChannel {
	if channel.Type == "email" {
		if channel.UseGlobalSMTPSet && channel.UseGlobalSMTP {
			clearLegacySMTPConfiguration(&channel)
		}
		if !hasLegacySMTPConfiguration(channel) {
			channel.UseGlobalSMTP = true
		} else if !channel.UseGlobalSMTPSet {
			channel.UseGlobalSMTP = false
		}
		channel.MaskedWebhookURL = ""
		channel.SMTPPasswordConfigured = strings.TrimSpace(channel.SMTPPassword) != "" || channel.SMTPPasswordConfigured
		channel.MaskedEmailTarget = maskEmailRecipients(channel.EmailRecipients)
		if !channel.UseGlobalSMTP && channel.SMTPPort == 0 {
			channel.SMTPPort = 587
		}
		return channel
	}
	channel.MaskedWebhookURL = maskWebhookURL(channel.WebhookURL)
	return channel
}

func hasLegacySMTPConfiguration(channel NotificationChannel) bool {
	return strings.TrimSpace(channel.SMTPHost) != "" ||
		channel.SMTPPort != 0 ||
		strings.TrimSpace(channel.SMTPFrom) != "" ||
		strings.TrimSpace(channel.SMTPUsername) != "" ||
		strings.TrimSpace(channel.SMTPPassword) != "" ||
		channel.SMTPPasswordConfigured
}

func clearLegacySMTPConfiguration(channel *NotificationChannel) {
	channel.SMTPHost = ""
	channel.SMTPPort = 0
	channel.SMTPTLS = false
	channel.SMTPFrom = ""
	channel.SMTPUsername = ""
	channel.SMTPPassword = ""
	channel.SMTPPasswordConfigured = false
}

func maskEmailRecipients(recipients []string) string {
	cleaned := make([]string, 0, len(recipients))
	for _, recipient := range recipients {
		recipient = strings.TrimSpace(recipient)
		if recipient == "" {
			continue
		}
		parts := strings.Split(recipient, "@")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			cleaned = append(cleaned, "<EMAIL>")
			continue
		}
		local := parts[0]
		if len(local) > 2 {
			local = local[:1] + "***" + local[len(local)-1:]
		} else {
			local = "***"
		}
		cleaned = append(cleaned, local+"@<EMAIL_DOMAIN>")
	}
	if len(cleaned) == 0 {
		return ""
	}
	return strings.Join(cleaned, ",")
}

func maskWebhookURL(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "<WEBHOOK_URL>"
	}
	return parsed.Scheme + "://" + maskedWebhookHost(parsed.Host) + "/<WEBHOOK_PATH>"
}

func maskedWebhookHost(host string) string {
	normalized := strings.ToLower(strings.TrimSpace(host))
	switch {
	case normalized == "discord.com" || strings.HasSuffix(normalized, ".discord.com"):
		return "discord.com"
	case normalized == "hooks.slack.com":
		return "hooks.slack.com"
	default:
		return "<WEBHOOK_HOST>"
	}
}

func (s *MemoryStore) ListRemediationActions(ctx context.Context) ([]RemediationAction, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]RemediationAction, 0, len(s.remediations))
	for _, action := range s.remediations {
		out = append(out, action)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out, nil
}

func (s *MemoryStore) GetRemediationAction(ctx context.Context, id string) (RemediationAction, error) {
	if err := ctx.Err(); err != nil {
		return RemediationAction{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	action, ok := s.remediations[id]
	if !ok {
		return RemediationAction{}, ErrNotFound
	}
	return action, nil
}

func (s *MemoryStore) UpdateRemediationAction(ctx context.Context, action RemediationAction) (RemediationAction, error) {
	if err := ctx.Err(); err != nil {
		return RemediationAction{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.remediations[action.ID]; !ok {
		return RemediationAction{}, ErrNotFound
	}
	action.UpdatedAt = time.Now().UTC()
	s.remediations[action.ID] = action
	return action, nil
}

func incidentKey(incident Incident) string {
	return incident.Rule + "\x00" + incident.ServiceID + "\x00" + incident.StreamID
}

func validIncidentStatus(status string) bool {
	switch status {
	case "open", "acknowledged", "investigating", "mitigated", "resolved", "ignored":
		return true
	default:
		return false
	}
}

func isTerminalIncidentStatus(status string) bool {
	return status == "resolved" || status == "ignored"
}

func canTransitionIncidentStatus(current, next string) bool {
	if current == next {
		return true
	}
	if isTerminalIncidentStatus(current) {
		return false
	}
	switch current {
	case "open":
		return validIncidentStatus(next)
	case "acknowledged":
		return next == "investigating" || next == "mitigated" || isTerminalIncidentStatus(next)
	case "investigating":
		return next == "mitigated" || isTerminalIncidentStatus(next)
	case "mitigated":
		return isTerminalIncidentStatus(next)
	default:
		return false
	}
}

func uniqueNonEmptyStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
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
	}
	return out
}

func newID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return prefix + "_id_unavailable"
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}
