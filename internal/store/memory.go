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
)

type MemoryStore struct {
	mu           sync.Mutex
	signals      []Signal
	incidents    map[string]Incident
	deliveries   []NotificationDelivery
	channels     map[string]NotificationChannel
	remediations map[string]RemediationAction
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{incidents: map[string]Incident{}, channels: map[string]NotificationChannel{}, remediations: map[string]RemediationAction{}}
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

func (s *MemoryStore) UpsertIncident(ctx context.Context, incident Incident) (Incident, bool, error) {
	if err := ctx.Err(); err != nil {
		return Incident{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	key := incidentKey(incident)
	if existing, ok := s.incidents[key]; ok && existing.Status != "resolved" && existing.Status != "ignored" {
		existing.SignalID = incident.SignalID
		existing.SummaryJA = incident.SummaryJA
		existing.Report = incident.Report
		existing.UpdatedAt = now
		s.incidents[key] = existing
		return existing, false, nil
	}
	if incident.ID == "" {
		incident.ID = newID("inc")
	}
	if incident.Status == "" {
		incident.Status = "open"
	}
	incident.OpenedAt = now
	incident.UpdatedAt = now
	s.incidents[key] = incident
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
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out, nil
}

func (s *MemoryStore) GetIncident(ctx context.Context, id string) (Incident, error) {
	if err := ctx.Err(); err != nil {
		return Incident{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, incident := range s.incidents {
		if incident.ID == id {
			return incident, nil
		}
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
	for key, incident := range s.incidents {
		if incident.ID != id {
			continue
		}
		now := time.Now().UTC()
		incident.Status = status
		incident.UpdatedAt = now
		if status == "resolved" || status == "ignored" {
			incident.ResolvedAt = &now
		} else {
			incident.ResolvedAt = nil
		}
		s.incidents[key] = incident
		return incident, nil
	}
	return Incident{}, ErrNotFound
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

func newID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return prefix + "_id_unavailable"
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}
