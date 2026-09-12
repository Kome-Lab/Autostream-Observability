package notifications

import (
	"context"
	"strings"

	"github.com/example/autostream-observability/internal/store"
)

type Notifier interface {
	NotifyIncidentOpened(ctx context.Context, incident store.Incident) ([]DeliveryResult, error)
}

type IncidentEventNotifier interface {
	NotifyIncidentEvent(ctx context.Context, eventType string, incident store.Incident) ([]DeliveryResult, error)
}

// ChannelSelectiveIncidentEventNotifier allows a caller to retry only the
// configured channels that have not already accepted the same event.
type ChannelSelectiveIncidentEventNotifier interface {
	NotifyIncidentEventExceptChannels(ctx context.Context, eventType string, incident store.Incident, excludedChannelIDs map[string]struct{}) ([]DeliveryResult, error)
}

func NotifyIncidentEvent(ctx context.Context, notifier Notifier, eventType string, incident store.Incident) ([]DeliveryResult, error) {
	if eventNotifier, ok := notifier.(IncidentEventNotifier); ok {
		return eventNotifier.NotifyIncidentEvent(ctx, eventType, incident)
	}
	if eventType == "incident.opened" {
		return notifier.NotifyIncidentOpened(ctx, incident)
	}
	return nil, nil
}

type DeliveryResult struct {
	EventType string `json:"event_type"`
	Channel   string `json:"channel"`
	Target    string `json:"target"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
	ChannelID string `json:"-"`
}

func normalizedEventType(value string) string {
	switch strings.TrimSpace(value) {
	case "incident.opened", "incident.updated", "incident.resolved", "diagnostic.created", "remediation.pending_approval", "remediation.executed", "admin.audit":
		return strings.TrimSpace(value)
	default:
		return "incident.updated"
	}
}

func normalizedType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "discord", "discord_webhook":
		return "discord"
	case "slack", "slack_webhook":
		return "slack"
	case "email":
		return "email"
	default:
		return "generic"
	}
}
