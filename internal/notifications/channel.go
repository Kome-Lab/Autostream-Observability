package notifications

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/example/autostream-observability/internal/store"
)

type ChannelStore interface {
	ListNotificationChannels(ctx context.Context) ([]store.NotificationChannel, error)
}

type ChannelNotifier struct {
	Store          ChannelStore
	Fallback       Notifier
	EmailRelay     EmailRelay
	Timeout        time.Duration
	EmailTimeout   time.Duration
	RetryMax       int
	RetryBaseDelay time.Duration
	HTTP           *http.Client
	AllowPrivate   bool
}

func (n ChannelNotifier) NotifyIncidentOpened(ctx context.Context, incident store.Incident) ([]DeliveryResult, error) {
	return n.NotifyIncidentEvent(ctx, "incident.opened", incident)
}

func (n ChannelNotifier) NotifyIncidentEvent(ctx context.Context, eventType string, incident store.Incident) ([]DeliveryResult, error) {
	return n.notifyIncidentEvent(ctx, eventType, incident, nil)
}

func (n ChannelNotifier) NotifyIncidentEventExceptChannels(ctx context.Context, eventType string, incident store.Incident, excludedChannelIDs map[string]struct{}) ([]DeliveryResult, error) {
	return n.notifyIncidentEvent(ctx, eventType, incident, excludedChannelIDs)
}

func (n ChannelNotifier) notifyIncidentEvent(ctx context.Context, eventType string, incident store.Incident, excludedChannelIDs map[string]struct{}) ([]DeliveryResult, error) {
	eventType = normalizedEventType(eventType)
	if n.Store == nil {
		if n.Fallback == nil {
			return nil, nil
		}
		return NotifyIncidentEvent(ctx, n.Fallback, eventType, incident)
	}
	channels, err := n.Store.ListNotificationChannels(ctx)
	if err != nil {
		return nil, err
	}
	results := make([]DeliveryResult, 0, len(channels))
	matchedChannel := false
	for _, channel := range channels {
		if !channel.Enabled {
			continue
		}
		if eventType != "admin.audit" && !matchesFilters(channel, incident, eventType) {
			continue
		}
		matchedChannel = true
		if channel.ID != "" && channel.Type != "email" {
			if _, excluded := excludedChannelIDs[channel.ID]; excluded {
				continue
			}
		}
		timeout := n.Timeout
		if channel.Type == "email" && n.EmailTimeout > 0 {
			timeout = n.EmailTimeout
		}
		channelDestinations := []store.NotificationChannel{channel}
		if channel.Type == "email" {
			channelDestinations = make([]store.NotificationChannel, 0, len(channel.EmailRecipients))
			for _, recipient := range channel.EmailRecipients {
				destinationID := emailDestinationID(channel.ID, recipient)
				if _, excluded := excludedChannelIDs[destinationID]; excluded {
					continue
				}
				destination := channel
				destination.EmailRecipients = []string{recipient}
				channelDestinations = append(channelDestinations, destination)
			}
		}
		for _, destination := range channelDestinations {
			notifier := NotifierForChannelWithRelay(destination, timeout, n.RetryMax, n.RetryBaseDelay, n.HTTP, n.AllowPrivate, n.EmailRelay)
			deliveries, _ := notifier.NotifyIncidentEvent(ctx, eventType, incident)
			for _, delivery := range deliveries {
				delivery.ChannelID = channel.ID
				delivery.Channel = channel.Type
				if channel.Type == "email" {
					delivery.ChannelID = emailDestinationID(channel.ID, destination.EmailRecipients[0])
					delivery.Target = channel.MaskedEmailTarget
				} else {
					delivery.Target = channel.MaskedWebhookURL
				}
				results = append(results, delivery)
			}
		}
	}
	if len(results) == 0 && !matchedChannel && n.Fallback != nil {
		return NotifyIncidentEvent(ctx, n.Fallback, eventType, incident)
	}
	return results, nil
}

func emailDestinationID(channelID, recipient string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(recipient))))
	return strings.TrimSpace(channelID) + "/recipient/" + fmt.Sprintf("%x", sum[:8])
}

func NotifierForChannel(channel store.NotificationChannel, timeout time.Duration, retryMax int, retryBaseDelay time.Duration, client *http.Client, allowPrivate bool) IncidentEventNotifier {
	return NotifierForChannelWithRelay(channel, timeout, retryMax, retryBaseDelay, client, allowPrivate, nil)
}

func NotifierForChannelWithRelay(channel store.NotificationChannel, timeout time.Duration, retryMax int, retryBaseDelay time.Duration, client *http.Client, allowPrivate bool, emailRelay EmailRelay) IncidentEventNotifier {
	if channel.Type == "email" {
		return EmailNotifier{Channel: channel, Relay: emailRelay, Timeout: timeout}
	}
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	if retryBaseDelay == 0 {
		retryBaseDelay = time.Second
	}
	return WebhookNotifier{Type: channel.Type, URL: channel.WebhookURL, Timeout: timeout, RetryMax: retryMax, RetryBaseDelay: retryBaseDelay, HTTP: client, AllowPrivate: allowPrivate}
}

func matchesFilters(channel store.NotificationChannel, incident store.Incident, eventType string) bool {
	if len(channel.SeverityFilter) > 0 && !contains(channel.SeverityFilter, incident.Severity) {
		return false
	}
	if len(channel.EventTypeFilter) > 0 && !contains(channel.EventTypeFilter, eventType) {
		return false
	}
	return true
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), want) {
			return true
		}
	}
	return false
}
