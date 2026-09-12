package notifications

import (
	"context"
	"errors"
	"time"

	"github.com/example/autostream-observability/internal/store"
)

type EmailRelay interface {
	SendNotificationEmail(ctx context.Context, recipients []string, subject, text string) error
}

type HTMLEmailRelay interface {
	SendNotificationEmailHTML(ctx context.Context, recipients []string, subject, text, html string) error
}

type EmailNotifier struct {
	Channel store.NotificationChannel
	Relay   EmailRelay
	Timeout time.Duration
}

func (n EmailNotifier) NotifyIncidentOpened(ctx context.Context, incident store.Incident) ([]DeliveryResult, error) {
	return n.NotifyIncidentEvent(ctx, "incident.opened", incident)
}

func (n EmailNotifier) NotifyIncidentEvent(ctx context.Context, eventType string, incident store.Incident) ([]DeliveryResult, error) {
	eventType = normalizedEventType(eventType)
	channel := n.Channel
	target := channel.MaskedEmailTarget
	if target == "" {
		target = "<EMAIL>"
	}
	result := DeliveryResult{EventType: eventType, Channel: "email", Target: target}
	if len(channel.EmailRecipients) == 0 {
		result.Status = "failure"
		result.Error = "email notification is not configured"
		return []DeliveryResult{result}, errors.New(result.Error)
	}
	if !channel.UseGlobalSMTP || n.Relay == nil {
		result.Status = "failure"
		result.Error = "email notification delivery failed"
		return []DeliveryResult{result}, errors.New(result.Error)
	}
	if n.Timeout <= 0 {
		n.Timeout = 5 * time.Second
	}
	// The Control Panel relay may have delivered to an earlier recipient before
	// returning a later-recipient failure. Retrying the whole recipient list here
	// would therefore duplicate messages that were already accepted.
	reqCtx, cancel := context.WithTimeout(ctx, n.Timeout)
	defer cancel()
	recipients := append([]string(nil), channel.EmailRecipients...)
	subject := formatEmailSubject(eventType, incident)
	text := formatIncidentEmailText(eventType, incident)
	var lastErr error
	if htmlRelay, ok := n.Relay.(HTMLEmailRelay); ok {
		lastErr = htmlRelay.SendNotificationEmailHTML(reqCtx, recipients, subject, text, formatIncidentHTML(eventType, incident))
	} else {
		lastErr = n.Relay.SendNotificationEmail(reqCtx, recipients, subject, text)
	}
	if lastErr == nil {
		result.Status = "success"
		return []DeliveryResult{result}, nil
	}
	result.Status = "failure"
	result.Error = safeEmailRelayError(lastErr)
	return []DeliveryResult{result}, lastErr
}
