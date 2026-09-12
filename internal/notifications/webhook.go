package notifications

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/example/autostream-observability/internal/store"
)

type WebhookNotifier struct {
	Type           string
	URL            string
	Timeout        time.Duration
	RetryMax       int
	RetryBaseDelay time.Duration
	HTTP           *http.Client
	AllowPrivate   bool
	Sleep          func(context.Context, time.Duration) error
}

func (n WebhookNotifier) Enabled() bool {
	return strings.TrimSpace(n.URL) != ""
}

func (n WebhookNotifier) NotifyIncidentOpened(ctx context.Context, incident store.Incident) ([]DeliveryResult, error) {
	return n.NotifyIncidentEvent(ctx, "incident.opened", incident)
}

func (n WebhookNotifier) NotifyIncidentEvent(ctx context.Context, eventType string, incident store.Incident) ([]DeliveryResult, error) {
	eventType = normalizedEventType(eventType)
	result := DeliveryResult{EventType: eventType, Channel: normalizedType(n.Type), Target: MaskWebhookURL(n.URL)}
	if !n.Enabled() {
		result.Status = "failure"
		result.Error = "notification webhook is not configured"
		return []DeliveryResult{result}, errors.New(result.Error)
	}
	allowPrivate := n.AllowPrivate || allowPrivateWebhooksFromEnv()
	normalizedURL, err := NormalizeWebhookURLForTypeWithPolicy(n.URL, n.Type, allowPrivate)
	if err != nil {
		result.Status = "failure"
		result.Error = SanitizeDeliveryError(err)
		return []DeliveryResult{result}, err
	}
	n.URL = normalizedURL
	result.Target = MaskWebhookURL(n.URL)
	payload, err := json.Marshal(n.payload(eventType, incident))
	if err != nil {
		result.Status = "failure"
		result.Error = SanitizeDeliveryError(err)
		return []DeliveryResult{result}, err
	}
	client := n.HTTP
	if client == nil {
		client = webhookHTTPClient(n.Timeout, allowPrivate, n.Type)
	}
	attempts := n.RetryMax + 1
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		reqCtx := ctx
		cancel := func() {}
		if n.Timeout > 0 {
			reqCtx, cancel = context.WithTimeout(ctx, n.Timeout)
		}
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, n.URL, bytes.NewReader(payload))
		if err != nil {
			cancel()
			lastErr = err
			break
		}
		req.Header.Set("Content-Type", "application/json")
		res, err := client.Do(req)
		cancel()
		retryable := false
		if err != nil {
			lastErr = err
			retryable = true
		} else {
			statusCode := res.StatusCode
			res.Body.Close()
			if statusCode >= 200 && statusCode < 300 {
				result.Status = "success"
				return []DeliveryResult{result}, nil
			}
			lastErr = fmt.Errorf("webhook returned status %d", statusCode)
			retryable = retryableWebhookStatus(statusCode)
		}
		if !retryable || attempt == attempts-1 {
			break
		}
		if err := n.sleep(ctx, webhookRetryDelay(n.RetryBaseDelay, attempt)); err != nil {
			lastErr = err
			break
		}
	}
	result.Status = "failure"
	result.Error = SanitizeDeliveryError(lastErr)
	return []DeliveryResult{result}, errors.New(result.Error)
}

func (n WebhookNotifier) sleep(ctx context.Context, delay time.Duration) error {
	return sleepWithFunc(ctx, delay, n.Sleep)
}

func sleepWithFunc(ctx context.Context, delay time.Duration, sleep func(context.Context, time.Duration) error) error {
	if delay <= 0 {
		return nil
	}
	if sleep != nil {
		return sleep(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func retryableWebhookStatus(status int) bool {
	return status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500
}

func webhookRetryDelay(base time.Duration, attempt int) time.Duration {
	if base <= 0 {
		return 0
	}
	delay := base
	for i := 0; i < attempt; i++ {
		delay *= 2
	}
	return delay
}
