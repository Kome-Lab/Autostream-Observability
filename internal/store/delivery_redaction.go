package store

import (
	"net/url"
	"strings"
)

func sanitizeNotificationDelivery(delivery NotificationDelivery) NotificationDelivery {
	delivery.Target = sanitizeDeliveryTarget(delivery.Target)
	delivery.Error = sanitizeDeliveryErrorText(delivery.Error)
	delivery.Metadata = sanitizeDeliveryMetadata(delivery.Metadata)
	if delivery.Metadata == nil {
		delivery.Metadata = map[string]any{}
	}
	return delivery
}

func sanitizeDeliveryTarget(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if parsed, err := url.Parse(trimmed); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		return maskWebhookURL(trimmed)
	}
	if deliverySecretLikeValue(trimmed) {
		return "<redacted>"
	}
	return trimmed
}

func sanitizeDeliveryErrorText(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	if deliverySecretLikeValue(value) {
		return "notification delivery error redacted"
	}
	return value
}

func sanitizeDeliveryMetadata(metadata map[string]any) map[string]any {
	if metadata == nil {
		return nil
	}
	out := make(map[string]any, len(metadata))
	for key, value := range metadata {
		if deliverySecretLikeKey(key) {
			out[key] = "<redacted>"
			continue
		}
		out[key] = sanitizeDeliveryMetadataValue(value)
	}
	return out
}

func sanitizeDeliveryMetadataValue(value any) any {
	switch typed := value.(type) {
	case string:
		if deliverySecretLikeValue(typed) {
			return "<redacted>"
		}
		return typed
	case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, nil:
		return typed
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, sanitizeDeliveryMetadataValue(item))
		}
		return out
	case map[string]any:
		return sanitizeDeliveryMetadata(typed)
	default:
		return nil
	}
}

func deliverySecretLikeKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	for _, token := range []string{"webhook_url", "token", "secret", "password", "passwd", "private_key", "credential", "authorization", "stream_key", "refresh_token", "access_token", "client_secret", "api_key", "apikey"} {
		if strings.Contains(normalized, token) {
			return true
		}
	}
	return false
}

func deliverySecretLikeValue(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || strings.Contains(trimmed, "<WEBHOOK_PATH>") || strings.Contains(trimmed, "<redacted>") || strings.Contains(trimmed, "****") {
		return false
	}
	lower := strings.ToLower(trimmed)
	for _, pattern := range []string{
		"discord.com/api/webhooks/",
		"hooks.slack.com/services/",
		"token=",
		"access_token",
		"refresh_token",
		"authorization",
		"bearer ",
		"private_key",
		"password",
		"secret",
		"credential",
		"-----begin private key-----",
		"ast_svc_",
		"ast_ingest_v1.",
	} {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	if parsed, err := url.Parse(trimmed); err == nil && parsed.Scheme != "" && parsed.User != nil {
		return true
	}
	return false
}
