package notifications

import (
	"errors"
	"net/url"
	"strings"
)

func safeEmailRelayError(err error) string {
	type safeDeliveryCoder interface {
		SafeDeliveryCode() string
	}
	code := ""
	var coder safeDeliveryCoder
	if errors.As(err, &coder) {
		code = coder.SafeDeliveryCode()
	} else if err != nil {
		code = err.Error()
	}
	if safeEmailRelayCode(code) {
		return strings.TrimSpace(code)
	}
	return "send_failed"
}

func safeEmailRelayCode(code string) bool {
	switch strings.TrimSpace(code) {
	case "smtp_not_configured", "smtp_requires_tls", "smtp_dial_failed", "smtp_starttls_failed", "smtp_auth_failed", "smtp_from_rejected", "smtp_recipient_rejected", "smtp_data_failed", "smtp_write_failed", "smtp_close_failed", "rate_limited", "send_failed",
		"missing_service_scope", "missing_service_token", "invalid_service_token", "service_token_not_registered", "service_type_not_allowed",
		"service_registry_not_configured", "list_services_failed", "app_settings_failed", "secret_encryption_key_required":
		return true
	default:
		return false
	}
}

func SanitizeChannelDeliveryError(channel string, err error) string {
	if err == nil {
		return ""
	}
	if normalizedType(channel) == "email" {
		return safeEmailRelayError(err)
	}
	return SanitizeDeliveryError(err)
}

func SanitizeDeliveryError(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		message = urlErr.Err.Error()
	}
	switch {
	case strings.Contains(message, "notification webhook URL"):
		return message
	case strings.Contains(message, "webhook returned status"):
		return message
	case strings.Contains(message, "notification webhook is not configured"):
		return message
	default:
		return "notification webhook delivery failed"
	}
}
