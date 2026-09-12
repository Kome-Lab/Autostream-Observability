package httpapi

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/example/autostream-observability/internal/store"
)

var standaloneSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bAIza[0-9A-Za-z_-]{35}\b`),
	regexp.MustCompile(`\beyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\b`),
	regexp.MustCompile(`\bmfa\.[0-9A-Za-z_-]{60,}\b`),
	regexp.MustCompile(`\b[MN][0-9A-Za-z]{23}\.[0-9A-Za-z_-]{6}\.[0-9A-Za-z_-]{27}\b`),
}

func safeAttributeEvidence(attributes map[string]any) []string {
	if len(attributes) == 0 {
		return nil
	}
	allowed := []string{
		"failure_phase", "error_class", "dry_run", "upload_dry_run", "upload_attempts", "file_count", "remux_duration_ms",
		"discord.audio_forwarded_total", "discord.audio_forward_errors_total", "discord.audio_last_forward_age_sec", "discord.audio_last_packet_age_sec",
		"discord.worker_event_publish_failures_total", counterDeltaAttribute, "observability.counter_reset",
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
