package notifications

import (
	"os"
	"strconv"
	"strings"
	"time"
)

func FromEnv() WebhookNotifier {
	return WebhookNotifier{
		Type:           envDefault("NOTIFICATION_WEBHOOK_TYPE", "generic"),
		URL:            os.Getenv("NOTIFICATION_WEBHOOK_URL"),
		Timeout:        envDuration("NOTIFICATION_WEBHOOK_TIMEOUT_SEC", 5*time.Second),
		RetryMax:       envInt("NOTIFICATION_WEBHOOK_RETRY_MAX", 3),
		RetryBaseDelay: envDuration("NOTIFICATION_WEBHOOK_RETRY_BASE_DELAY_SEC", time.Second),
		AllowPrivate:   allowPrivateWebhooksFromEnv(),
	}
}

func envDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	duration, err := time.ParseDuration(value + "s")
	if err != nil || duration <= 0 {
		return fallback
	}
	return duration
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return fallback
	}
	return parsed
}

func allowPrivateWebhooksFromEnv() bool {
	if observabilityProductionEnvironment() {
		return false
	}
	return envTruthy("OBSERVABILITY_ALLOW_PRIVATE_WEBHOOKS")
}

func observabilityProductionEnvironment() bool {
	for _, key := range []string{"OBSERVABILITY_ENV", "AUTOSTREAM_ENV", "APP_ENV", "GO_ENV"} {
		if strings.EqualFold(strings.TrimSpace(os.Getenv(key)), "production") {
			return true
		}
	}
	return false
}

func envTruthy(key string) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	return value == "1" || value == "true" || value == "yes"
}
