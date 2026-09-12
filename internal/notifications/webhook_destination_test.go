package notifications

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/example/autostream-observability/internal/store"
)

func TestMaskWebhookURL(t *testing.T) {
	got := MaskWebhookURL("https://example.com/api/webhooks/<WEBHOOK_ID>/<WEBHOOK_TOKEN>")
	if got != "https://<WEBHOOK_HOST>/<WEBHOOK_PATH>" {
		t.Fatalf("unexpected mask: %s", got)
	}
}

func TestValidateWebhookURLRejectsPrivateTargetsByDefault(t *testing.T) {
	for _, raw := range []string{
		"http://localhost/hook",
		"http://127.0.0.1/hook",
		"http://10.0.0.1/hook",
		"http://169.254.169.254/latest/meta-data",
		"http://[::1]/hook",
		"http://user:password@example.com/hook",
	} {
		if err := ValidateWebhookURLWithPolicy(raw, false); err == nil {
			t.Fatalf("expected private or credentialed URL to be rejected: %s", raw)
		}
	}
}

func TestValidateWebhookURLIgnoresPrivateWebhookAllowanceInProduction(t *testing.T) {
	raw := "http://127.0.0.1/hook"

	t.Run("development explicit allowance", func(t *testing.T) {
		t.Setenv("OBSERVABILITY_ALLOW_PRIVATE_WEBHOOKS", "true")
		if err := ValidateWebhookURL(raw); err != nil {
			t.Fatalf("development private webhook allowance rejected: %v", err)
		}
	})

	t.Run("production ignores explicit allowance", func(t *testing.T) {
		t.Setenv("OBSERVABILITY_ENV", "production")
		t.Setenv("OBSERVABILITY_ALLOW_PRIVATE_WEBHOOKS", "true")
		if err := ValidateWebhookURL(raw); err == nil {
			t.Fatal("production must reject private webhook even when OBSERVABILITY_ALLOW_PRIVATE_WEBHOOKS=true")
		}
	})
}

func TestValidateWebhookURLRejectsRemoteHTTPByDefault(t *testing.T) {
	if err := ValidateWebhookURLWithPolicy("http://hooks.example.com/services/TOKEN", false); err == nil {
		t.Fatal("remote webhook URL over HTTP must be rejected by default")
	}
}

func TestValidateWebhookURLRestrictsDiscordAndSlackHosts(t *testing.T) {
	if err := ValidateWebhookURLForTypeWithPolicy("https://example.com/webhook/token", "discord", false); err == nil {
		t.Fatal("discord channel must reject non-Discord webhook host")
	}
	if err := ValidateWebhookURLForTypeWithPolicy("https://example.com/webhook/token", "slack", false); err == nil {
		t.Fatal("slack channel must reject non-Slack webhook host")
	}
	if err := ValidateWebhookURLForTypeWithPolicy("https://discord.com/api/webhooks/id/token", "discord", false); err != nil {
		t.Fatalf("discord webhook host rejected: %v", err)
	}
	if err := ValidateWebhookURLForTypeWithPolicy("https://hooks.slack.com/services/T000/B000/XXX", "slack", false); err != nil {
		t.Fatalf("slack webhook host rejected: %v", err)
	}
	if err := ValidateWebhookURLForTypeWithPolicy("https://example.com/webhook/token", "generic", false); err != nil {
		t.Fatalf("generic webhook should allow arbitrary public HTTPS host: %v", err)
	}
}

func TestNormalizeDiscordWebhookURLAliases(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "canonical", raw: "https://discord.com/api/webhooks/id/token", want: "https://discord.com/api/webhooks/id/token"},
		{name: "www", raw: "https://www.discord.com/api/webhooks/id/token", want: "https://discord.com/api/webhooks/id/token"},
		{name: "ptb", raw: "https://ptb.discord.com/api/webhooks/id/token?wait=true", want: "https://discord.com/api/webhooks/id/token?wait=true"},
		{name: "canary", raw: "https://canary.discord.com/api/webhooks/id/token", want: "https://discord.com/api/webhooks/id/token"},
		{name: "legacy", raw: "https://discordapp.com/api/webhooks/id/token", want: "https://discord.com/api/webhooks/id/token"},
		{name: "legacy www", raw: "https://www.discordapp.com/api/webhooks/id/token", want: "https://discord.com/api/webhooks/id/token"},
		{name: "legacy ptb", raw: "https://ptb.discordapp.com/api/webhooks/id/token", want: "https://discord.com/api/webhooks/id/token"},
		{name: "legacy canary", raw: "https://canary.discordapp.com/api/webhooks/id/token", want: "https://discord.com/api/webhooks/id/token"},
		{name: "explicit default port", raw: "https://ptb.discord.com:443/api/webhooks/id/token", want: "https://discord.com/api/webhooks/id/token"},
		{name: "versioned API path", raw: "https://canary.discord.com/api/v10/webhooks/id/token?thread_id=123", want: "https://discord.com/api/v10/webhooks/id/token?thread_id=123"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeWebhookURLForTypeWithPolicy(tt.raw, "discord", false)
			if err != nil {
				t.Fatalf("normalize Discord webhook URL: %v", err)
			}
			if got != tt.want {
				t.Fatalf("normalized URL = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeDiscordWebhookURLRejectsDeceptiveOrInvalidTargets(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "deceptive suffix", raw: "https://discord.com.evil.example/api/webhooks/id/token"},
		{name: "unapproved subdomain", raw: "https://evil.discord.com/api/webhooks/id/token"},
		{name: "legacy deceptive suffix", raw: "https://discordapp.com.evil.example/api/webhooks/id/token"},
		{name: "non default port", raw: "https://discord.com:444/api/webhooks/id/token"},
		{name: "wrong path", raw: "https://discord.com/channels/id/token"},
		{name: "missing token", raw: "https://discord.com/api/webhooks/id"},
		{name: "extra path segment", raw: "https://discord.com/api/webhooks/id/token/extra"},
		{name: "invalid API version", raw: "https://discord.com/api/latest/webhooks/id/token"},
		{name: "fragment", raw: "https://discord.com/api/webhooks/id/token#secret"},
		{name: "HTTP", raw: "http://discord.com/api/webhooks/id/token"},
		{name: "userinfo", raw: "https://user@discord.com/api/webhooks/id/token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NormalizeWebhookURLForTypeWithPolicy(tt.raw, "discord", false); err == nil {
				t.Fatalf("expected Discord webhook URL to be rejected: %s", tt.raw)
			}
		})
	}
}

func TestDiscordWebhookNotifierCanonicalizesAliasBeforeSend(t *testing.T) {
	var gotURL string
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotURL = req.URL.String()
		return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody, Header: make(http.Header)}, nil
	})}
	notifier := WebhookNotifier{
		Type: "discord",
		URL:  "https://ptb.discord.com/api/webhooks/id/token?wait=true",
		HTTP: client,
	}
	results, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "inc-01", Severity: "info"})
	if err != nil {
		t.Fatal(err)
	}
	if gotURL != "https://discord.com/api/webhooks/id/token?wait=true" {
		t.Fatalf("request URL = %q", gotURL)
	}
	if len(results) != 1 || results[0].Target != "https://discord.com/<WEBHOOK_PATH>" {
		t.Fatalf("unexpected delivery result: %#v", results)
	}
}

func TestWebhookNotifierRejectsHostResolvingPrivateNetwork(t *testing.T) {
	original := webhookLookupIPAddr
	webhookLookupIPAddr = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		if host != "webhook.public-name.example" {
			t.Fatalf("unexpected host lookup: %s", host)
		}
		return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
	}
	defer func() { webhookLookupIPAddr = original }()

	notifier := WebhookNotifier{
		Type:     "generic",
		URL:      "https://webhook.public-name.example/hook/secret-token",
		RetryMax: -1,
	}
	results, err := notifier.NotifyIncidentOpened(t.Context(), store.Incident{ID: "inc-04", Rule: "webhook_private_dns", Severity: "critical", Status: "open", SummaryJA: "Webhook private DNS target.", ServiceID: "obs-01"})
	if err == nil {
		t.Fatal("expected webhook delivery to reject private DNS target")
	}
	if len(results) != 1 || results[0].Status != "failure" || results[0].Target != "https://<WEBHOOK_HOST>/<WEBHOOK_PATH>" || strings.Contains(results[0].Error, "169.254.169.254") || strings.Contains(results[0].Error, "secret-token") {
		t.Fatalf("unexpected sanitized failure result: %#v", results)
	}
	if strings.Contains(err.Error(), "169.254.169.254") || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("secret leaked in returned error: %v", err)
	}
}

func TestValidateWebhookURLAllowsPrivateTargetOnlyWhenExplicit(t *testing.T) {
	if err := ValidateWebhookURLWithPolicy("http://127.0.0.1:8080/hook", true); err != nil {
		t.Fatalf("explicit private webhook allowance rejected: %v", err)
	}
	if err := ValidateWebhookURLWithPolicy("https://hooks.example.com/services/TOKEN", false); err != nil {
		t.Fatalf("public webhook rejected: %v", err)
	}
}
