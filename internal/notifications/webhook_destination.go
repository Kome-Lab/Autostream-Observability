package notifications

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var webhookLookupIPAddr = net.DefaultResolver.LookupIPAddr

func MaskWebhookURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
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

func ValidateWebhookURL(raw string) error {
	return ValidateWebhookURLWithPolicy(raw, allowPrivateWebhooksFromEnv())
}

func ValidateWebhookURLForType(raw, channelType string) error {
	return ValidateWebhookURLForTypeWithPolicy(raw, channelType, allowPrivateWebhooksFromEnv())
}

func NormalizeWebhookURLForType(raw, channelType string) (string, error) {
	return NormalizeWebhookURLForTypeWithPolicy(raw, channelType, allowPrivateWebhooksFromEnv())
}

func ValidateWebhookURLWithPolicy(raw string, allowPrivate bool) error {
	return ValidateWebhookURLForTypeWithPolicy(raw, "generic", allowPrivate)
}

func ValidateWebhookURLForTypeWithPolicy(raw, channelType string, allowPrivate bool) error {
	_, err := NormalizeWebhookURLForTypeWithPolicy(raw, channelType, allowPrivate)
	return err
}

func NormalizeWebhookURLForTypeWithPolicy(raw, channelType string, allowPrivate bool) (string, error) {
	trimmed := strings.TrimSpace(raw)
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("notification webhook URL must be an absolute URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("notification webhook URL must use http or https")
	}
	if parsed.Scheme == "http" && !allowPrivate {
		return "", errors.New("notification webhook URL must use https for remote targets")
	}
	if parsed.User != nil {
		return "", errors.New("notification webhook URL must not include userinfo")
	}
	if !allowPrivate && unsafeWebhookHost(parsed.Hostname()) {
		return "", errors.New("notification webhook URL must not target a private network")
	}
	if !allowPrivate && !webhookHostAllowedForType(parsed.Hostname(), channelType) {
		return "", errors.New("notification webhook URL host does not match channel type")
	}
	if normalizedType(channelType) == "discord" && isDiscordWebhookHost(parsed.Hostname()) {
		if parsed.Scheme != "https" {
			return "", errors.New("notification Discord webhook URL must use https")
		}
		if port := parsed.Port(); port != "" && port != "443" {
			return "", errors.New("notification Discord webhook URL must use the default HTTPS port")
		}
		if parsed.Fragment != "" {
			return "", errors.New("notification Discord webhook URL must not include a fragment")
		}
		if !validDiscordWebhookPath(parsed.EscapedPath()) {
			return "", errors.New("notification Discord webhook URL path is invalid")
		}
		parsed.Scheme = "https"
		parsed.Host = "discord.com"
		return parsed.String(), nil
	}
	return trimmed, nil
}

func webhookHostAllowedForType(host, channelType string) bool {
	normalizedHost := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	switch normalizedType(channelType) {
	case "discord":
		return isDiscordWebhookHost(normalizedHost)
	case "slack":
		return normalizedHost == "hooks.slack.com"
	default:
		return true
	}
}

func isDiscordWebhookHost(host string) bool {
	switch strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), ".")) {
	case "discord.com", "www.discord.com", "ptb.discord.com", "canary.discord.com",
		"discordapp.com", "www.discordapp.com", "ptb.discordapp.com", "canary.discordapp.com":
		return true
	default:
		return false
	}
}

func validDiscordWebhookPath(path string) bool {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 4 {
		return parts[0] == "api" && parts[1] == "webhooks" && parts[2] != "" && parts[3] != ""
	}
	if len(parts) == 5 {
		version := strings.TrimPrefix(parts[1], "v")
		if version == parts[1] || version == "" {
			return false
		}
		if _, err := strconv.Atoi(version); err != nil {
			return false
		}
		return parts[0] == "api" && parts[2] == "webhooks" && parts[3] != "" && parts[4] != ""
	}
	return false
}

func webhookHTTPClient(timeout time.Duration, allowPrivate bool, channelType string) *http.Client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	transport := &http.Transport{
		Proxy:       nil,
		DialContext: safeWebhookDialContext(allowPrivate),
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			normalizedURL, err := NormalizeWebhookURLForTypeWithPolicy(req.URL.String(), channelType, allowPrivate)
			if err != nil {
				return err
			}
			normalized, err := url.Parse(normalizedURL)
			if err != nil {
				return errors.New("notification webhook redirect URL is invalid")
			}
			req.URL = normalized
			return nil
		},
	}
}

func safeWebhookDialContext(allowPrivate bool) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("notification webhook address is invalid")
		}
		if allowPrivate {
			return dialer.DialContext(ctx, network, address)
		}
		resolved, err := webhookLookupIPAddr(ctx, host)
		if err != nil {
			return nil, errors.New("notification webhook host resolution failed")
		}
		for _, candidate := range resolved {
			if unsafeWebhookIP(candidate.IP) {
				continue
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(candidate.IP.String(), port))
		}
		return nil, errors.New("notification webhook URL must not target a private network")
	}
}

func unsafeWebhookHost(host string) bool {
	normalized := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if normalized == "" || normalized == "localhost" || strings.HasSuffix(normalized, ".localhost") {
		return true
	}
	if ip := net.ParseIP(normalized); ip != nil {
		return unsafeWebhookIP(ip)
	}
	return false
}

func unsafeWebhookIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}
