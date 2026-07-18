package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/example/autostream-observability/internal/version"
)

const (
	ServiceType                    = "observability"
	dockerComposeObservabilityHost = "observability"
	notificationEmailRelayTimeout  = 25 * time.Second
	maxNotificationEmailTextBytes  = 16 * 1024
	maxNotificationEmailHTMLBytes  = 64 * 1024
)

type Client struct {
	BaseURL          string
	Token            string
	ServiceID        string
	ServiceName      string
	ServicePublicURL string
	Version          string
	HeartbeatEvery   time.Duration
	ConfigError      string
	HTTP             *http.Client
}

type RemediationRequest struct {
	ActionID   string `json:"action_id"`
	Action     string `json:"action"`
	IncidentID string `json:"incident_id"`
	StreamID   string `json:"stream_id"`
}

type NotificationEmailRequest struct {
	Recipients []string `json:"recipients"`
	Subject    string   `json:"subject"`
	Text       string   `json:"text"`
	HTML       string   `json:"html,omitempty"`
}

type NotificationEmailError struct {
	Code string
}

func (e NotificationEmailError) Error() string {
	return e.Code
}

func (e NotificationEmailError) SafeDeliveryCode() string {
	return e.Code
}

type Registration struct {
	ServiceID    string         `json:"service_id"`
	ServiceType  string         `json:"service_type"`
	ServiceName  string         `json:"service_name"`
	PublicURL    string         `json:"public_url"`
	Version      string         `json:"version"`
	Commit       string         `json:"commit,omitempty"`
	BuildDate    string         `json:"build_date,omitempty"`
	Capabilities map[string]any `json:"capabilities"`
	Hostname     string         `json:"hostname,omitempty"`
	OS           string         `json:"os,omitempty"`
	Arch         string         `json:"arch,omitempty"`
}

type Heartbeat struct {
	ServiceID    string         `json:"service_id"`
	Status       string         `json:"status"`
	Version      string         `json:"version,omitempty"`
	Commit       string         `json:"commit,omitempty"`
	BuildDate    string         `json:"build_date,omitempty"`
	Capabilities map[string]any `json:"capabilities,omitempty"`
	Hostname     string         `json:"hostname,omitempty"`
	OS           string         `json:"os,omitempty"`
	Arch         string         `json:"arch,omitempty"`
	Metrics      map[string]any `json:"metrics,omitempty"`
}

func FromEnv() Client {
	timeout := 5 * time.Second
	if raw := strings.TrimSpace(os.Getenv("CONTROL_PANEL_TIMEOUT_SEC")); raw != "" {
		if seconds, err := strconv.Atoi(raw); err == nil && seconds > 0 {
			timeout = time.Duration(seconds) * time.Second
		}
	}
	client := Client{
		BaseURL:          strings.TrimSpace(os.Getenv("CONTROL_PANEL_URL")),
		Token:            strings.TrimSpace(os.Getenv("CONTROL_PANEL_TOKEN")),
		ServiceID:        envDefault("SERVICE_ID", "observability-01"),
		ServiceName:      envDefault("SERVICE_NAME", "Observability"),
		ServicePublicURL: strings.TrimSpace(os.Getenv("SERVICE_PUBLIC_URL")),
		Version:          envDefault("SERVICE_VERSION", version.Current()),
		HeartbeatEvery:   envDuration("CONTROL_PANEL_HEARTBEAT_INTERVAL_SEC", 30*time.Second),
		HTTP:             noRedirectClient(timeout),
	}
	applyNodeConfigFromEnv(&client, ServiceType)
	return client
}

func (c Client) Enabled() bool {
	return strings.TrimSpace(c.ConfigError) == "" && strings.TrimSpace(c.BaseURL) != "" && strings.TrimSpace(c.Token) != ""
}

func (c Client) ExecuteRemediation(ctx context.Context, req RemediationRequest) error {
	if strings.TrimSpace(c.ConfigError) != "" {
		return errors.New(c.ConfigError)
	}
	if !c.Enabled() {
		return errors.New("control panel dispatch is not configured")
	}
	if strings.TrimSpace(req.ActionID) == "" || strings.TrimSpace(req.Action) == "" || strings.TrimSpace(req.IncidentID) == "" || strings.TrimSpace(req.StreamID) == "" {
		return errors.New("action_id, action, incident_id, and stream_id are required")
	}
	if err := validateHTTPURL(c.BaseURL, "CONTROL_PANEL_URL"); err != nil {
		return err
	}
	base, err := url.Parse(strings.TrimRight(c.BaseURL, "/"))
	if err != nil {
		return errors.New("control panel url is invalid")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/services/remediation-actions/execute"
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("encode remediation request: %w", err)
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = noRedirectClient(5 * time.Second)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create control panel request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("control panel dispatch failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("control panel dispatch returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (c Client) SendNotificationEmail(ctx context.Context, recipients []string, subject, text string) error {
	return c.SendNotificationEmailHTML(ctx, recipients, subject, text, "")
}

func (c Client) SendNotificationEmailHTML(ctx context.Context, recipients []string, subject, text, html string) error {
	if strings.TrimSpace(c.ConfigError) != "" {
		return errors.New(c.ConfigError)
	}
	if !c.Enabled() {
		return errors.New("control panel email relay is not configured")
	}
	cleanRecipients := make([]string, 0, len(recipients))
	for _, recipient := range recipients {
		recipient = strings.TrimSpace(recipient)
		if recipient == "" || strings.ContainsAny(recipient, "\r\n") {
			return errors.New("notification email recipients are invalid")
		}
		cleanRecipients = append(cleanRecipients, recipient)
	}
	if len(cleanRecipients) == 0 || strings.TrimSpace(subject) == "" || strings.ContainsAny(subject, "\r\n\x00") || strings.TrimSpace(text) == "" || strings.ContainsRune(text, '\x00') || len(text) > maxNotificationEmailTextBytes {
		return errors.New("notification email payload is invalid")
	}
	if strings.ContainsRune(html, '\x00') || len(html) > maxNotificationEmailHTMLBytes {
		return errors.New("notification email payload is invalid")
	}
	request := NotificationEmailRequest{
		Recipients: cleanRecipients,
		Subject:    strings.TrimSpace(subject),
		Text:       text,
		HTML:       html,
	}
	if err := validateHTTPURL(c.BaseURL, "CONTROL_PANEL_URL"); err != nil {
		return NotificationEmailError{Code: "send_failed"}
	}
	body, err := json.Marshal(request)
	if err != nil {
		return NotificationEmailError{Code: "send_failed"}
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+"/services/notifications/email", bytes.NewReader(body))
	if err != nil {
		return NotificationEmailError{Code: "send_failed"}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.Token)
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = noRedirectClient(notificationEmailRelayTimeout)
	} else if httpClient.Timeout > 0 && httpClient.Timeout < notificationEmailRelayTimeout {
		clonedClient := *httpClient
		clonedClient.Timeout = notificationEmailRelayTimeout
		httpClient = &clonedClient
	}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return NotificationEmailError{Code: "send_failed"}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	var failure struct {
		Code string `json:"code"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&failure)
	if !safeNotificationEmailCode(failure.Code) {
		failure.Code = "send_failed"
	}
	return NotificationEmailError{Code: failure.Code}
}

func safeNotificationEmailCode(code string) bool {
	switch strings.TrimSpace(code) {
	case "smtp_not_configured", "smtp_requires_tls", "smtp_dial_failed", "smtp_starttls_failed", "smtp_auth_failed", "smtp_from_rejected", "smtp_recipient_rejected", "smtp_data_failed", "smtp_write_failed", "smtp_close_failed", "rate_limited", "send_failed",
		"missing_service_scope", "missing_service_token", "invalid_service_token", "service_token_not_registered", "service_type_not_allowed",
		"service_registry_not_configured", "list_services_failed", "app_settings_failed", "secret_encryption_key_required":
		return true
	default:
		return false
	}
}

func (c Client) Register(ctx context.Context) error {
	if strings.TrimSpace(c.ConfigError) != "" {
		return errors.New(c.ConfigError)
	}
	if !c.Enabled() {
		return errors.New("control panel registration is not configured")
	}
	if err := validateServicePublicURL(c.ServicePublicURL, "SERVICE_PUBLIC_URL"); err != nil {
		return err
	}
	return c.post(ctx, "/services/register", Registration{
		ServiceID:    c.ServiceID,
		ServiceType:  ServiceType,
		ServiceName:  c.ServiceName,
		PublicURL:    c.ServicePublicURL,
		Version:      c.Version,
		Commit:       version.Commit,
		BuildDate:    version.BuildDate,
		Capabilities: serviceCapabilities(),
		Hostname:     reportHostname(),
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
	})
}

func (c Client) Heartbeat(ctx context.Context) error {
	if strings.TrimSpace(c.ConfigError) != "" {
		return errors.New(c.ConfigError)
	}
	if !c.Enabled() {
		return errors.New("control panel heartbeat is not configured")
	}
	return c.post(ctx, "/services/heartbeat", Heartbeat{
		ServiceID:    c.ServiceID,
		Status:       "online",
		Version:      c.Version,
		Commit:       version.Commit,
		BuildDate:    version.BuildDate,
		Capabilities: serviceCapabilities(),
		Hostname:     reportHostname(),
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		Metrics:      NodeRuntimeMetrics(),
	})
}

func (c Client) RunHeartbeatLoop(ctx context.Context, onError func(error)) {
	interval := c.HeartbeatEvery
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := c.Heartbeat(ctx); err != nil && onError != nil {
			onError(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c Client) post(ctx context.Context, endpoint string, payload any) error {
	if err := validateHTTPURL(c.BaseURL, "CONTROL_PANEL_URL"); err != nil {
		return err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+"/"+strings.TrimLeft(endpoint, "/"), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = noRedirectClient(5 * time.Second)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return errors.New("control panel request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("control panel request returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func noRedirectClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func serviceCapabilities() map[string]any {
	return map[string]any{
		"signal_ingest":           true,
		"incident_detection":      true,
		"diagnostics":             true,
		"remediation":             true,
		"notification_channels":   true,
		"notification_deliveries": true,
		"health_endpoint":         true,
	}
}

func reportHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(hostname)
}

func NodeRuntimeMetrics() map[string]any {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	metrics := make(map[string]any)
	for name, value := range NodeHostMetrics() {
		metrics[name] = value
	}
	metrics["observability.goroutines"] = runtime.NumGoroutine()
	metrics["observability.heap_alloc_bytes"] = mem.HeapAlloc
	metrics["observability.heap_sys_bytes"] = mem.HeapSys
	metrics["observability.heap_objects"] = mem.HeapObjects
	metrics["observability.uptime_seconds"] = time.Since(processStartedAt).Seconds()
	return metrics
}

func validateHTTPURL(raw, name string) error {
	return validateHTTPURLWithAllowedHTTPHost(raw, name, "")
}

func validateServicePublicURL(raw, name string) error {
	return validateHTTPURLWithAllowedHTTPHost(raw, name, dockerComposeObservabilityHost)
}

func validateHTTPURLWithAllowedHTTPHost(raw, name, allowedHTTPHost string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return errors.New(name + " must be an absolute URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New(name + " must use http or https")
	}
	if parsed.User != nil {
		return errors.New(name + " must not include userinfo")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New(name + " must not include query or fragment")
	}
	if parsed.Scheme == "http" && !isLocalDevHost(parsed.Hostname()) && !(allowedHTTPHost != "" && strings.EqualFold(parsed.Hostname(), allowedHTTPHost)) {
		return errors.New(name + " must use https for remote hosts")
	}
	return nil
}

func isLocalDevHost(host string) bool {
	normalized := strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	return normalized == "localhost" || normalized == "127.0.0.1" || normalized == "host.docker.internal"
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
