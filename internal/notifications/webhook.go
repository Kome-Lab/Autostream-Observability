package notifications

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/example/autostream-observability/internal/store"
)

type Notifier interface {
	NotifyIncidentOpened(ctx context.Context, incident store.Incident) ([]DeliveryResult, error)
}

type IncidentEventNotifier interface {
	NotifyIncidentEvent(ctx context.Context, eventType string, incident store.Incident) ([]DeliveryResult, error)
}

func NotifyIncidentEvent(ctx context.Context, notifier Notifier, eventType string, incident store.Incident) ([]DeliveryResult, error) {
	if eventNotifier, ok := notifier.(IncidentEventNotifier); ok {
		return eventNotifier.NotifyIncidentEvent(ctx, eventType, incident)
	}
	if eventType == "incident.opened" {
		return notifier.NotifyIncidentOpened(ctx, incident)
	}
	return nil, nil
}

type DeliveryResult struct {
	EventType string
	Channel   string
	Target    string
	Status    string
	Error     string
}

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

type EmailNotifier struct {
	Channel        store.NotificationChannel
	Timeout        time.Duration
	RetryMax       int
	RetryBaseDelay time.Duration
	Send           func(addr string, auth smtp.Auth, from string, to []string, msg []byte) error
	Sleep          func(context.Context, time.Duration) error
}

var smtpLookupIPAddr = net.DefaultResolver.LookupIPAddr
var webhookLookupIPAddr = net.DefaultResolver.LookupIPAddr

type ChannelStore interface {
	ListNotificationChannels(ctx context.Context) ([]store.NotificationChannel, error)
}

type ChannelNotifier struct {
	Store          ChannelStore
	Fallback       Notifier
	Timeout        time.Duration
	RetryMax       int
	RetryBaseDelay time.Duration
	HTTP           *http.Client
	AllowPrivate   bool
}

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
	if err := ValidateWebhookURLForTypeWithPolicy(n.URL, n.Type, allowPrivate); err != nil {
		result.Status = "failure"
		result.Error = SanitizeDeliveryError(err)
		return []DeliveryResult{result}, err
	}
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

func (n ChannelNotifier) NotifyIncidentOpened(ctx context.Context, incident store.Incident) ([]DeliveryResult, error) {
	return n.NotifyIncidentEvent(ctx, "incident.opened", incident)
}

func (n ChannelNotifier) NotifyIncidentEvent(ctx context.Context, eventType string, incident store.Incident) ([]DeliveryResult, error) {
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
	for _, channel := range channels {
		if !channel.Enabled || !matchesFilters(channel, incident, eventType) {
			continue
		}
		notifier := NotifierForChannel(channel, n.Timeout, n.RetryMax, n.RetryBaseDelay, n.HTTP, n.AllowPrivate)
		deliveries, _ := notifier.NotifyIncidentEvent(ctx, eventType, incident)
		for _, delivery := range deliveries {
			delivery.Channel = channel.Type
			if channel.Type == "email" {
				delivery.Target = channel.MaskedEmailTarget
			} else {
				delivery.Target = channel.MaskedWebhookURL
			}
			results = append(results, delivery)
		}
	}
	if len(results) == 0 && n.Fallback != nil {
		return NotifyIncidentEvent(ctx, n.Fallback, eventType, incident)
	}
	return results, nil
}

func NotifierForChannel(channel store.NotificationChannel, timeout time.Duration, retryMax int, retryBaseDelay time.Duration, client *http.Client, allowPrivate bool) IncidentEventNotifier {
	if channel.Type == "email" {
		return EmailNotifier{Channel: channel, Timeout: timeout, RetryMax: retryMax, RetryBaseDelay: retryBaseDelay}
	}
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	if retryBaseDelay == 0 {
		retryBaseDelay = time.Second
	}
	return WebhookNotifier{Type: channel.Type, URL: channel.WebhookURL, Timeout: timeout, RetryMax: retryMax, RetryBaseDelay: retryBaseDelay, HTTP: client, AllowPrivate: allowPrivate}
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
	if len(channel.EmailRecipients) == 0 || strings.TrimSpace(channel.SMTPHost) == "" || strings.TrimSpace(channel.SMTPFrom) == "" {
		result.Status = "failure"
		result.Error = "email notification is not configured"
		return []DeliveryResult{result}, errors.New(result.Error)
	}
	port := channel.SMTPPort
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(channel.SMTPHost, strconv.Itoa(port))
	var auth smtp.Auth
	if channel.SMTPUsername != "" && channel.SMTPPassword != "" {
		auth = smtp.PlainAuth("", channel.SMTPUsername, channel.SMTPPassword, channel.SMTPHost)
	}
	msg := []byte(formatEmailMessage(eventType, incident, channel.SMTPFrom, channel.EmailRecipients))
	if n.Timeout <= 0 {
		n.Timeout = 5 * time.Second
	}
	attempts := n.RetryMax + 1
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if n.Send == nil {
			reqCtx, cancel := context.WithTimeout(ctx, n.Timeout)
			lastErr = safeSMTPSendMail(reqCtx, channel, auth, msg, allowPrivateSMTPFromEnv())
			cancel()
			if lastErr == nil {
				result.Status = "success"
				return []DeliveryResult{result}, nil
			}
		} else {
			errCh := make(chan error, 1)
			go func() {
				errCh <- n.Send(addr, auth, channel.SMTPFrom, channel.EmailRecipients, msg)
			}()
			timer := time.NewTimer(n.Timeout)
			select {
			case <-ctx.Done():
				timer.Stop()
				result.Status = "failure"
				result.Error = "email notification delivery failed"
				return []DeliveryResult{result}, ctx.Err()
			case err := <-errCh:
				timer.Stop()
				if err == nil {
					result.Status = "success"
					return []DeliveryResult{result}, nil
				}
				lastErr = err
			case <-timer.C:
				lastErr = context.DeadlineExceeded
			}
		}
		if attempt == attempts-1 {
			break
		}
		if err := sleepWithFunc(ctx, webhookRetryDelay(n.RetryBaseDelay, attempt), n.Sleep); err != nil {
			lastErr = err
			break
		}
	}
	result.Status = "failure"
	result.Error = "email notification delivery failed"
	return []DeliveryResult{result}, lastErr
}

func safeSMTPSendMail(ctx context.Context, channel store.NotificationChannel, auth smtp.Auth, msg []byte, allowPrivate bool) error {
	host := strings.TrimSpace(channel.SMTPHost)
	port := channel.SMTPPort
	if port == 0 {
		port = 587
	}
	conn, err := safeSMTPDialContext(ctx, host, port, allowPrivate)
	if err != nil {
		return err
	}
	defer conn.Close()
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer client.Close()
	if err := client.Hello("localhost"); err != nil {
		return err
	}
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	} else if channel.SMTPTLS {
		return errors.New("notification SMTP STARTTLS unavailable")
	}
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return err
		}
	}
	if err := client.Mail(channel.SMTPFrom); err != nil {
		return err
	}
	for _, recipient := range channel.EmailRecipients {
		if err := client.Rcpt(recipient); err != nil {
			return err
		}
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(msg); err != nil {
		writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func safeSMTPDialContext(ctx context.Context, host string, port int, allowPrivate bool) (net.Conn, error) {
	if port <= 0 || port > 65535 {
		return nil, errors.New("notification SMTP port is invalid")
	}
	if allowPrivate {
		dialer := &net.Dialer{}
		return dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	}
	resolved, err := smtpLookupIPAddr(ctx, host)
	if err != nil {
		return nil, errors.New("notification SMTP host resolution failed")
	}
	dialer := &net.Dialer{}
	for _, candidate := range resolved {
		if unsafeWebhookIP(candidate.IP) {
			continue
		}
		return dialer.DialContext(ctx, "tcp", net.JoinHostPort(candidate.IP.String(), strconv.Itoa(port)))
	}
	return nil, errors.New("notification SMTP host must not target a private network")
}

func formatEmailMessage(eventType string, incident store.Incident, from string, to []string) string {
	subject := "[AutoStream] " + strings.ToUpper(incident.Severity) + " " + incident.Rule
	headers := []string{
		"From: " + from,
		"To: " + strings.Join(to, ", "),
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
	}
	return strings.Join(headers, "\r\n") + "\r\n\r\n" + formatIncidentText(eventType, incident)
}

func (n WebhookNotifier) payload(eventType string, incident store.Incident) map[string]any {
	text := formatIncidentText(eventType, incident)
	switch normalizedType(n.Type) {
	case "discord":
		return map[string]any{"content": text}
	case "slack":
		return map[string]any{"text": text}
	default:
		return map[string]any{
			"event_type":  eventType,
			"severity":    incident.Severity,
			"status":      incident.Status,
			"incident_id": incident.ID,
			"rule":        incident.Rule,
			"service_id":  incident.ServiceID,
			"stream_id":   incident.StreamID,
			"summary":     incident.SummaryJA,
		}
	}
}

func formatIncidentText(eventType string, incident store.Incident) string {
	parts := []string{
		strings.ToUpper(incident.Severity) + ": " + incident.SummaryJA,
		"Event: " + eventType,
		"Rule: " + incident.Rule,
		"Service: " + incident.ServiceID,
	}
	if incident.StreamID != "" {
		parts = append(parts, "Stream: "+incident.StreamID)
	}
	parts = append(parts, "Status: "+incident.Status)
	return strings.Join(parts, "\n")
}

func normalizedEventType(value string) string {
	switch strings.TrimSpace(value) {
	case "incident.opened", "incident.updated", "incident.resolved", "diagnostic.created", "remediation.pending_approval", "remediation.executed":
		return strings.TrimSpace(value)
	default:
		return "incident.updated"
	}
}

func normalizedType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "discord", "discord_webhook":
		return "discord"
	case "slack", "slack_webhook":
		return "slack"
	case "email":
		return "email"
	default:
		return "generic"
	}
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

func ValidateSMTPChannel(channel store.NotificationChannel) error {
	return ValidateSMTPChannelWithPolicy(channel, allowPrivateSMTPFromEnv())
}

func ValidateSMTPChannelWithPolicy(channel store.NotificationChannel, allowPrivate bool) error {
	host := strings.TrimSpace(channel.SMTPHost)
	if host == "" {
		return errors.New("notification SMTP host is required")
	}
	if strings.ContainsAny(host, `/\@`) {
		return errors.New("notification SMTP host must be a hostname or IP address")
	}
	if !allowPrivate && unsafeWebhookHost(host) {
		return errors.New("notification SMTP host must not target a private network")
	}
	if channel.SMTPPort < 0 || channel.SMTPPort > 65535 {
		return errors.New("notification SMTP port is invalid")
	}
	if !allowPrivate && !channel.SMTPTLS {
		return errors.New("notification SMTP requires TLS for remote targets")
	}
	if (channel.SMTPUsername != "" || channel.SMTPPassword != "") && !channel.SMTPTLS {
		return errors.New("notification SMTP credentials require TLS")
	}
	return nil
}

func ValidateWebhookURLWithPolicy(raw string, allowPrivate bool) error {
	return ValidateWebhookURLForTypeWithPolicy(raw, "generic", allowPrivate)
}

func ValidateWebhookURLForTypeWithPolicy(raw, channelType string, allowPrivate bool) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return errors.New("notification webhook URL must be an absolute URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("notification webhook URL must use http or https")
	}
	if parsed.Scheme == "http" && !allowPrivate {
		return errors.New("notification webhook URL must use https for remote targets")
	}
	if parsed.User != nil {
		return errors.New("notification webhook URL must not include userinfo")
	}
	if !allowPrivate && unsafeWebhookHost(parsed.Hostname()) {
		return errors.New("notification webhook URL must not target a private network")
	}
	if !allowPrivate && !webhookHostAllowedForType(parsed.Hostname(), channelType) {
		return errors.New("notification webhook URL host does not match channel type")
	}
	return nil
}

func webhookHostAllowedForType(host, channelType string) bool {
	normalizedHost := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	switch normalizedType(channelType) {
	case "discord":
		return normalizedHost == "discord.com" || normalizedHost == "www.discord.com"
	case "slack":
		return normalizedHost == "hooks.slack.com"
	default:
		return true
	}
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
			return ValidateWebhookURLForTypeWithPolicy(req.URL.String(), channelType, allowPrivate)
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

func allowPrivateSMTPFromEnv() bool {
	if observabilityProductionEnvironment() {
		return false
	}
	return envTruthy("OBSERVABILITY_ALLOW_PRIVATE_SMTP")
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
