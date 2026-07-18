package notifications

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

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
	EventType string `json:"event_type"`
	Channel   string `json:"channel"`
	Target    string `json:"target"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
}

type EmailRelay interface {
	SendNotificationEmail(ctx context.Context, recipients []string, subject, text string) error
}

type HTMLEmailRelay interface {
	SendNotificationEmailHTML(ctx context.Context, recipients []string, subject, text, html string) error
}

const maxNotificationEmailTextBytes = 16 * 1024

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
	Relay          EmailRelay
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
	EmailRelay     EmailRelay
	Timeout        time.Duration
	EmailTimeout   time.Duration
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
		if !channel.Enabled {
			continue
		}
		if eventType != "admin.audit" && !matchesFilters(channel, incident, eventType) {
			continue
		}
		timeout := n.Timeout
		if channel.Type == "email" && n.EmailTimeout > 0 {
			timeout = n.EmailTimeout
		}
		notifier := NotifierForChannelWithRelay(channel, timeout, n.RetryMax, n.RetryBaseDelay, n.HTTP, n.AllowPrivate, n.EmailRelay)
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
	return NotifierForChannelWithRelay(channel, timeout, retryMax, retryBaseDelay, client, allowPrivate, nil)
}

func NotifierForChannelWithRelay(channel store.NotificationChannel, timeout time.Duration, retryMax int, retryBaseDelay time.Duration, client *http.Client, allowPrivate bool, emailRelay EmailRelay) IncidentEventNotifier {
	if channel.Type == "email" {
		return EmailNotifier{Channel: channel, Relay: emailRelay, Timeout: timeout, RetryMax: retryMax, RetryBaseDelay: retryBaseDelay}
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
	if len(channel.EmailRecipients) == 0 {
		result.Status = "failure"
		result.Error = "email notification is not configured"
		return []DeliveryResult{result}, errors.New(result.Error)
	}
	usesGlobalSMTP := channel.UseGlobalSMTP || !hasDirectSMTPConfiguration(channel)
	if usesGlobalSMTP && n.Relay == nil {
		result.Status = "failure"
		result.Error = "email notification delivery failed"
		return []DeliveryResult{result}, errors.New(result.Error)
	}
	if !usesGlobalSMTP && (strings.TrimSpace(channel.SMTPHost) == "" || strings.TrimSpace(channel.SMTPFrom) == "") {
		result.Status = "failure"
		result.Error = "email notification is not configured"
		return []DeliveryResult{result}, errors.New(result.Error)
	}
	addr := ""
	var auth smtp.Auth
	var msg []byte
	if !usesGlobalSMTP {
		port := channel.SMTPPort
		if port == 0 {
			port = 587
		}
		addr = net.JoinHostPort(channel.SMTPHost, strconv.Itoa(port))
		if channel.SMTPUsername != "" && channel.SMTPPassword != "" {
			auth = smtp.PlainAuth("", channel.SMTPUsername, channel.SMTPPassword, channel.SMTPHost)
		}
		msg = []byte(formatEmailMessage(eventType, incident, channel.SMTPFrom, channel.EmailRecipients))
	}
	if n.Timeout <= 0 {
		n.Timeout = 5 * time.Second
	}
	attempts := n.RetryMax + 1
	if attempts < 1 {
		attempts = 1
	}
	// The Control Panel relay may have delivered to an earlier recipient before
	// returning a later-recipient failure. Retrying the whole recipient list here
	// would therefore duplicate messages that were already accepted.
	if usesGlobalSMTP {
		attempts = 1
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if usesGlobalSMTP {
			reqCtx, cancel := context.WithTimeout(ctx, n.Timeout)
			recipients := append([]string(nil), channel.EmailRecipients...)
			subject := formatEmailSubject(eventType, incident)
			text := formatIncidentEmailText(eventType, incident)
			if htmlRelay, ok := n.Relay.(HTMLEmailRelay); ok {
				lastErr = htmlRelay.SendNotificationEmailHTML(reqCtx, recipients, subject, text, formatIncidentHTML(eventType, incident))
			} else {
				lastErr = n.Relay.SendNotificationEmail(reqCtx, recipients, subject, text)
			}
			cancel()
			if lastErr == nil {
				result.Status = "success"
				return []DeliveryResult{result}, nil
			}
		} else if n.Send == nil {
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
	if usesGlobalSMTP {
		result.Error = safeEmailRelayError(lastErr)
	}
	return []DeliveryResult{result}, lastErr
}

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
	subject := formatEmailSubjectHeader(formatEmailSubject(eventType, incident))
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	plainHeader := textproto.MIMEHeader{}
	plainHeader.Set("Content-Type", `text/plain; charset="UTF-8"`)
	plainHeader.Set("Content-Transfer-Encoding", "quoted-printable")
	plainPart, plainErr := writer.CreatePart(plainHeader)
	if plainErr == nil {
		plainWriter := quotedprintable.NewWriter(plainPart)
		_, plainErr = plainWriter.Write([]byte(formatIncidentEmailText(eventType, incident)))
		if closeErr := plainWriter.Close(); plainErr == nil {
			plainErr = closeErr
		}
	}
	htmlHeader := textproto.MIMEHeader{}
	htmlHeader.Set("Content-Type", `text/html; charset="UTF-8"`)
	htmlHeader.Set("Content-Transfer-Encoding", "quoted-printable")
	htmlPart, htmlErr := writer.CreatePart(htmlHeader)
	if htmlErr == nil {
		htmlWriter := quotedprintable.NewWriter(htmlPart)
		_, htmlErr = htmlWriter.Write([]byte(formatIncidentHTML(eventType, incident)))
		if closeErr := htmlWriter.Close(); htmlErr == nil {
			htmlErr = closeErr
		}
	}
	closeErr := writer.Close()
	if plainErr != nil || htmlErr != nil || closeErr != nil {
		return formatPlainEmailMessage(subject, from, to, formatIncidentEmailText(eventType, incident))
	}
	headers := []string{
		"From: " + formatEmailAddressHeader(from),
		"To: " + formatEmailAddressListHeader(to),
		"Subject: " + subject,
		"MIME-Version: 1.0",
		fmt.Sprintf(`Content-Type: multipart/alternative; boundary=%q`, writer.Boundary()),
	}
	return strings.Join(headers, "\r\n") + "\r\n\r\n" + body.String()
}

func formatPlainEmailMessage(subject, from string, to []string, text string) string {
	headers := []string{
		"From: " + formatEmailAddressHeader(from),
		"To: " + formatEmailAddressListHeader(to),
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"Content-Transfer-Encoding: 8bit",
	}
	return strings.Join(headers, "\r\n") + "\r\n\r\n" + text
}

func formatEmailAddressHeader(value string) string {
	value = sanitizeEmailHeaderValue(value)
	if address, err := mail.ParseAddress(value); err == nil && strings.TrimSpace(address.Address) != "" {
		return address.String()
	}
	return value
}

func formatEmailAddressListHeader(values []string) string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value = formatEmailAddressHeader(value); value != "" {
			out = append(out, value)
		}
	}
	return strings.Join(out, ", ")
}

func sanitizeEmailHeaderValue(value string) string {
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", "")
	value = strings.ReplaceAll(value, "\x00", "")
	return strings.TrimSpace(value)
}

func formatEmailSubjectHeader(subject string) string {
	subject = sanitizeEmailHeaderValue(subject)
	for index, value := range subject {
		if value > 127 {
			return subject[:index] + mime.QEncoding.Encode("UTF-8", subject[index:])
		}
	}
	return subject
}

func formatEmailSubject(eventType string, incident store.Incident) string {
	severity := strings.ToUpper(strings.TrimSpace(incident.Severity))
	if severity == "" {
		severity = "INFO"
	}
	legacy := strings.TrimSpace("[AutoStream] " + severity + " " + strings.TrimSpace(incident.Rule))
	title := notificationTitle(eventType, incident)
	subject := legacy
	if title != "" && title != strings.TrimSpace(incident.Rule) {
		subject += " | " + title
	}
	return truncateNotificationText(strings.Join(strings.Fields(strings.ReplaceAll(strings.ReplaceAll(subject, "\r", " "), "\n", " ")), " "), 200)
}

func hasDirectSMTPConfiguration(channel store.NotificationChannel) bool {
	return strings.TrimSpace(channel.SMTPHost) != "" ||
		channel.SMTPPort != 0 ||
		strings.TrimSpace(channel.SMTPFrom) != "" ||
		strings.TrimSpace(channel.SMTPUsername) != "" ||
		strings.TrimSpace(channel.SMTPPassword) != "" ||
		channel.SMTPPasswordConfigured
}

func (n WebhookNotifier) payload(eventType string, incident store.Incident) map[string]any {
	text := formatIncidentText(eventType, incident)
	switch normalizedType(n.Type) {
	case "discord":
		embed := map[string]any{
			"title":  truncateNotificationText(notificationTitle(eventType, incident), 256),
			"color":  notificationColor(incident.Severity),
			"fields": discordNotificationFields(eventType, incident),
			"footer": map[string]any{"text": "AutoStream • " + eventType},
		}
		if description := notificationDescription(eventType, incident); description != "" {
			embed["description"] = truncateNotificationText(description, 3000)
		}
		if timestamp := notificationTimestamp(incident); timestamp != "" {
			embed["timestamp"] = timestamp
		}
		return map[string]any{
			"embeds": []map[string]any{embed},
			"allowed_mentions": map[string]any{
				"parse": []string{},
			},
		}
	case "slack":
		return map[string]any{
			"text":   escapeSlackText(text),
			"blocks": slackNotificationBlocks(eventType, incident),
		}
	default:
		summary := incident.SummaryJA
		if sourceSummary := strings.TrimSpace(incident.SourceSummary); sourceSummary != "" {
			summary = sourceSummary
		}
		return map[string]any{
			"event_type":  eventType,
			"severity":    incident.Severity,
			"status":      incident.Status,
			"incident_id": incident.ID,
			"rule":        incident.Rule,
			"service_id":  incident.ServiceID,
			"stream_id":   incident.StreamID,
			"summary":     summary,
		}
	}
}

func escapeSlackText(value string) string {
	return strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
	).Replace(value)
}

func formatIncidentText(eventType string, incident store.Incident) string {
	parts := []string{notificationTitle(eventType, incident), ""}
	for _, field := range notificationMessageFields(eventType, incident) {
		parts = append(parts, field.Name+": "+field.Value)
	}
	if timestamp := notificationTimestamp(incident); timestamp != "" {
		parts = append(parts, "日時: "+timestamp)
	}
	if description := notificationDescription(eventType, incident); description != "" {
		parts = append(parts, "", "詳細", description)
	}
	return strings.Join(parts, "\n")
}

func formatIncidentEmailText(eventType string, incident store.Incident) string {
	return truncateEmailBytes(formatIncidentText(eventType, incident), maxNotificationEmailTextBytes)
}

func formatIncidentHTML(eventType string, incident store.Incident) string {
	title := truncateNotificationText(notificationTitle(eventType, incident), 256)
	summary := truncateNotificationText(notificationDescription(eventType, incident), 12000)
	if summary == "" {
		summary = "詳細情報はありません。"
	}

	var rows strings.Builder
	for _, field := range emailNotificationFields(eventType, incident) {
		rows.WriteString(`<tr><th scope="row" style="padding:10px 12px;text-align:left;vertical-align:top;width:34%;border-bottom:1px solid #e4e7ec;color:#475467;font-size:13px;font-weight:600;">`)
		rows.WriteString(html.EscapeString(field.Name))
		rows.WriteString(`</th><td style="padding:10px 12px;vertical-align:top;border-bottom:1px solid #e4e7ec;color:#101828;font-size:14px;word-break:break-word;">`)
		rows.WriteString(formatEmailHTMLText(truncateNotificationText(field.Value, 2048)))
		rows.WriteString(`</td></tr>`)
	}

	return `<!doctype html><html lang="ja"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>` +
		`<body style="margin:0;padding:0;background:#f2f4f7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#101828;">` +
		`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f2f4f7;"><tr><td align="center" style="padding:24px 12px;">` +
		`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:640px;background:#ffffff;border:1px solid #e4e7ec;border-radius:12px;overflow:hidden;">` +
		`<tr><td style="height:6px;background:` + notificationEmailAccent(incident.Severity) + `;font-size:0;line-height:0;">&nbsp;</td></tr>` +
		`<tr><td style="padding:22px 24px 14px;"><div style="color:#667085;font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;">AutoStream Notification</div>` +
		`<h1 style="margin:8px 0 0;font-size:22px;line-height:1.35;color:#101828;">` + html.EscapeString(title) + `</h1></td></tr>` +
		`<tr><td style="padding:0 24px 18px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e4e7ec;border-radius:8px;border-collapse:separate;border-spacing:0;overflow:hidden;">` + rows.String() + `</table></td></tr>` +
		`<tr><td style="padding:0 24px 24px;"><div style="margin-bottom:8px;color:#475467;font-size:13px;font-weight:700;">概要</div>` +
		`<div style="padding:14px 16px;background:#f9fafb;border-radius:8px;color:#344054;font-size:14px;line-height:1.65;word-break:break-word;">` + formatEmailHTMLText(summary) + `</div></td></tr>` +
		`<tr><td style="padding:14px 24px;background:#f9fafb;border-top:1px solid #e4e7ec;color:#667085;font-size:12px;">AutoStream Control Panel から送信された通知です。</td></tr>` +
		`</table></td></tr></table></body></html>`
}

func emailNotificationFields(eventType string, incident store.Incident) []notificationMessageField {
	eventType = normalizedEventType(eventType)
	eventValue := notificationEventLabel(eventType) + " (" + eventType + ")"
	actionCode := strings.TrimSpace(incident.Rule)
	actionValue := actionCode
	if actionCode != "" && eventType == "admin.audit" {
		actionValue = NotificationActionLabel(actionCode) + " (" + actionCode + ")"
	}
	if actionValue == "" {
		actionValue = "—"
	}
	description := notificationDescription(eventType, incident)
	resource := notificationContextValue(description, "対象", "resource")
	if resource == "" {
		switch {
		case strings.TrimSpace(incident.StreamID) != "":
			resource = "配信枠: " + strings.TrimSpace(incident.StreamID)
		case strings.TrimSpace(incident.ServiceID) != "":
			resource = "サービス: " + strings.TrimSpace(incident.ServiceID)
		case strings.TrimSpace(incident.ID) != "":
			resource = "インシデント: " + strings.TrimSpace(incident.ID)
		default:
			resource = "—"
		}
	}
	actor := notificationContextValue(description, "実行者", "actor")
	if actor == "" {
		actor = "—"
	}
	timestamp := notificationTimestamp(incident)
	if timestamp == "" {
		timestamp = "—"
	}
	return []notificationMessageField{
		{Name: "イベント", Value: eventValue},
		{Name: "操作 / ルール", Value: actionValue},
		{Name: "対象", Value: resource},
		{Name: "実行者", Value: actor},
		{Name: "結果", Value: notificationStatusLabel(incident.Status)},
		{Name: "重要度", Value: notificationSeverityLabel(incident.Severity)},
		{Name: "日時", Value: timestamp},
	}
}

func notificationContextValue(summary string, keys ...string) string {
	for _, line := range strings.Split(strings.ReplaceAll(summary, "\r\n", "\n"), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(parts) != 2 {
			continue
		}
		for _, key := range keys {
			if strings.EqualFold(strings.TrimSpace(parts[0]), key) {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func formatEmailHTMLText(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	return strings.ReplaceAll(html.EscapeString(value), "\n", "<br>")
}

func notificationEmailAccent(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "error":
		return "#d92d20"
	case "warning":
		return "#f79009"
	case "info":
		return "#1570ef"
	default:
		return "#667085"
	}
}

func truncateEmailBytes(value string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(value) <= maxBytes {
		return value
	}
	suffix := "…"
	limit := maxBytes - len(suffix)
	if limit <= 0 {
		return suffix[:maxBytes]
	}
	used := 0
	for _, value := range value {
		size := utf8.RuneLen(value)
		if size < 1 || used+size > limit {
			break
		}
		used += size
	}
	return strings.TrimSpace(value[:used]) + suffix
}

type notificationMessageField struct {
	Name  string
	Value string
}

func NotificationActionLabel(action string) string {
	action = strings.TrimSpace(action)
	labels := map[string]string{
		"app.settings.test_email":               "テストメールを送信",
		"app.settings.update":                   "アプリ設定を更新",
		"api_tokens.create":                     "APIトークンを作成",
		"api_tokens.revoke":                     "APIトークンを失効",
		"api_tokens.rotate":                     "APIトークンを再生成",
		"archive.artifact.delete":               "録画ファイルを削除",
		"archive.artifact.download":             "録画ファイルをダウンロード",
		"archive.artifact.rename":               "録画ファイル名を変更",
		"archive.artifact.share.create":         "録画ファイルの共有リンクを作成",
		"archive.artifact.share.revoke":         "録画ファイルの共有リンクを無効化",
		"archive_destinations.create":           "Drive保存先を作成",
		"archive_destinations.delete":           "Drive保存先を削除",
		"archive_destinations.update":           "Drive保存先を更新",
		"archive_profiles.create":               "Archiveプロファイルを作成",
		"archive_profiles.delete":               "Archiveプロファイルを削除",
		"archive_profiles.update":               "Archiveプロファイルを更新",
		"auth.change_password":                  "パスワードを変更",
		"auth.email.change_request":             "メールアドレス変更を申請",
		"auth.email.confirm":                    "メールアドレス変更を確認",
		"auth.login":                            "管理画面へログイン",
		"auth.logout":                           "管理画面からログアウト",
		"auth.avatar.update":                    "プロフィール画像を更新",
		"auth.avatar.delete":                    "プロフィール画像を削除",
		"auth.oauth.login":                      "OAuthでログイン",
		"auth.oauth.provision_user":             "OAuthユーザーを作成",
		"auth.oauth.start":                      "OAuthログインを開始",
		"auth.passkey.login.start":              "Passkeyログインを開始",
		"auth.passkey.login.finish":             "Passkeyでログイン",
		"auth.oauth_link.create":                "OAuth連携を作成",
		"auth.oauth_link.delete":                "OAuth連携を解除",
		"discord_configs.create":                "Discord BOT設定を作成",
		"discord_configs.delete":                "Discord BOT設定を削除",
		"discord_configs.update":                "Discord BOT設定を更新",
		"caption_profiles.create":               "Captionプロファイルを作成",
		"caption_profiles.delete":               "Captionプロファイルを削除",
		"caption_profiles.update":               "Captionプロファイルを更新",
		"encoder_profiles.create":               "Encoderプロファイルを作成",
		"encoder_profiles.delete":               "Encoderプロファイルを削除",
		"encoder_profiles.update":               "Encoderプロファイルを更新",
		"incidents.acknowledge":                 "インシデントを確認済みに変更",
		"incidents.resolve":                     "インシデントを解決済みに変更",
		"integrations.drive_destination.create": "Drive保存先を作成",
		"integrations.drive_destination.delete": "Drive保存先を削除",
		"integrations.drive_destination.update": "Drive保存先を更新",
		"integrations.oauth_account.connect":    "OAuth接続アカウントを接続",
		"integrations.oauth_account.create":     "OAuth接続アカウントを作成",
		"integrations.oauth_account.delete":     "OAuth接続アカウントを削除",
		"integrations.oauth_account.update":     "OAuth接続アカウントを更新",
		"integrations.oauth_provider.create":    "OAuthプロバイダを作成",
		"integrations.oauth_provider.delete":    "OAuthプロバイダを削除",
		"integrations.oauth_provider.update":    "OAuthプロバイダを更新",
		"mfa.disable":                           "MFAを無効化",
		"mfa.enroll":                            "MFAを登録",
		"mfa.recovery_codes.regenerate":         "MFAリカバリーコードを再発行",
		"mfa.verify":                            "MFAを確認",
		"nodes.configure_token.rotate":          "Node設定トークンを再生成",
		"nodes.delete":                          "Nodeを削除",
		"nodes.registration_token.create":       "Node登録トークンを発行",
		"nodes.runtime_token.rotate":            "Node Runtime Tokenを再生成",
		"nodes.update":                          "Nodeを更新",
		"notification_channels.create":          "通知先を作成",
		"notification_channels.delete":          "通知先を削除",
		"notification_channels.test":            "通知テストを送信",
		"notification_channels.update":          "通知先を更新",
		"oauth_accounts.create":                 "OAuth接続アカウントを作成",
		"oauth_accounts.delete":                 "OAuth接続アカウントを削除",
		"oauth_accounts.update":                 "OAuth接続アカウントを更新",
		"oauth_providers.create":                "OAuthプロバイダを作成",
		"oauth_providers.delete":                "OAuthプロバイダを削除",
		"oauth_providers.update":                "OAuthプロバイダを更新",
		"overlay_profiles.create":               "Overlayプロファイルを作成",
		"overlay_profiles.delete":               "Overlayプロファイルを削除",
		"overlay_profiles.update":               "Overlayプロファイルを更新",
		"passkeys.delete":                       "Passkeyを削除",
		"passkeys.registration.start":           "Passkey登録を開始",
		"passkeys.registration.finish":          "Passkey登録を完了",
		"remediation.approve":                   "復旧操作を承認",
		"remediation.execute":                   "復旧操作を実行",
		"roles.create":                          "ロールを作成",
		"roles.delete":                          "ロールを削除",
		"roles.update":                          "ロールを更新",
		"secrets.update":                        "シークレットを更新",
		"security.settings.update":              "セキュリティ設定を更新",
		"services.assign":                       "Nodeを割り当て",
		"services.delete":                       "Nodeを削除",
		"services.runtime_config.read":          "Nodeが実行設定を参照",
		"services.runtime_config.preview":       "Node実行設定をプレビュー",
		"services.unassign":                     "Nodeの割り当てを解除",
		"setup.first_admin":                     "初期管理者を作成",
		"system_updates.create":                 "システム更新を依頼",
		"system_updates.request":                "システム更新を依頼",
		"system_updates.cancel":                 "システム更新をキャンセル",
		"system_updates.claim":                  "システム更新ジョブを取得",
		"system_updates.authorize":              "システム更新の実行を承認",
		"system_updates.report":                 "システム更新の進捗を報告",
		"system_updates.succeeded":              "システム更新に成功",
		"system_updates.rolled_back":            "システム更新をロールバック",
		"system_updates.failed":                 "システム更新に失敗",
		"streams.create":                        "配信枠を作成",
		"streams.discord_youtube_notify":        "DiscordへYouTube配信を通知",
		"streams.mark_failed":                   "配信を失敗状態に変更",
		"streams.preview_link.create":           "プレビューリンクを作成",
		"streams.retry_upload":                  "録画ファイルのアップロードを再試行",
		"streams.start":                         "配信を開始",
		"streams.stop":                          "配信を停止",
		"streams.update":                        "配信枠を更新",
		"streams.update_settings":               "配信設定を更新",
		"streams.worker_event_test":             "Workerイベントをテスト",
		"users.create":                          "ユーザーを作成",
		"users.delete":                          "ユーザーを削除",
		"users.disable":                         "ユーザーを無効化",
		"users.email_welcome":                   "ウェルカムメールを送信",
		"users.oauth_link.create":               "ユーザーのOAuth連携を作成",
		"users.oauth_link.delete":               "ユーザーのOAuth連携を解除",
		"users.force_password_change":           "次回ログイン時のパスワード変更を要求",
		"users.lock":                            "ユーザーをロック",
		"users.reset_password":                  "ユーザーのパスワードをリセット",
		"users.update":                          "ユーザーを更新",
		"users.unlock":                          "ユーザーのロックを解除",
		"workers.assign":                        "Workerを割り当て",
		"workers.restart":                       "Workerを再起動",
		"workers.unassign":                      "Workerの割り当てを解除",
		"youtube.complete":                      "YouTube配信を終了",
		"youtube_outputs.create":                "YouTube出力を作成",
		"youtube_outputs.delete":                "YouTube出力を削除",
		"youtube_outputs.update":                "YouTube出力を更新",
	}
	if label := labels[action]; label != "" {
		return label
	}
	if action == "" {
		return "管理操作"
	}
	return action
}

func NotificationResourceLabel(resourceType string) string {
	resourceType = strings.TrimSpace(resourceType)
	labels := map[string]string{
		"archive_artifact":     "録画ファイル",
		"archive_destination":  "Drive保存先",
		"archive_share":        "共有リンク",
		"audit_log":            "監査ログ",
		"discord_config":       "Discord BOT設定",
		"node":                 "Node",
		"notification_channel": "通知先",
		"oauth_account":        "OAuth接続アカウント",
		"oauth_provider":       "OAuthプロバイダ",
		"profile":              "プロファイル",
		"role":                 "ロール",
		"secret":               "シークレット",
		"service":              "Node",
		"stream":               "配信枠",
		"user":                 "ユーザー",
		"worker":               "Worker Node",
		"youtube_output":       "YouTube出力",
	}
	if label := labels[resourceType]; label != "" {
		return label
	}
	return strings.ReplaceAll(resourceType, "_", " ")
}

func notificationTitle(eventType string, incident store.Incident) string {
	if normalizedEventType(eventType) == "admin.audit" {
		return NotificationActionLabel(incident.Rule)
	}
	label := notificationEventLabel(eventType)
	if rule := strings.TrimSpace(incident.Rule); rule != "" {
		return label + ": " + rule
	}
	return label
}

func notificationEventLabel(eventType string) string {
	labels := map[string]string{
		"incident.opened":              "インシデント発生",
		"incident.updated":             "インシデント更新",
		"incident.resolved":            "インシデント解決",
		"diagnostic.created":           "診断作成",
		"remediation.pending_approval": "復旧承認待ち",
		"remediation.executed":         "復旧実行",
		"admin.audit":                  "管理操作",
	}
	eventType = normalizedEventType(eventType)
	if label := labels[eventType]; label != "" {
		return label
	}
	return eventType
}

func notificationSeverityLabel(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "重大"
	case "error":
		return "エラー"
	case "warning":
		return "警告"
	case "info":
		return "情報"
	default:
		if severity = strings.TrimSpace(severity); severity != "" {
			return severity
		}
		return "情報"
	}
}

func notificationStatusLabel(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "success", "ok":
		return "成功"
	case "failure", "failed", "error":
		return "失敗"
	case "open":
		return "未対応"
	case "acknowledged":
		return "確認済み"
	case "resolved":
		return "解決済み"
	default:
		if status = strings.TrimSpace(status); status != "" {
			return status
		}
		return "記録済み"
	}
}

func notificationMessageFields(eventType string, incident store.Incident) []notificationMessageField {
	fields := []notificationMessageField{
		{Name: "重要度", Value: notificationSeverityLabel(incident.Severity)},
		{Name: "結果", Value: notificationStatusLabel(incident.Status)},
	}
	if rule := strings.TrimSpace(incident.Rule); rule != "" {
		name := "ルール"
		if normalizedEventType(eventType) == "admin.audit" {
			name = "操作コード"
		}
		fields = append(fields, notificationMessageField{Name: name, Value: rule})
	}
	if serviceID := strings.TrimSpace(incident.ServiceID); serviceID != "" {
		fields = append(fields, notificationMessageField{Name: "サービス", Value: serviceID})
	}
	if streamID := strings.TrimSpace(incident.StreamID); streamID != "" {
		fields = append(fields, notificationMessageField{Name: "配信枠", Value: streamID})
	}
	return fields
}

func discordNotificationFields(eventType string, incident store.Incident) []map[string]any {
	fields := notificationMessageFields(eventType, incident)
	out := make([]map[string]any, 0, len(fields))
	for _, field := range fields {
		out = append(out, map[string]any{
			"name":   field.Name,
			"value":  truncateNotificationText(field.Value, 480),
			"inline": true,
		})
	}
	return out
}

func slackNotificationBlocks(eventType string, incident store.Incident) []map[string]any {
	blocks := []map[string]any{
		{
			"type": "header",
			"text": map[string]any{
				"type": "plain_text",
				"text": truncateNotificationText(notificationTitle(eventType, incident), 150),
			},
		},
	}
	if description := notificationDescription(eventType, incident); description != "" {
		blocks = append(blocks, map[string]any{
			"type": "section",
			"text": map[string]any{
				"type": "plain_text",
				"text": truncateNotificationText(description, 3000),
			},
		})
	}
	fields := make([]map[string]any, 0, len(notificationMessageFields(eventType, incident)))
	for _, field := range notificationMessageFields(eventType, incident) {
		fields = append(fields, map[string]any{
			"type": "mrkdwn",
			"text": "*" + field.Name + "*\n" + escapeSlackText(truncateNotificationText(field.Value, 1900)),
		})
	}
	if len(fields) > 0 {
		blocks = append(blocks, map[string]any{"type": "section", "fields": fields})
	}
	contextText := "`" + escapeSlackText(eventType) + "`"
	if timestamp := notificationTimestamp(incident); timestamp != "" {
		contextText += " • " + escapeSlackText(timestamp)
	}
	blocks = append(blocks, map[string]any{
		"type": "context",
		"elements": []map[string]any{{
			"type": "mrkdwn",
			"text": contextText,
		}},
	})
	return blocks
}

func notificationDescription(eventType string, incident store.Incident) string {
	description := strings.TrimSpace(incident.SummaryJA)
	title := strings.TrimSpace(notificationTitle(eventType, incident))
	if description == title {
		return ""
	}
	if strings.HasPrefix(description, title+"\n") {
		return strings.TrimSpace(strings.TrimPrefix(description, title+"\n"))
	}
	return description
}

func notificationTimestamp(incident store.Incident) string {
	if !incident.UpdatedAt.IsZero() {
		return incident.UpdatedAt.UTC().Format(time.RFC3339)
	}
	if !incident.OpenedAt.IsZero() {
		return incident.OpenedAt.UTC().Format(time.RFC3339)
	}
	return ""
}

func notificationColor(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "error":
		return 0xd92d20
	case "warning":
		return 0xf79009
	case "info":
		return 0x1570ef
	default:
		return 0x667085
	}
}

func truncateNotificationText(value string, maxRunes int) string {
	value = strings.TrimSpace(value)
	if maxRunes <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= maxRunes {
		return value
	}
	if maxRunes == 1 {
		return "…"
	}
	return string(runes[:maxRunes-1]) + "…"
}

func normalizedEventType(value string) string {
	switch strings.TrimSpace(value) {
	case "incident.opened", "incident.updated", "incident.resolved", "diagnostic.created", "remediation.pending_approval", "remediation.executed", "admin.audit":
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

func NormalizeWebhookURLForType(raw, channelType string) (string, error) {
	return NormalizeWebhookURLForTypeWithPolicy(raw, channelType, allowPrivateWebhooksFromEnv())
}

func ValidateSMTPChannel(channel store.NotificationChannel) error {
	return ValidateSMTPChannelWithPolicy(channel, allowPrivateSMTPFromEnv())
}

func ValidateSMTPChannelWithPolicy(channel store.NotificationChannel, allowPrivate bool) error {
	if channel.UseGlobalSMTP || !hasDirectSMTPConfiguration(channel) {
		if len(channel.EmailRecipients) == 0 {
			return errors.New("notification email recipient is required")
		}
		return nil
	}
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
	usernameConfigured := strings.TrimSpace(channel.SMTPUsername) != ""
	passwordConfigured := strings.TrimSpace(channel.SMTPPassword) != "" || channel.SMTPPasswordConfigured
	if usernameConfigured != passwordConfigured {
		return errors.New("notification SMTP credentials are incomplete")
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
