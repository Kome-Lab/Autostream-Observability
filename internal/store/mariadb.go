package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

type MariaDBStore struct {
	DB        *sql.DB
	SecretKey string
}

func (s MariaDBStore) AllowRateLimit(ctx context.Context, bucketKey string, window time.Duration, burst int, now time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if bucketKey == "" || window <= 0 || burst <= 0 {
		return false, nil
	}
	windowStart := rateLimitWindowStart(now.UTC(), window)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	cleanupBefore := windowStart.Add(-2 * window)
	if _, err := tx.ExecContext(ctx, `DELETE FROM rate_limit_buckets WHERE updated_at < ?`, cleanupBefore); err != nil {
		return false, err
	}

	var existingWindow time.Time
	var hits int
	err = tx.QueryRowContext(ctx, `SELECT window_start, hit_count FROM rate_limit_buckets WHERE bucket_key = ? FOR UPDATE`, bucketKey).Scan(&existingWindow, &hits)
	if err == sql.ErrNoRows {
		if _, err := tx.ExecContext(ctx, `INSERT INTO rate_limit_buckets (bucket_key, window_start, hit_count, updated_at) VALUES (?, ?, ?, ?)`, bucketKey, windowStart, 1, now.UTC()); err != nil {
			return false, err
		}
		return true, tx.Commit()
	}
	if err != nil {
		return false, err
	}
	if !existingWindow.Equal(windowStart) {
		if _, err := tx.ExecContext(ctx, `UPDATE rate_limit_buckets SET window_start = ?, hit_count = ?, updated_at = ? WHERE bucket_key = ?`, windowStart, 1, now.UTC(), bucketKey); err != nil {
			return false, err
		}
		return true, tx.Commit()
	}
	if hits >= burst {
		if _, err := tx.ExecContext(ctx, `UPDATE rate_limit_buckets SET updated_at = ? WHERE bucket_key = ?`, now.UTC(), bucketKey); err != nil {
			return false, err
		}
		return false, tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `UPDATE rate_limit_buckets SET hit_count = hit_count + 1, updated_at = ? WHERE bucket_key = ?`, now.UTC(), bucketKey); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func rateLimitWindowStart(now time.Time, window time.Duration) time.Time {
	if window <= 0 {
		return now.UTC()
	}
	windowNanos := int64(window)
	if windowNanos <= 0 {
		return now.UTC()
	}
	return time.Unix(0, now.UnixNano()-(now.UnixNano()%windowNanos)).UTC()
}

func (s MariaDBStore) SaveSignal(ctx context.Context, signal Signal) (Signal, error) {
	if err := ctx.Err(); err != nil {
		return Signal{}, err
	}
	now := time.Now().UTC()
	if signal.ID == "" {
		signal.ID = newID("sig")
	}
	if signal.Timestamp.IsZero() {
		signal.Timestamp = now
	}
	signal.CreatedAt = now
	if signal.Attributes == nil {
		signal.Attributes = map[string]any{}
	}
	attrs, err := json.Marshal(signal.Attributes)
	if err != nil {
		return Signal{}, err
	}
	var value any
	if signal.Value != nil {
		value = *signal.Value
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO signals
(id, signal_type, name, service_id, service_type, stream_id, status, value_double, attributes, occurred_at, created_at)
VALUES (?, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), ?, ?, ?, ?)`,
		signal.ID, signal.Type, signal.Name, signal.ServiceID, signal.ServiceType, signal.StreamID, signal.Status, value, string(attrs), signal.Timestamp, signal.CreatedAt); err != nil {
		return Signal{}, err
	}
	return signal, nil
}

func (s MariaDBStore) ListSignals(ctx context.Context, limit int) ([]Signal, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id, signal_type, name, service_id, service_type, COALESCE(stream_id, ''), COALESCE(status, ''), value_double, attributes, occurred_at, created_at
FROM signals ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Signal
	for rows.Next() {
		var signal Signal
		var value sql.NullFloat64
		var attrsRaw []byte
		if err := rows.Scan(&signal.ID, &signal.Type, &signal.Name, &signal.ServiceID, &signal.ServiceType, &signal.StreamID, &signal.Status, &value, &attrsRaw, &signal.Timestamp, &signal.CreatedAt); err != nil {
			return nil, err
		}
		if value.Valid {
			v := value.Float64
			signal.Value = &v
		}
		signal.Attributes = map[string]any{}
		if len(attrsRaw) > 0 {
			_ = json.Unmarshal(attrsRaw, &signal.Attributes)
		}
		out = append(out, signal)
	}
	return out, rows.Err()
}

func (s MariaDBStore) UpsertIncident(ctx context.Context, incident Incident) (Incident, bool, error) {
	if err := ctx.Err(); err != nil {
		return Incident{}, false, err
	}
	now := time.Now().UTC()
	existing, err := s.findOpenIncident(ctx, incident.Rule, incident.ServiceID, incident.StreamID)
	if err == nil {
		existing.SignalID = incident.SignalID
		existing.SummaryJA = incident.SummaryJA
		existing.Report = incident.Report
		existing.UpdatedAt = now
		report, err := json.Marshal(existing.Report)
		if err != nil {
			return Incident{}, false, err
		}
		if _, err := s.DB.ExecContext(ctx, `UPDATE incidents SET signal_id = ?, summary_ja = ?, diagnostic_report = ?, updated_at = ? WHERE id = ?`,
			existing.SignalID, existing.SummaryJA, string(report), existing.UpdatedAt, existing.ID); err != nil {
			return Incident{}, false, err
		}
		return existing, false, nil
	}
	if err != sql.ErrNoRows {
		return Incident{}, false, err
	}
	if incident.ID == "" {
		incident.ID = newID("inc")
	}
	if incident.Status == "" {
		incident.Status = "open"
	}
	incident.OpenedAt = now
	incident.UpdatedAt = now
	report, err := json.Marshal(incident.Report)
	if err != nil {
		return Incident{}, false, err
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO incidents
(id, rule, severity, status, summary_ja, service_id, stream_id, signal_id, diagnostic_report, opened_at, updated_at, resolved_at)
VALUES (?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?, ?, ?, NULL)`,
		incident.ID, incident.Rule, incident.Severity, incident.Status, incident.SummaryJA, incident.ServiceID, incident.StreamID, incident.SignalID, string(report), incident.OpenedAt, incident.UpdatedAt); err != nil {
		return Incident{}, false, err
	}
	return incident, true, nil
}

func (s MariaDBStore) ListIncidents(ctx context.Context) ([]Incident, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, rule, severity, status, summary_ja, service_id, COALESCE(stream_id, ''), signal_id, diagnostic_report, opened_at, updated_at, resolved_at
FROM incidents ORDER BY updated_at DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Incident
	for rows.Next() {
		incident, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, incident)
	}
	return out, rows.Err()
}

func (s MariaDBStore) GetIncident(ctx context.Context, id string) (Incident, error) {
	row := s.DB.QueryRowContext(ctx, `SELECT id, rule, severity, status, summary_ja, service_id, COALESCE(stream_id, ''), signal_id, diagnostic_report, opened_at, updated_at, resolved_at
FROM incidents WHERE id = ?`, id)
	incident, err := scanIncident(row)
	if err == sql.ErrNoRows {
		return Incident{}, ErrNotFound
	}
	return incident, err
}

func (s MariaDBStore) UpdateIncidentStatus(ctx context.Context, id, status string) (Incident, error) {
	if err := ctx.Err(); err != nil {
		return Incident{}, err
	}
	if !validIncidentStatus(status) {
		return Incident{}, ErrInvalidStatus
	}
	now := time.Now().UTC()
	var resolved any
	if status == "resolved" || status == "ignored" {
		resolved = now
	}
	result, err := s.DB.ExecContext(ctx, `UPDATE incidents SET status = ?, updated_at = ?, resolved_at = ? WHERE id = ?`, status, now, resolved, id)
	if err != nil {
		return Incident{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return Incident{}, err
	}
	if affected == 0 {
		return Incident{}, ErrNotFound
	}
	return s.GetIncident(ctx, id)
}

func (s MariaDBStore) SaveNotificationDelivery(ctx context.Context, delivery NotificationDelivery) (NotificationDelivery, error) {
	if err := ctx.Err(); err != nil {
		return NotificationDelivery{}, err
	}
	if delivery.ID == "" {
		delivery.ID = newID("ntf")
	}
	if delivery.CreatedAt.IsZero() {
		delivery.CreatedAt = time.Now().UTC()
	}
	if delivery.Metadata == nil {
		delivery.Metadata = map[string]any{}
	}
	delivery = sanitizeNotificationDelivery(delivery)
	metadata, err := json.Marshal(delivery.Metadata)
	if err != nil {
		return NotificationDelivery{}, err
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO notification_deliveries
(id, event_type, channel, target, incident_id, status, error_text, metadata, created_at)
VALUES (?, ?, ?, ?, NULLIF(?, ''), ?, NULLIF(?, ''), ?, ?)`,
		delivery.ID, delivery.EventType, delivery.Channel, delivery.Target, delivery.IncidentID, delivery.Status, delivery.Error, string(metadata), delivery.CreatedAt); err != nil {
		return NotificationDelivery{}, err
	}
	return delivery, nil
}

func (s MariaDBStore) ListNotificationDeliveries(ctx context.Context) ([]NotificationDelivery, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, event_type, channel, target, COALESCE(incident_id, ''), status, COALESCE(error_text, ''), metadata, created_at
FROM notification_deliveries ORDER BY created_at DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NotificationDelivery
	for rows.Next() {
		var delivery NotificationDelivery
		var metadataRaw []byte
		if err := rows.Scan(&delivery.ID, &delivery.EventType, &delivery.Channel, &delivery.Target, &delivery.IncidentID, &delivery.Status, &delivery.Error, &metadataRaw, &delivery.CreatedAt); err != nil {
			return nil, err
		}
		if len(metadataRaw) > 0 {
			_ = json.Unmarshal(metadataRaw, &delivery.Metadata)
		}
		out = append(out, sanitizeNotificationDelivery(delivery))
	}
	return out, rows.Err()
}

func (s MariaDBStore) ListNotificationChannels(ctx context.Context) ([]NotificationChannel, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, name, channel_type, enabled, webhook_url_ciphertext, webhook_url_nonce, COALESCE(masked_webhook_url, ''), COALESCE(email_recipients, '[]'), COALESCE(smtp_host, ''), COALESCE(smtp_port, 0), smtp_tls, COALESCE(smtp_from, ''), COALESCE(smtp_username, ''), smtp_password_ciphertext, smtp_password_nonce, smtp_password_configured, COALESCE(masked_email_target, ''), severity_filter, event_type_filter, created_at, updated_at
FROM notification_channels ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NotificationChannel
	for rows.Next() {
		channel, err := s.scanNotificationChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, channel)
	}
	return out, rows.Err()
}

func (s MariaDBStore) CreateNotificationChannel(ctx context.Context, channel NotificationChannel) (NotificationChannel, error) {
	if err := ctx.Err(); err != nil {
		return NotificationChannel{}, err
	}
	now := time.Now().UTC()
	if channel.ID == "" {
		channel.ID = newID("ntc")
	}
	channel.Type = normalizeChannelType(channel.Type)
	channel = normalizeNotificationChannelSecrets(channel)
	channel.CreatedAt = now
	channel.UpdatedAt = now
	var webhookCiphertext, webhookNonce string
	var smtpCiphertext, smtpNonce string
	var err error
	if channel.Type == "email" {
		if channel.SMTPPassword != "" {
			smtpCiphertext, smtpNonce, err = encryptSecret(channel.SMTPPassword, s.SecretKey)
			if err != nil {
				return NotificationChannel{}, err
			}
		}
	} else {
		webhookCiphertext, webhookNonce, err = encryptSecret(channel.WebhookURL, s.SecretKey)
		if err != nil {
			return NotificationChannel{}, err
		}
	}
	recipients, err := json.Marshal(channel.EmailRecipients)
	if err != nil {
		return NotificationChannel{}, err
	}
	severity, err := json.Marshal(channel.SeverityFilter)
	if err != nil {
		return NotificationChannel{}, err
	}
	events, err := json.Marshal(channel.EventTypeFilter)
	if err != nil {
		return NotificationChannel{}, err
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO notification_channels
(id, name, channel_type, enabled, webhook_url_ciphertext, webhook_url_nonce, masked_webhook_url, email_recipients, smtp_host, smtp_port, smtp_tls, smtp_from, smtp_username, smtp_password_ciphertext, smtp_password_nonce, smtp_password_configured, masked_email_target, severity_filter, event_type_filter, created_at, updated_at)
VALUES (?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), ?, NULLIF(?, ''), NULLIF(?, 0), ?, NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), ?, NULLIF(?, ''), ?, ?, ?, ?)`,
		channel.ID, channel.Name, channel.Type, channel.Enabled, webhookCiphertext, webhookNonce, channel.MaskedWebhookURL, string(recipients), channel.SMTPHost, channel.SMTPPort, channel.SMTPTLS, channel.SMTPFrom, channel.SMTPUsername, smtpCiphertext, smtpNonce, channel.SMTPPasswordConfigured, channel.MaskedEmailTarget, string(severity), string(events), channel.CreatedAt, channel.UpdatedAt); err != nil {
		return NotificationChannel{}, err
	}
	return publicChannel(channel), nil
}

func (s MariaDBStore) GetNotificationChannel(ctx context.Context, id string) (NotificationChannel, error) {
	row := s.DB.QueryRowContext(ctx, `SELECT id, name, channel_type, enabled, webhook_url_ciphertext, webhook_url_nonce, COALESCE(masked_webhook_url, ''), COALESCE(email_recipients, '[]'), COALESCE(smtp_host, ''), COALESCE(smtp_port, 0), smtp_tls, COALESCE(smtp_from, ''), COALESCE(smtp_username, ''), smtp_password_ciphertext, smtp_password_nonce, smtp_password_configured, COALESCE(masked_email_target, ''), severity_filter, event_type_filter, created_at, updated_at
FROM notification_channels WHERE id = ?`, id)
	channel, err := s.scanNotificationChannel(row)
	if err == sql.ErrNoRows {
		return NotificationChannel{}, ErrNotFound
	}
	return channel, err
}

func (s MariaDBStore) UpdateNotificationChannel(ctx context.Context, channel NotificationChannel) (NotificationChannel, error) {
	if err := ctx.Err(); err != nil {
		return NotificationChannel{}, err
	}
	existing, err := s.GetNotificationChannel(ctx, channel.ID)
	if err != nil {
		return NotificationChannel{}, err
	}
	if channel.Name != "" {
		existing.Name = channel.Name
	}
	if channel.Type != "" {
		existing.Type = normalizeChannelType(channel.Type)
	}
	existing.Enabled = channel.Enabled
	if channel.UseGlobalSMTPSet {
		existing.UseGlobalSMTP = channel.UseGlobalSMTP
		existing.UseGlobalSMTPSet = true
		if channel.UseGlobalSMTP {
			clearLegacySMTPConfiguration(&existing)
		}
	}
	if channel.WebhookURL != "" {
		existing.WebhookURL = channel.WebhookURL
	}
	if channel.EmailRecipients != nil {
		existing.EmailRecipients = append([]string(nil), channel.EmailRecipients...)
	}
	if channel.SMTPHost != "" {
		existing.SMTPHost = channel.SMTPHost
	}
	if channel.SMTPPort != 0 {
		existing.SMTPPort = channel.SMTPPort
	}
	existing.SMTPTLS = channel.SMTPTLS
	if channel.SMTPFrom != "" {
		existing.SMTPFrom = channel.SMTPFrom
	}
	if channel.SMTPUsername != "" {
		existing.SMTPUsername = channel.SMTPUsername
	}
	if channel.SMTPPassword != "" {
		existing.SMTPPassword = channel.SMTPPassword
	}
	if channel.SeverityFilter != nil {
		existing.SeverityFilter = append([]string(nil), channel.SeverityFilter...)
	}
	if channel.EventTypeFilter != nil {
		existing.EventTypeFilter = append([]string(nil), channel.EventTypeFilter...)
	}
	existing = normalizeNotificationChannelSecrets(existing)
	existing.UpdatedAt = time.Now().UTC()
	var webhookCiphertext, webhookNonce string
	var smtpCiphertext, smtpNonce string
	if existing.Type == "email" {
		if existing.SMTPPassword != "" {
			smtpCiphertext, smtpNonce, err = encryptSecret(existing.SMTPPassword, s.SecretKey)
			if err != nil {
				return NotificationChannel{}, err
			}
		}
	} else {
		webhookCiphertext, webhookNonce, err = encryptSecret(existing.WebhookURL, s.SecretKey)
		if err != nil {
			return NotificationChannel{}, err
		}
	}
	recipients, err := json.Marshal(existing.EmailRecipients)
	if err != nil {
		return NotificationChannel{}, err
	}
	severity, err := json.Marshal(existing.SeverityFilter)
	if err != nil {
		return NotificationChannel{}, err
	}
	events, err := json.Marshal(existing.EventTypeFilter)
	if err != nil {
		return NotificationChannel{}, err
	}
	result, err := s.DB.ExecContext(ctx, `UPDATE notification_channels SET name = ?, channel_type = ?, enabled = ?, webhook_url_ciphertext = NULLIF(?, ''), webhook_url_nonce = NULLIF(?, ''), masked_webhook_url = NULLIF(?, ''), email_recipients = ?, smtp_host = NULLIF(?, ''), smtp_port = NULLIF(?, 0), smtp_tls = ?, smtp_from = NULLIF(?, ''), smtp_username = NULLIF(?, ''), smtp_password_ciphertext = NULLIF(?, ''), smtp_password_nonce = NULLIF(?, ''), smtp_password_configured = ?, masked_email_target = NULLIF(?, ''), severity_filter = ?, event_type_filter = ?, updated_at = ? WHERE id = ?`,
		existing.Name, existing.Type, existing.Enabled, webhookCiphertext, webhookNonce, existing.MaskedWebhookURL, string(recipients), existing.SMTPHost, existing.SMTPPort, existing.SMTPTLS, existing.SMTPFrom, existing.SMTPUsername, smtpCiphertext, smtpNonce, existing.SMTPPasswordConfigured, existing.MaskedEmailTarget, string(severity), string(events), existing.UpdatedAt, existing.ID)
	if err != nil {
		return NotificationChannel{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return NotificationChannel{}, err
	}
	if affected == 0 {
		return NotificationChannel{}, ErrNotFound
	}
	return publicChannel(existing), nil
}

func (s MariaDBStore) DeleteNotificationChannel(ctx context.Context, id string) error {
	result, err := s.DB.ExecContext(ctx, `DELETE FROM notification_channels WHERE id = ?`, id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s MariaDBStore) CreateRemediationAction(ctx context.Context, action RemediationAction) (RemediationAction, error) {
	if err := ctx.Err(); err != nil {
		return RemediationAction{}, err
	}
	now := time.Now().UTC()
	if action.ID == "" {
		action.ID = newID("rem")
	}
	if action.Status == "" {
		action.Status = "suggested"
	}
	action.CreatedAt = now
	action.UpdatedAt = now
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO remediation_actions
(id, incident_id, action, mode, status, safe_auto, requires_approval, result, created_at, updated_at, executed_at)
VALUES (?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?, ?)`,
		action.ID, action.IncidentID, action.Action, action.Mode, action.Status, action.SafeAuto, action.RequiresApproval, action.Result, action.CreatedAt, action.UpdatedAt, action.ExecutedAt); err != nil {
		return RemediationAction{}, err
	}
	return action, nil
}

func (s MariaDBStore) ListRemediationActions(ctx context.Context) ([]RemediationAction, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, incident_id, action, mode, status, safe_auto, requires_approval, COALESCE(result, ''), created_at, updated_at, executed_at
FROM remediation_actions ORDER BY updated_at DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RemediationAction
	for rows.Next() {
		action, err := scanRemediationAction(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, action)
	}
	return out, rows.Err()
}

func (s MariaDBStore) GetRemediationAction(ctx context.Context, id string) (RemediationAction, error) {
	row := s.DB.QueryRowContext(ctx, `SELECT id, incident_id, action, mode, status, safe_auto, requires_approval, COALESCE(result, ''), created_at, updated_at, executed_at
FROM remediation_actions WHERE id = ?`, id)
	action, err := scanRemediationAction(row)
	if err == sql.ErrNoRows {
		return RemediationAction{}, ErrNotFound
	}
	return action, err
}

func (s MariaDBStore) UpdateRemediationAction(ctx context.Context, action RemediationAction) (RemediationAction, error) {
	if err := ctx.Err(); err != nil {
		return RemediationAction{}, err
	}
	action.UpdatedAt = time.Now().UTC()
	result, err := s.DB.ExecContext(ctx, `UPDATE remediation_actions SET status = ?, result = NULLIF(?, ''), updated_at = ?, executed_at = ? WHERE id = ?`,
		action.Status, action.Result, action.UpdatedAt, action.ExecutedAt, action.ID)
	if err != nil {
		return RemediationAction{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return RemediationAction{}, err
	}
	if affected == 0 {
		return RemediationAction{}, ErrNotFound
	}
	return action, nil
}

type remediationScanner interface {
	Scan(dest ...any) error
}

func scanRemediationAction(scanner remediationScanner) (RemediationAction, error) {
	var action RemediationAction
	var executed sql.NullTime
	if err := scanner.Scan(&action.ID, &action.IncidentID, &action.Action, &action.Mode, &action.Status, &action.SafeAuto, &action.RequiresApproval, &action.Result, &action.CreatedAt, &action.UpdatedAt, &executed); err != nil {
		return RemediationAction{}, err
	}
	if executed.Valid {
		action.ExecutedAt = &executed.Time
	}
	return action, nil
}

func (s MariaDBStore) findOpenIncident(ctx context.Context, rule, serviceID, streamID string) (Incident, error) {
	row := s.DB.QueryRowContext(ctx, `SELECT id, rule, severity, status, summary_ja, service_id, COALESCE(stream_id, ''), signal_id, diagnostic_report, opened_at, updated_at, resolved_at
FROM incidents
WHERE rule = ? AND service_id = ? AND COALESCE(stream_id, '') = ? AND status NOT IN ('resolved', 'ignored')
ORDER BY updated_at DESC LIMIT 1`, rule, serviceID, streamID)
	return scanIncident(row)
}

type incidentScanner interface {
	Scan(dest ...any) error
}

type notificationChannelScanner interface {
	Scan(dest ...any) error
}

func (s MariaDBStore) scanNotificationChannel(scanner notificationChannelScanner) (NotificationChannel, error) {
	var channel NotificationChannel
	var webhookCiphertext, webhookNonce sql.NullString
	var smtpCiphertext, smtpNonce sql.NullString
	var severityRaw, eventsRaw []byte
	var recipientsRaw []byte
	if err := scanner.Scan(&channel.ID, &channel.Name, &channel.Type, &channel.Enabled, &webhookCiphertext, &webhookNonce, &channel.MaskedWebhookURL, &recipientsRaw, &channel.SMTPHost, &channel.SMTPPort, &channel.SMTPTLS, &channel.SMTPFrom, &channel.SMTPUsername, &smtpCiphertext, &smtpNonce, &channel.SMTPPasswordConfigured, &channel.MaskedEmailTarget, &severityRaw, &eventsRaw, &channel.CreatedAt, &channel.UpdatedAt); err != nil {
		return NotificationChannel{}, err
	}
	if len(recipientsRaw) > 0 {
		_ = json.Unmarshal(recipientsRaw, &channel.EmailRecipients)
	}
	if len(severityRaw) > 0 {
		_ = json.Unmarshal(severityRaw, &channel.SeverityFilter)
	}
	if len(eventsRaw) > 0 {
		_ = json.Unmarshal(eventsRaw, &channel.EventTypeFilter)
	}
	if webhookCiphertext.Valid && webhookCiphertext.String != "" {
		plaintext, err := decryptSecret(webhookCiphertext.String, webhookNonce.String, s.SecretKey)
		if err != nil {
			return NotificationChannel{}, err
		}
		channel.WebhookURL = plaintext
	}
	if smtpCiphertext.Valid && smtpCiphertext.String != "" {
		plaintext, err := decryptSecret(smtpCiphertext.String, smtpNonce.String, s.SecretKey)
		if err != nil {
			return NotificationChannel{}, err
		}
		channel.SMTPPassword = plaintext
		channel.SMTPPasswordConfigured = true
	}
	return normalizeNotificationChannelSecrets(channel), nil
}

func scanIncident(scanner incidentScanner) (Incident, error) {
	var incident Incident
	var reportRaw []byte
	var resolved sql.NullTime
	if err := scanner.Scan(&incident.ID, &incident.Rule, &incident.Severity, &incident.Status, &incident.SummaryJA, &incident.ServiceID, &incident.StreamID, &incident.SignalID, &reportRaw, &incident.OpenedAt, &incident.UpdatedAt, &resolved); err != nil {
		return Incident{}, err
	}
	if resolved.Valid {
		incident.ResolvedAt = &resolved.Time
	}
	if len(reportRaw) > 0 {
		_ = json.Unmarshal(reportRaw, &incident.Report)
	}
	return incident, nil
}
