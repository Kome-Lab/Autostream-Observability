CREATE TABLE IF NOT EXISTS notification_channels (
  id VARCHAR(64) PRIMARY KEY,
  name VARCHAR(128) NOT NULL,
  channel_type ENUM('discord','slack','generic') NOT NULL,
  enabled BOOLEAN NOT NULL,
  webhook_url_ciphertext TEXT NOT NULL,
  webhook_url_nonce VARCHAR(64) NOT NULL,
  masked_webhook_url VARCHAR(512) NOT NULL,
  severity_filter JSON NOT NULL,
  event_type_filter JSON NOT NULL,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  INDEX idx_notification_channels_enabled (enabled, channel_type)
);
