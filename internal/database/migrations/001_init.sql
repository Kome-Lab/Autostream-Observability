CREATE TABLE IF NOT EXISTS signals (
  id VARCHAR(64) PRIMARY KEY,
  signal_type VARCHAR(64) NOT NULL,
  name VARCHAR(128) NOT NULL,
  service_id VARCHAR(128) NOT NULL,
  service_type VARCHAR(64) NOT NULL,
  stream_id VARCHAR(128) NULL,
  status VARCHAR(64) NULL,
  value_double DOUBLE NULL,
  attributes JSON NOT NULL,
  occurred_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL,
  INDEX idx_signals_service_created (service_id, created_at),
  INDEX idx_signals_stream_created (stream_id, created_at),
  INDEX idx_signals_name_created (name, created_at)
);

CREATE TABLE IF NOT EXISTS incidents (
  id VARCHAR(64) PRIMARY KEY,
  rule VARCHAR(128) NOT NULL,
  severity ENUM('info','warning','error','critical') NOT NULL,
  status ENUM('open','acknowledged','investigating','mitigated','resolved','ignored') NOT NULL,
  summary_ja TEXT NOT NULL,
  service_id VARCHAR(128) NOT NULL,
  stream_id VARCHAR(128) NULL,
  signal_id VARCHAR(64) NOT NULL,
  diagnostic_report JSON NOT NULL,
  opened_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  resolved_at DATETIME NULL,
  INDEX idx_incidents_open_dedupe (rule, service_id, stream_id, status),
  INDEX idx_incidents_status_updated (status, updated_at)
);

CREATE TABLE IF NOT EXISTS notification_deliveries (
  id VARCHAR(64) PRIMARY KEY,
  event_type VARCHAR(128) NOT NULL,
  channel VARCHAR(64) NOT NULL,
  target VARCHAR(512) NOT NULL,
  incident_id VARCHAR(64) NULL,
  status ENUM('success','failure') NOT NULL,
  error_text TEXT NULL,
  metadata JSON NOT NULL,
  created_at DATETIME NOT NULL,
  INDEX idx_notification_deliveries_created (created_at),
  INDEX idx_notification_deliveries_incident (incident_id)
);

CREATE TABLE IF NOT EXISTS remediation_actions (
  id VARCHAR(64) PRIMARY KEY,
  incident_id VARCHAR(64) NOT NULL,
  action VARCHAR(128) NOT NULL,
  mode ENUM('disabled','suggest_only','safe_auto','manual_approval') NOT NULL,
  status ENUM('disabled','suggested','pending_approval','approved','executed','blocked') NOT NULL,
  safe_auto BOOLEAN NOT NULL,
  requires_approval BOOLEAN NOT NULL,
  result TEXT NULL,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  executed_at DATETIME NULL,
  INDEX idx_remediation_incident (incident_id),
  INDEX idx_remediation_status_updated (status, updated_at)
);
