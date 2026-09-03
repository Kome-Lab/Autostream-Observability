CREATE TABLE IF NOT EXISTS notification_channel_v2_migration_backup (
  channel_id VARCHAR(64) PRIMARY KEY,
  smtp_host VARCHAR(255) NULL,
  smtp_port INT NULL,
  smtp_tls BOOLEAN NOT NULL,
  smtp_from VARCHAR(255) NULL,
  smtp_username VARCHAR(255) NULL,
  smtp_password_ciphertext TEXT NULL,
  smtp_password_nonce VARCHAR(64) NULL,
  smtp_password_configured BOOLEAN NOT NULL,
  source_fingerprint CHAR(64) NOT NULL,
  backed_up_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
);

CREATE TABLE IF NOT EXISTS notification_channel_v2_replacement_authority (
  authority_id VARCHAR(64) PRIMARY KEY,
  config_owner VARCHAR(64) NOT NULL,
  config_key VARCHAR(128) NOT NULL,
  authority_revision VARCHAR(128) NOT NULL,
  verified_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  CONSTRAINT chk_notification_channel_v2_authority
    CHECK (authority_id='global_smtp' AND config_owner='control_panel' AND config_key='global_smtp')
);

CREATE TABLE IF NOT EXISTS notification_channel_v2_config_references (
  channel_id VARCHAR(64) PRIMARY KEY,
  config_owner VARCHAR(64) NOT NULL,
  config_key VARCHAR(128) NOT NULL,
  migrated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_notification_channel_v2_reference
    FOREIGN KEY (channel_id) REFERENCES notification_channels(id) ON DELETE CASCADE,
  CONSTRAINT chk_notification_channel_v2_reference
    CHECK (config_owner = 'control_panel' AND config_key = 'global_smtp')
);

INSERT INTO notification_channel_v2_migration_backup
  (channel_id, smtp_host, smtp_port, smtp_tls, smtp_from, smtp_username,
   smtp_password_ciphertext, smtp_password_nonce, smtp_password_configured, source_fingerprint)
SELECT id, smtp_host, smtp_port, smtp_tls, smtp_from, smtp_username,
       smtp_password_ciphertext, smtp_password_nonce, smtp_password_configured,
       SHA2(CONCAT_WS('|', id, COALESCE(smtp_host,''), COALESCE(smtp_port,0), smtp_tls,
         COALESCE(smtp_from,''), COALESCE(smtp_username,''),
         COALESCE(smtp_password_ciphertext,''), COALESCE(smtp_password_nonce,''),
         smtp_password_configured), 256)
FROM notification_channels
WHERE channel_type='email' AND (
  smtp_host IS NOT NULL OR smtp_port IS NOT NULL OR smtp_from IS NOT NULL OR
  smtp_username IS NOT NULL OR smtp_password_ciphertext IS NOT NULL OR
  smtp_password_nonce IS NOT NULL OR smtp_password_configured=TRUE
)
ON DUPLICATE KEY UPDATE
  smtp_host=VALUES(smtp_host),
  smtp_port=VALUES(smtp_port),
  smtp_tls=VALUES(smtp_tls),
  smtp_from=VALUES(smtp_from),
  smtp_username=VALUES(smtp_username),
  smtp_password_ciphertext=VALUES(smtp_password_ciphertext),
  smtp_password_nonce=VALUES(smtp_password_nonce),
  smtp_password_configured=VALUES(smtp_password_configured),
  source_fingerprint=VALUES(source_fingerprint),
  backed_up_at=CURRENT_TIMESTAMP(6);

INSERT IGNORE INTO notification_channel_v2_config_references
  (channel_id, config_owner, config_key)
SELECT channel_id, 'control_panel', 'global_smtp'
FROM notification_channel_v2_migration_backup;

DROP TEMPORARY TABLE IF EXISTS notification_channel_v2_eol_guard;

CREATE TEMPORARY TABLE notification_channel_v2_eol_guard (
  failure TINYINT NOT NULL,
  CONSTRAINT chk_notification_channel_v2_eol_guard CHECK (failure=0)
);

INSERT INTO notification_channel_v2_eol_guard (failure)
SELECT IF(
  EXISTS (
    SELECT 1
    FROM notification_channels AS current
    LEFT JOIN notification_channel_v2_migration_backup AS backup ON backup.channel_id=current.id
    WHERE current.channel_type='email' AND (
      current.smtp_host IS NOT NULL OR current.smtp_port IS NOT NULL OR current.smtp_from IS NOT NULL OR
      current.smtp_username IS NOT NULL OR current.smtp_password_ciphertext IS NOT NULL OR
      current.smtp_password_nonce IS NOT NULL OR current.smtp_password_configured=TRUE
    ) AND (
      backup.channel_id IS NULL OR backup.source_fingerprint <> SHA2(CONCAT_WS('|', current.id,
        COALESCE(current.smtp_host,''), COALESCE(current.smtp_port,0), current.smtp_tls,
        COALESCE(current.smtp_from,''), COALESCE(current.smtp_username,''),
        COALESCE(current.smtp_password_ciphertext,''), COALESCE(current.smtp_password_nonce,''),
        current.smtp_password_configured), 256)
    )
  ) OR EXISTS (
    SELECT 1
    FROM notification_channel_v2_migration_backup AS backup
    LEFT JOIN notification_channels AS current ON current.id=backup.channel_id
    LEFT JOIN notification_channel_v2_config_references AS replacement ON replacement.channel_id=backup.channel_id
    WHERE current.id IS NULL OR replacement.channel_id IS NULL OR
      replacement.config_owner<>'control_panel' OR replacement.config_key<>'global_smtp'
  ) OR EXISTS (
	SELECT 1
	FROM notification_channel_v2_config_references AS replacement
	LEFT JOIN notification_channel_v2_migration_backup AS backup ON backup.channel_id=replacement.channel_id
	WHERE backup.channel_id IS NULL
  ) OR (
	EXISTS (SELECT 1 FROM notification_channel_v2_migration_backup)
	AND NOT EXISTS (
	  SELECT 1
	  FROM notification_channel_v2_replacement_authority
	  WHERE authority_id='global_smtp'
	    AND config_owner='control_panel'
	    AND config_key='global_smtp'
	    AND TRIM(authority_revision)<>''
	)
  ),
  1,
  0
);

DROP TEMPORARY TABLE notification_channel_v2_eol_guard;

ALTER TABLE notification_channels
  DROP COLUMN smtp_host,
  DROP COLUMN smtp_port,
  DROP COLUMN smtp_tls,
  DROP COLUMN smtp_from,
  DROP COLUMN smtp_username,
  DROP COLUMN smtp_password_ciphertext,
  DROP COLUMN smtp_password_nonce,
  DROP COLUMN smtp_password_configured;
