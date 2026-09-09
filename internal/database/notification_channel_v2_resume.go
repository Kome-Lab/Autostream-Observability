package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Migration 008 is already distributed. Keep its SQL/history intact and enter
// this recovery path before executing SQL that requires removed SMTP columns.
func applyNotificationChannelV2(ctx context.Context, db *sql.DB, body string) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	var columns int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.columns
 WHERE table_schema=DATABASE() AND table_name='notification_channels' AND column_name IN
 ('smtp_host','smtp_port','smtp_tls','smtp_from','smtp_username','smtp_password_ciphertext','smtp_password_nonce','smtp_password_configured')`).Scan(&columns); err != nil {
		return err
	}
	if columns != 0 && columns != 8 {
		return errors.New("partial legacy SMTP schema cannot establish recovery authority")
	}
	if columns == 8 {
		for _, stmt := range splitSQLStatements(body) {
			if strings.HasPrefix(stmt, "INSERT INTO notification_channel_v2_migration_backup") {
				// Preserve the first saved backup. Check existing rows before adding
				// missing ones, rather than refreshing evidence from changed data.
				if err := validateNotificationBackup(ctx, conn, true); err != nil {
					return err
				}
				stmt, _, _ = strings.Cut(stmt, "ON DUPLICATE KEY UPDATE")
				stmt = strings.Replace(stmt, "INSERT INTO", "INSERT IGNORE INTO", 1)
			}
			if strings.HasPrefix(stmt, "ALTER TABLE notification_channels") {
				if err := validateNotificationReplacement(ctx, conn); err != nil {
					return err
				}
				if err := notificationV2Checkpoint(ctx, conn); err != nil {
					return err
				}
			}
			if _, err := conn.ExecContext(ctx, stmt); err != nil {
				return err
			}
		}
	}
	// A deleted column is never completion evidence by itself. These queries
	// require the retained backup, replacement rows and live Panel authority,
	// including when the old runner stopped after the final ALTER TABLE.
	if err := validateNotificationBackup(ctx, conn, false); err != nil {
		return err
	}
	if err := validateNotificationReplacement(ctx, conn); err != nil {
		return err
	}
	if err := notificationV2Checkpoint(ctx, conn); err != nil {
		return err
	}
	var remaining int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.columns
 WHERE table_schema=DATABASE() AND table_name='notification_channels' AND column_name LIKE 'smtp_%'`).Scan(&remaining); err != nil {
		return err
	}
	if remaining != 0 {
		return errors.New("legacy SMTP final schema mismatch")
	}
	return nil
}

func smtpFingerprint(alias, id string) string {
	return fmt.Sprintf(`SHA2(CONCAT_WS('|', %s.%s, COALESCE(%s.smtp_host,''), COALESCE(%s.smtp_port,0), %s.smtp_tls,
 COALESCE(%s.smtp_from,''), COALESCE(%s.smtp_username,''), COALESCE(%s.smtp_password_ciphertext,''),
 COALESCE(%s.smtp_password_nonce,''), %s.smtp_password_configured), 256)`, alias, id, alias, alias, alias, alias, alias, alias, alias, alias)
}

func validateNotificationBackup(ctx context.Context, conn *sql.Conn, legacy bool) error {
	query := `SELECT COUNT(*) FROM notification_channel_v2_migration_backup AS backup
 LEFT JOIN notification_channels AS current ON current.id=backup.channel_id
 WHERE current.id IS NULL OR current.channel_type<>'email'
 OR backup.source_fingerprint <> ` + smtpFingerprint("backup", "channel_id")
	if legacy {
		query += " OR backup.source_fingerprint <> " + smtpFingerprint("current", "id")
	}
	var mismatches int
	if err := conn.QueryRowContext(ctx, query).Scan(&mismatches); err != nil {
		return err
	}
	if mismatches != 0 {
		return errors.New("retained SMTP backup mismatch")
	}
	return nil
}

func validateNotificationReplacement(ctx context.Context, conn *sql.Conn) error {
	var mismatch bool
	err := conn.QueryRowContext(ctx, `SELECT EXISTS (
 SELECT 1 FROM notification_channel_v2_migration_backup AS backup
 LEFT JOIN notification_channels AS current ON current.id=backup.channel_id
 LEFT JOIN notification_channel_v2_config_references AS replacement ON replacement.channel_id=backup.channel_id
 WHERE current.id IS NULL OR current.channel_type<>'email' OR replacement.channel_id IS NULL
 OR replacement.config_owner<>'control_panel' OR replacement.config_key<>'global_smtp'
 ) OR EXISTS (
 SELECT 1 FROM notification_channel_v2_config_references AS replacement
 LEFT JOIN notification_channel_v2_migration_backup AS backup ON backup.channel_id=replacement.channel_id
 WHERE backup.channel_id IS NULL
 ) OR (EXISTS(SELECT 1 FROM notification_channel_v2_migration_backup) AND NOT EXISTS (
 SELECT 1 FROM notification_channel_v2_replacement_authority WHERE authority_id='global_smtp'
 AND config_owner='control_panel' AND config_key='global_smtp' AND TRIM(authority_revision)<>''))`).Scan(&mismatch)
	if err != nil {
		return err
	}
	if mismatch {
		return errors.New("SMTP replacement authority mismatch")
	}
	return nil
}

// Bind all retained rows to the successful gate before DDL and compare them
// after DDL/on restart. Only a revalidated legacy interruption may establish a
// previously absent checkpoint. No credential or digest enters diagnostics.
func notificationV2Checkpoint(ctx context.Context, conn *sql.Conn) error {
	h := sha256.New()
	for _, query := range []string{
		`SELECT * FROM notification_channel_v2_migration_backup ORDER BY channel_id`,
		`SELECT * FROM notification_channel_v2_config_references ORDER BY channel_id`,
		`SELECT authority_id,config_owner,config_key,authority_revision FROM notification_channel_v2_replacement_authority ORDER BY authority_id`,
		`SELECT id,name,channel_type,enabled,webhook_url_ciphertext,webhook_url_nonce,masked_webhook_url,email_recipients,
 masked_email_target,severity_filter,event_type_filter,created_at,updated_at FROM notification_channels ORDER BY id`,
	} {
		rows, err := conn.QueryContext(ctx, query)
		if err != nil {
			return err
		}
		columns, err := rows.Columns()
		if err != nil {
			rows.Close()
			return err
		}
		for rows.Next() {
			values := make([]any, len(columns))
			args := make([]any, len(columns))
			for i := range args {
				args[i] = &values[i]
			}
			if err := rows.Scan(args...); err != nil {
				rows.Close()
				return err
			}
			if err := json.NewEncoder(h).Encode(values); err != nil {
				rows.Close()
				return err
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS notification_channel_v2_eol_checkpoint (
 gate_id TINYINT PRIMARY KEY, state_digest CHAR(64) NOT NULL,
 mismatch_count INT NOT NULL CHECK (mismatch_count=0))`); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `INSERT IGNORE INTO notification_channel_v2_eol_checkpoint
 (gate_id,state_digest,mismatch_count) VALUES (1,?,0)`, digest); err != nil {
		return err
	}
	var matches bool
	if err := conn.QueryRowContext(ctx, `SELECT state_digest=? AND mismatch_count=0 FROM notification_channel_v2_eol_checkpoint WHERE gate_id=1`, digest).Scan(&matches); err != nil {
		return err
	}
	if !matches {
		return errors.New("SMTP retained state changed after EOL gate")
	}
	return nil
}
